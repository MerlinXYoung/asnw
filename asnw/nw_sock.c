/*
 * Description: 
 *     History: yang@haipo.me, 2016/03/16, create
 */

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <errno.h>
# include <fcntl.h>
# include <netdb.h>
# include <unistd.h>
# include "nw_sock.h"

const char *nw_sock_human_addr(const struct sockaddr *addr)
{
    static char dst[NW_HUMAN_ADDR_SIZE];
    char ip[INET6_ADDRSTRLEN];

    switch (addr->sa_family) {
    case AF_INET: {
        const struct sockaddr_in* in = (const struct sockaddr_in*)addr;
        inet_ntop(in->sin_family, &in->sin_addr, ip, sizeof(ip));
        snprintf(dst, sizeof(dst), "%s:%u", ip, ntohs(in->sin_port));
        break;
    }
    case AF_INET6: {
        const struct sockaddr_in6* in6 = (const struct sockaddr_in6*)addr;
        inet_ntop(in6->sin6_family, &in6->sin6_addr, ip, sizeof(ip));
        snprintf(dst, sizeof(dst), "%s:%u", ip, ntohs(in6->sin6_port));
        break;
    }
    case AF_UNIX: {
        const struct sockaddr_un* un = (const struct sockaddr_un*)addr;
        snprintf(dst, sizeof(dst), "%s:%s", "unix", (un->sun_path));
        break;
    }
    default:
        dst[0] = 0;
        break;
    }

    return dst;
}

const char *nw_sock_human_addr_s(const struct sockaddr *addr, char *dst)
{
    char ip[INET6_ADDRSTRLEN];

    switch (addr->sa_family) {
    case AF_INET: {
        const struct sockaddr_in* in = (const struct sockaddr_in*)addr;
        inet_ntop(in->sin_family, &in->sin_addr, ip, sizeof(ip));
        snprintf(dst, NW_HUMAN_ADDR_SIZE, "%s:%u", ip, ntohs(in->sin_port));
        break;
    }
    case AF_INET6: {
        const struct sockaddr_in6* in6 = (const struct sockaddr_in6*)addr;
        inet_ntop(in6->sin6_family, &in6->sin6_addr, ip, sizeof(ip));
        snprintf(dst, NW_HUMAN_ADDR_SIZE, "%s:%u", ip, ntohs(in6->sin6_port));
        break;
    }
    case AF_UNIX: {
        const struct sockaddr_un* un = (const struct sockaddr_un*)addr;
        snprintf(dst, NW_HUMAN_ADDR_SIZE, "%s:%s", "unix", (un->sun_path));
        break;
    }
    default:
        dst[0] = 0;
        break;
    }

    return dst;
}

const char *nw_sock_ip(const struct sockaddr *addr)
{
    static char ip[INET6_ADDRSTRLEN];
    switch (addr->sa_family) {
    case AF_INET: {
        const struct sockaddr_in* in = (const struct sockaddr_in*)addr;
        inet_ntop(in->sin_family, &in->sin_addr, ip, sizeof(ip));
        break;
    }
    case AF_INET6: {
        const struct sockaddr_in6* in6 = (const struct sockaddr_in6*)addr;
        inet_ntop(in6->sin6_family, &in6->sin6_addr, ip, sizeof(ip));
        break;
    }
    default:
        ip[0] = 0;
        break;
    }
    return ip;
}

const char *nw_sock_ip_s(const struct sockaddr *addr, char *ip)
{
    switch (addr->sa_family) {
    case AF_INET: {
        const struct sockaddr_in* in = (const struct sockaddr_in*)addr;
        inet_ntop(in->sin_family, &in->sin_addr, ip, NW_SOCK_IP_SIZE);
        break;
    }
    case AF_INET6: {
        const struct sockaddr_in6* in6 = (const struct sockaddr_in6*)addr;
        inet_ntop(in6->sin6_family, &in6->sin6_addr, ip, NW_SOCK_IP_SIZE);
        break;
    }
    default:
        ip[0] = 0;
        break;
    }
    return ip;
}

int nw_sock_set_mode(struct sockaddr_un *addr, mode_t mode)
{
    if (!addr || addr->sun_family != AF_UNIX)
        return 0;
    return chmod(addr->sun_path, mode);
}

static int nw_sock_addr_fill_inet(struct sockaddr_in6* addr, const char* host, const char* port)
{
    memset(addr, 0, sizeof(struct sockaddr_in6));
    if (strchr(host, '.') != NULL) {
        struct sockaddr_in* in = (struct sockaddr_in*)addr;
        in->sin_family = AF_INET;
        if (inet_pton(in->sin_family, host, &in->sin_addr) <= 0) {
            return -1;
        }
        in->sin_port = htons(strtoul(port, NULL, 0));
    }
    else {
        addr->sin6_family = AF_INET6;
        if (inet_pton(addr->sin6_family, host, &addr->sin6_addr) <= 0) {
            return -1;
        }
        addr->sin6_port = htons(strtoul(port, NULL, 0));
    }

    return 0;
}

static int nw_sock_addr_fill_unix(struct sockaddr_un* addr, const char* unix_path)
{
    size_t pathlen = strlen(unix_path);
    if (pathlen >= sizeof(addr->sun_path)) {
        return -1;
    }
    addr->sun_family = AF_UNIX;
    strcpy(addr->sun_path, unix_path);

    return 0;
}

int nw_sock_cfg_parse(const char* cfg, struct sockaddr_storage* addr, int* sock_type )
{
    char* s = strdup(cfg);
    char* sep = strchr(s, '@');
    if (sep == NULL) {
        free(s);
        return -1;
    }
    *sep = '\0';
    char* type = s;
    char* name = sep + 1;
    int is_inet = 0;

    if (strcasecmp(type, "tcp") == 0) {
        *sock_type = SOCK_STREAM;
        is_inet = 1;
    }
    else if (strcasecmp(type, "udp") == 0) {
        *sock_type = SOCK_DGRAM;
        is_inet = 1;
    }
    else if (strcasecmp(type, "stream") == 0) {
        *sock_type = SOCK_STREAM;
    }
    else if (strcasecmp(type, "dgram") == 0) {
        *sock_type = SOCK_DGRAM;
    }
    else if (strcasecmp(type, "seqpacket") == 0) {
        *sock_type = SOCK_SEQPACKET;
    }
    else {
        free(s);
        return -2;
    }

    if (is_inet) {
        sep = strchr(name, ':');
        if (sep == NULL) {
            free(s);
            return -3;
        }
        *sep = '\0';
        char* host = name;
        char* port = sep + 1;
        if (nw_sock_addr_fill_inet((struct sockaddr_in6*)addr, host, port) < 0) {
            free(s);
            return -4;
        }
    }
    else {
        if (nw_sock_addr_fill_unix((struct sockaddr_un*)addr, name) < 0) {
            free(s);
            return -5;
        }
    }

    free(s);
    return 0;
}

int nw_sock_errno(int sockfd)
{
    int _errno = 0;
    socklen_t len = sizeof(int);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &_errno, &len) == 0)
        return _errno;
    if (errno != 0)
        return errno;
    return EBADFD;
}

int nw_sock_get_send_buf(int sockfd, int *buf_size)
{
    socklen_t len = sizeof(*buf_size);
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, buf_size, &len) != 0)
        return -1;
    return 0;
}

int nw_sock_get_recv_buf(int sockfd, int *buf_size)
{
    socklen_t len = sizeof(*buf_size);
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, buf_size, &len) != 0)
        return -1;
    return 0;
}

int nw_sock_set_send_buf(int sockfd, int buf_size)
{
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) != 0)
        return -1;
    return 0;
}

int nw_sock_set_recv_buf(int sockfd, int buf_size)
{
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) != 0)
        return -1;
    return 0;
}

int nw_sock_set_nonblock(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    return 0;
}

int nw_sock_set_no_delay(int sockfd)
{
    int val = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) != 0)
        return -1;
    return 0;
}

int nw_sock_set_reuse_addr(int sockfd)
{
    int val = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != 0)
        return -1;
    return 0;
}

