/*
 * Description: socket related
 *     History: yang@haipo.me, 2016/03/16, create
 */

# ifndef _NW_SOCK_H_
# define _NW_SOCK_H_

# include <sys/types.h>
# include <sys/resource.h>
# include <sys/stat.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include "nw_utils.h"
#ifdef __cplusplus
extern "C" {
#endif

socklen_t FORCE_INLINE nw_sockaddr_len(int sa_family) {
    switch (sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    case AF_UNIX:
        return sizeof(struct sockaddr_un);
    default:
        return 0;
    }
}

# define NW_HUMAN_ADDR_SIZE 128
# define NW_SOCK_IP_SIZE    INET6_ADDRSTRLEN

    /* convert nw_sockaddr addr to a human readable string */
    const char* nw_sock_human_addr(const struct sockaddr* addr);

    /* nw_sock_human_addr thead safe version, dest should at least NW_HUMAN_ADDR_SIZE len */
    const char* nw_sock_human_addr_s(const struct sockaddr* addr, char* dest);

    /* if addr family is AF_INET or AF_INET6, return ip string, else return empty string */
    const char* nw_sock_ip(const struct sockaddr* addr);

    /* nw_sock_ip thread safe version, ip should at least NW_SOCK_IP_SIZE len */
    const char* nw_sock_ip_s(const struct sockaddr* addr, char* ip);

    /* set unix socket mode */
    int nw_sock_set_mode(struct sockaddr_un* addr, mode_t mode);

    /*
     * input: cfg, format: protocol@address
     * protocol list: TCP, UDP, STREAM, DGRAM, SEQPACKET (case-insensitive)
     * addr type: ip:port or unix path. ip can support ipv6
     * example: tcp@127.0.0.1:3333
     *          dgram@/tmp/test.sock
     *
     * output: addr, sock_type
     * sock_type list: SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET
     */
    int nw_sock_cfg_parse(const char* cfg, struct sockaddr_storage* sockaddr, int* sock_type  );

    /* get sockfd peer addr */
    //int nw_sock_peer_addr(int sockfd, sockaddr** addr);

    /* get sockfd host addr */
    //int nw_sock_host_addr(int sockfd, sockaddr** addr);

    /* get sockfd errno to detect error */
    int nw_sock_errno(int sockfd);

    /* get sockfd system send buf size */
    int nw_sock_get_send_buf(int sockfd, int* buf_size);

    /* get sockfd system recv buf size */
    int nw_sock_get_recv_buf(int sockfd, int* buf_size);

    /* set sockfd system send buf size */
    int nw_sock_set_send_buf(int sockfd, int buf_size);

    /* set sockfd system send buf size */
    int nw_sock_set_recv_buf(int sockfd, int buf_size);

    /* set sockfd as nonblock */
    int nw_sock_set_nonblock(int sockfd);

    /* set sockfd no delay */
    int nw_sock_set_no_delay(int sockfd);

    /* set sockfd reuse addr */
    int nw_sock_set_reuse_addr(int sockfd);
#ifdef __cplusplus
}
#endif
# endif

