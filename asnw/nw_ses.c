/*
 * Description: 
 *     History: yang@haipo.me, 2016/03/19, create
 */

# include <stdio.h>
# include <errno.h>
# include <unistd.h>
# include "nw_ses.h"
#include "nw_utils.h"
 /* nw_buf is the basic instance of buf, with limit size */
typedef struct nw_buf {
    uint32_t size;
    uint32_t rpos;
    uint32_t wpos;
    struct nw_buf* next;
    char data[];
} nw_buf;

/* nw_buf operation */
static FORCE_INLINE size_t _buf_size(nw_buf* buf) {
    return buf->wpos - buf->rpos;
}
static FORCE_INLINE size_t _buf_avail(nw_buf* buf) {
    return buf->size - buf->wpos;
}
static FORCE_INLINE char* _buf_wptr(nw_buf* buf) {
    return buf->data + buf->wpos;
}
static FORCE_INLINE char* _buf_rptr(nw_buf* buf) {
    return buf->data + buf->rpos;
}


static FORCE_INLINE size_t _buf_write(nw_buf* buf, const void* data, size_t len)
{
    size_t available = _buf_avail(buf);
    size_t wlen = len > available ? available : len;
    memcpy(_buf_wptr(buf), data, wlen);
    buf->wpos += wlen;
    return wlen;
}

static FORCE_INLINE void _buf_shift(nw_buf* buf)
{
    if (buf->rpos == buf->wpos) {
        buf->rpos = buf->wpos = 0;
    }
    else if (buf->rpos != 0) {
        memmove(buf->data, _buf_rptr(buf), buf->wpos - buf->rpos);
        buf->wpos -= buf->rpos;
        buf->rpos = 0;
    }
}

static FORCE_INLINE nw_buf* _buf_alloc(uint32_t size)
{
    nw_buf* buf = (nw_buf*)malloc(sizeof(nw_buf) + size);
    buf->size = size;
    buf->rpos = 0;
    buf->wpos = 0;
    buf->next = NULL;
    return buf;
}

static size_t _wlist_write(nw_ses* ses, const void* data, size_t len);
static size_t _wlist_append(nw_ses* ses, const void* data, size_t len);
static void _wlist_shift(nw_ses* ses);

static void libev_on_read_write_evt(struct ev_loop *loop, ev_io *watcher, int events);
static void libev_on_accept_evt(struct ev_loop *loop, ev_io *watcher, int events);
static void libev_on_connect_evt(struct ev_loop *loop, ev_io *watcher, int events);

static void watch_stop(nw_ses *ses)
{
    if (ev_is_active(&ses->ev)) {
        ev_io_stop(ses->loop, &ses->ev);
    }
}

static void watch_read(nw_ses *ses)
{
    if (ev_is_active(&ses->ev)) {
        ev_io_stop(ses->loop, &ses->ev);
    }
    ev_io_init(&ses->ev, libev_on_read_write_evt, ses->sockfd, EV_READ);
    ev_io_start(ses->loop, &ses->ev);
}

static void watch_read_write(nw_ses *ses)
{
    if (ev_is_active(&ses->ev)) {
        ev_io_stop(ses->loop, &ses->ev);
    }
    ev_io_init(&ses->ev, libev_on_read_write_evt, ses->sockfd, EV_READ | EV_WRITE);
    ev_io_start(ses->loop, &ses->ev);
}

static void watch_accept(nw_ses *ses)
{
    ev_io_init(&ses->ev, libev_on_accept_evt, ses->sockfd, EV_READ);
    ev_io_start(ses->loop, &ses->ev);
}

static void watch_connect(nw_ses *ses)
{
    ev_io_init(&ses->ev, libev_on_connect_evt, ses->sockfd, EV_WRITE);
    ev_io_start(ses->loop, &ses->ev);
}

static int nw_write_stream(nw_ses *ses, const void *data, size_t size)
{
    size_t spos = 0;
    while (spos < size) {
        int ret = write(ses->sockfd, data + spos, size - spos);
        if (ret > 0) {
            spos += ret;
        } else if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        } else {
            break;
        }
    }

    return spos;
}

static int nw_write_packet(nw_ses *ses, const void *data, size_t size)
{
    while (true) {
        struct msghdr msg ;
        struct iovec io ;

        memset(&msg, 0, sizeof(msg));
        io.iov_base = (void *)data;
        io.iov_len = size;
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_flags = MSG_EOR;

        int ret = sendmsg(ses->sockfd, &msg, 0);
        if (ret < 0 && errno == EINTR) {
            continue;
        } else {
            return ret;
        }
    }
}

static void on_can_read(nw_ses *ses)
{
    if (ses->sockfd < 0)
        return;
    if (ses->rbuf == NULL) {
        ses->rbuf = _buf_alloc(ses->buf_limit);
        if (ses->rbuf == NULL) {
            ses->on_error(ses, "no recv buf");
            return;
        }
    }

    switch (ses->sock_type) {
    case SOCK_STREAM:
        {
            while (true) {
                int ret = read(ses->sockfd, _buf_wptr(ses->rbuf), _buf_avail(ses->rbuf));
                if (ret < 0) {
                    if (errno == EINTR) {
                        continue;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    } else {
                        char errmsg[100];
                        snprintf(errmsg, sizeof(errmsg), "read error: %s", strerror(errno));
                        ses->on_error(ses, errmsg);
                        return;
                    }
                } else if (ret == 0) {
                    ses->on_close(ses);
                    return;
                } else {
                    ses->rbuf->wpos += ret;
                }

                size_t size = 0;
                while ((size = _buf_size(ses->rbuf)) > 0) {
                    ret = ses->decode_pkg(ses, _buf_rptr(ses->rbuf), size);
                    if (ret < 0) {
                        char errmsg[100];
                        snprintf(errmsg, sizeof(errmsg), "decode msg error: %d", ret);
                        ses->on_error(ses, errmsg);
                        return;
                    } else if (ret > 0) {
                        ses->on_recv_pkg(ses, _buf_rptr(ses->rbuf), ret);
                        if (!ses->rbuf)
                            return;
                        ses->rbuf->rpos += ret;
                    } else {
                        _buf_shift(ses->rbuf);
                        if (ses->rbuf->wpos == ses->rbuf->size) {
                            ses->on_error(ses, "decode msg error");
                            return;
                        }
                        break;
                    }
                }

                _buf_shift(ses->rbuf);
            }
            if (_buf_size(ses->rbuf) == 0) {
                free(ses->rbuf);
                ses->rbuf = NULL;
            }
        }
        break;
    case SOCK_DGRAM:
        {
            while (true) {
                int ret = recvfrom(ses->sockfd, ses->rbuf->data, ses->rbuf->size, 0, 
                        ses->peer_addr, &ses->addrlen);
                if (ret < 0) {
                    if (errno == EINTR) {
                        continue;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    } else {
                        char errmsg[100];
                        snprintf(errmsg, sizeof(errmsg), "recvfrom error: %s", strerror(errno));
                        ses->on_error(ses, errmsg);
                        return;
                    }
                }
                int pkg_size = ret;
                ret = ses->decode_pkg(ses, ses->rbuf->data, pkg_size);
                if (ret < 0) {
                    char errmsg[100];
                    snprintf(errmsg, sizeof(errmsg), "decode msg error: %d", ret);
                    ses->on_error(ses, errmsg);
                    return;
                }
                ses->on_recv_pkg(ses, ses->rbuf->data, ret);
                if (!ses->rbuf)
                    return;
            }
            free(ses->rbuf);
            ses->rbuf = NULL;
        }
        break;
    case SOCK_SEQPACKET:
        {
            while (true) {
                struct msghdr msg;
                struct iovec io;
                char control[CMSG_SPACE(sizeof(int))];

                memset(&msg, 0, sizeof(msg));
                io.iov_base = ses->rbuf->data;
                io.iov_len = ses->rbuf->size;
                msg.msg_iov = &io;
                msg.msg_iovlen = 1;
                msg.msg_control = control;
                msg.msg_controllen = sizeof(control);

                int ret = recvmsg(ses->sockfd, &msg, 0);
                if (ret < 0) {
                    if (errno == EINTR) {
                       continue;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    } else {
                        char errmsg[100];
                        snprintf(errmsg, sizeof(errmsg), "recvmsg error: %s", strerror(errno));
                        ses->on_error(ses, errmsg);
                        return;
                    }
                } else if (ret == 0) {
                    ses->on_close(ses);
                    return;
                }

                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                if (cmsg != NULL) {
                    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type==SCM_RIGHTS) {
                        int fd = *(int *)CMSG_DATA(cmsg);
                        ses->on_recv_fd(ses, fd);
                    }
                } else {
                    int pkg_size = ret;
                    ret = ses->decode_pkg(ses, ses->rbuf->data, pkg_size);
                    if (ret < 0) {
                        char errmsg[100];
                        snprintf(errmsg, sizeof(errmsg), "decode msg error: %d", ret);
                        ses->on_error(ses, errmsg);
                        return;
                    }
                    ses->on_recv_pkg(ses, ses->rbuf->data, ret);
                    if (!ses->rbuf)
                        return;
                }
            }
            free(ses->rbuf);
            ses->rbuf = NULL;
        }
        break;
    }
}

static void on_can_write(nw_ses *ses)
{
    if (ses->sockfd < 0)
        return;

    while (ses->wlist_cnt > 0) {
        nw_buf *buf = ses->wlist_head;
        size_t size = _buf_size(buf);
        int nwrite = 0;
        if (ses->sock_type == SOCK_STREAM) {
            nwrite = nw_write_stream(ses, _buf_rptr(buf), size);
        } else {
            nwrite = nw_write_packet(ses, _buf_rptr(buf), size);
        }
        if (nwrite < size) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (ses->sock_type == SOCK_STREAM) {
                    buf->rpos += nwrite;
                    break;
                } else {
                    break;
                }
            } else {
                char errmsg[100];
                snprintf(errmsg, sizeof(errmsg), "write error: %s", strerror(errno));
                ses->on_error(ses, errmsg);
                return;
            }
        } else {
            _wlist_shift(ses);
        }
    }

    if (ses->wlist_cnt == 0) {
        watch_read(ses);
    }
}

static void on_can_accept(nw_ses *ses)
{
    if (ses->sockfd < 0)
        return;

    while (true) {
        struct sockaddr_storage peer_addr;
        memset(&peer_addr, 0, sizeof(peer_addr));
        socklen_t addrlen = sizeof(peer_addr);
        int sockfd = accept(ses->sockfd, (struct sockaddr*)&peer_addr, &addrlen);
        if (sockfd < 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                char errmsg[100];
                snprintf(errmsg, sizeof(errmsg), "accept error: %s", strerror(errno));
                ses->on_error(ses, errmsg);
                return;
            }
        } else {
            int ret = ses->on_accept(ses, sockfd, (struct sockaddr*)&peer_addr);
            if (ret < 0) {
                close(sockfd);
            }
        }
    }
}

static void on_can_connect(nw_ses *ses)
{
    if (ses->sockfd < 0)
        return;
    errno = nw_sock_errno(ses->sockfd);
    if (errno != 0) {
        ses->on_connect(ses, false);
        return;
    }
    watch_read(ses);
    ses->on_connect(ses, true);
}

static void libev_on_read_write_evt(struct ev_loop *loop, ev_io *watcher, int events)
{
    nw_ses *ses = (nw_ses *)watcher;
    if (events & EV_READ)
        on_can_read(ses);
    if (events & EV_WRITE)
        on_can_write(ses);
}

static void libev_on_accept_evt(struct ev_loop *loop, ev_io *watcher, int events)
{
    nw_ses *ses = (nw_ses *)watcher;
    if (events & EV_READ)
        on_can_accept(ses);
}

static void libev_on_connect_evt(struct ev_loop *loop, ev_io *watcher, int events)
{
    nw_ses *ses = (nw_ses *)watcher;
    watch_stop(ses);
    if (events & EV_WRITE)
        on_can_connect(ses);
}

int nw_ses_bind(nw_ses *ses, struct sockaddr *addr)
{

    if (addr->sa_family == AF_UNIX) {
        unlink(((struct sockaddr_un*)addr)->sun_path);
    }

    int ret = bind(ses->sockfd, addr, nw_sockaddr_len(addr->sa_family));
    if (ret < 0)
        return ret;

    if (addr->sa_family == AF_UNIX) {
        return nw_sock_set_mode((struct sockaddr_un*)addr, 0777);
    }

    return 0;
}

int nw_ses_listen(nw_ses *ses, int backlog)
{
    int ret = listen(ses->sockfd, backlog);
    if (ret < 0)
        return -1;
    watch_accept(ses);
    return 0;
}

int nw_ses_connect(nw_ses *ses, struct sockaddr *addr)
{
    int ret = connect(ses->sockfd, addr, nw_sockaddr_len(addr->sa_family));
    if (ret == 0) {
        watch_read(ses);
        ses->on_connect(ses, true);
        return 0;
    }
    if (errno == EINPROGRESS) {
        watch_connect(ses);
    } else {
        ses->on_connect(ses, false);
        return -1;
    }
    return 0;
}

int nw_ses_start(nw_ses *ses)
{
    if (ses->ses_type == NW_SES_TYPE_SERVER && (ses->sock_type == SOCK_STREAM || ses->sock_type == SOCK_SEQPACKET)) {
        return nw_ses_listen(ses, SOMAXCONN);
    } else {
        watch_read(ses);
    }
    return 0;
}

int nw_ses_stop(nw_ses *ses)
{
    watch_stop(ses);
    return 0;
}

int nw_ses_send(nw_ses *ses, const void *data, size_t size)
{
    if (ses->sockfd < 0) {
        return -1;
    }

    if (ses->wlist_cnt > 0) {
        size_t nwrite;
        if (ses->sock_type == SOCK_STREAM) {
            nwrite = _wlist_write(ses, data, size);
        } else {
            nwrite = _wlist_append(ses, data, size);
        }
        if (nwrite != size) {
            ses->on_error(ses, "no send buf");
            return -1;
        }
    } else {
        switch (ses->sock_type) {
        case SOCK_STREAM:
            {
                int nwrite = nw_write_stream(ses, data, size);
                if (nwrite < size) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        if (_wlist_write(ses, data + nwrite, size - nwrite) != (size - nwrite)) {
                            ses->on_error(ses, "no send buf");
                            return -1;
                        }
                        watch_read_write(ses);
                    } else {
                        char errmsg[100];
                        snprintf(errmsg, sizeof(errmsg), "write error: %s", strerror(errno));
                        ses->on_error(ses, errmsg);
                        return -1;
                    }
                }
            }
            break;
        case SOCK_DGRAM:
            {
                int ret = sendto(ses->sockfd, data, size, 0, ses->peer_addr, nw_sockaddr_len(ses->peer_addr->sa_family));
                if (ret < 0) {
                    char errmsg[100];
                    snprintf(errmsg, sizeof(errmsg), "sendto error: %s", strerror(errno));
                    ses->on_error(ses, errmsg);
                    return -1;
                }
            }
            break;
        case SOCK_SEQPACKET:
            {
                int ret = nw_write_packet(ses, data, size);
                if (ret < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        if (_wlist_append(ses, data, size) != size) {
                            ses->on_error(ses, "on send buf");
                            return -1;
                        }
                        watch_read_write(ses);
                    } else {
                        char errmsg[100];
                        snprintf(errmsg, sizeof(errmsg), "sendmsg error: %s", strerror(errno));
                        ses->on_error(ses, errmsg);
                        return -1;
                    }
                }
            }
            break;
        default:
            break;
        }
    }

    return 0;
}

int nw_ses_send_fd(nw_ses *ses, int fd)
{
    if (ses->sockfd < 0 || ses->sock_type != SOCK_SEQPACKET) {
        return -1;
    }

    struct msghdr msg;
    struct iovec io;
    char control[CMSG_SPACE(sizeof(int))];

    memset(&msg, 0, sizeof(msg));
    io.iov_base = &fd;
    io.iov_len = sizeof(fd);
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = fd;

    return sendmsg(ses->sockfd, &msg, MSG_EOR);
}

int nw_ses_init(nw_ses *ses, struct ev_loop *loop, struct sockaddr* peer_addr, socklen_t addrlen, 
    uint32_t buf_limit, uint32_t wlist_limit, int ses_type)
{
    memset(ses, 0, sizeof(nw_ses));
    ses->loop = loop;
    ses->ses_type = ses_type;
    ses->buf_limit = buf_limit;
    ses->wlist_limit = wlist_limit;
    if (peer_addr && addrlen > 0) {
        ses->peer_addr = (struct sockaddr*)malloc(addrlen);
        if (!ses->peer_addr)
            return -1;
        memcpy(ses->peer_addr, peer_addr, addrlen);
    }
    ses->addrlen = addrlen;

    return 0;
}

int nw_ses_close(nw_ses *ses)
{
    watch_stop(ses);
    ses->id = 0;
    if (ses->sockfd >= 0) {
        close(ses->sockfd);
        ses->sockfd = -1;
    }
    if (ses->rbuf) {
        free(ses->rbuf);
        ses->rbuf = NULL;
    }
    if (ses) {
        while (ses->wlist_cnt) {
            _wlist_shift(ses);
        }
    }

    return 0;
}

int nw_ses_release(nw_ses *ses)
{
    nw_ses_close(ses);
    free(ses->peer_addr);
    ses->peer_addr = NULL;

    return 0;
}

static size_t _wlist_write(nw_ses* ses, const void* data, size_t len)
{
    const void* pos = data;
    size_t left = len;

    if (ses->wlist_tail && _buf_avail(ses->wlist_tail)) {
        size_t ret = _buf_write(ses->wlist_tail, pos, left);
        left -= ret;
        pos += ret;
    }

    while (left) {
        if (ses->wlist_limit && ses->wlist_cnt >= ses->wlist_limit)
            return len - left;
        nw_buf* buf = _buf_alloc(ses->buf_limit);
        if (buf == NULL)
            return len - left;
        if (ses->wlist_head == NULL)
            ses->wlist_head = buf;
        if (ses->wlist_tail != NULL)
            ses->wlist_tail->next = buf;
        ses->wlist_tail = buf;
        ++ses->wlist_cnt;
        size_t ret = _buf_write(ses->wlist_tail, pos, left);
        left -= ret;
        pos += ret;
    }

    return len;
}

static size_t _wlist_append(nw_ses* ses, const void* data, size_t len)
{
    if (ses->wlist_limit && ses->wlist_cnt >= ses->wlist_limit)
        return 0;
    nw_buf* buf = _buf_alloc(ses->buf_limit);
    if (buf == NULL)
        return 0;
    if (len > buf->size) {
        free(buf);
        return 0;
    }
    _buf_write(buf, data, len);
    if (ses->wlist_head == NULL)
        ses->wlist_head = buf;
    if (ses->wlist_tail != NULL)
        ses->wlist_tail->next = buf;
    ses->wlist_tail = buf;
    ++ses->wlist_cnt;

    return len;
}

static void _wlist_shift(nw_ses* ses)
{
    if (ses->wlist_head) {
        nw_buf* tmp = ses->wlist_head;
        ses->wlist_head = tmp->next;
        if (ses->wlist_head == NULL) {
            ses->wlist_tail = NULL;
        }
        --ses->wlist_cnt;
        free(tmp);
    }
}
