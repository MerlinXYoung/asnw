/*
 * Description: 
 *     History: yang@haipo.me, 2016/03/20, create
 */

# include <stdlib.h>
# include <stdio.h>
# include <unistd.h>
# include "nw_svr.h"

static int create_socket(int family, int sock_type)
{
    int sockfd = socket(family, sock_type, 0);
    if (sockfd < 0)
        return -1;
    if (nw_sock_set_nonblock(sockfd) < 0) {
        close(sockfd);
        return -1;
    }
    if (nw_sock_set_reuse_addr(sockfd) < 0) {
        close(sockfd);
        return -1;
    }
    if (sock_type == SOCK_STREAM && (family == AF_INET || family == AF_INET6)) {
        if (nw_sock_set_no_delay(sockfd) < 0) {
            close(sockfd);
            return -1;
        }
    }

    return sockfd;
}

static int set_socket_option(nw_svr *svr, int sockfd)
{
    if (svr->read_mem > 0) {
        if (nw_sock_set_recv_buf(sockfd, svr->read_mem) < 0) {
            close(sockfd);
            return -1;
        }
    }
    if (svr->write_mem > 0) {
        if (nw_sock_set_send_buf(sockfd, svr->write_mem) < 0) {
            close(sockfd);
            return -1;
        }
    }

    return 0;
}

static void on_error(nw_ses *ses, const char *msg)
{
    nw_svr *svr = (nw_svr *)ses->svr;
    if (svr->type.on_error_msg) {
        svr->type.on_error_msg(ses, msg);
    }
    if (ses->ses_type == NW_SES_TYPE_COMMON) {
        nw_svr_close_clt(svr, ses);
    }
}

static void on_close(nw_ses *ses)
{
    nw_svr *svr = (nw_svr *)ses->svr;
    if (ses->ses_type == NW_SES_TYPE_COMMON) {
        nw_svr_close_clt(svr, ses);
    }
}

static void on_recv_fd(nw_ses *ses, int fd)
{
    close(fd);
}

static void nw_svr_free(nw_svr *svr)
{
    if (svr->svr_list) {
        for (uint32_t i = 0; i < svr->svr_cnt; ++i) {
            //if (svr->svr_list[i].write_buf != NULL) {
                nw_ses_release(&svr->svr_list[i]);
                free(svr->svr_list[i].host_addr);
            //}
        }
        free(svr->svr_list);
    }
    free(svr);
}

static int nw_svr_add_clt(nw_ses *ses, int sockfd, struct sockaddr *peer_addr)
{
    nw_svr *svr = (nw_svr *)ses->svr;
    set_socket_option(svr, sockfd);
    if (nw_sock_set_nonblock(sockfd) < 0) {
        return -1;
    }

    void *privdata = NULL;
    if (svr->type.on_privdata_alloc) {
        privdata = svr->type.on_privdata_alloc(svr);
        if (privdata == NULL) {
            return -1;
        }
    }

    nw_ses *clt = calloc(1,sizeof(nw_ses));
    if (clt == NULL) {
        return -1;
    }
    if (nw_ses_init(clt, nw_default_loop, peer_addr, ses->addrlen, svr->max_pkg_size, svr->buf_limit, NW_SES_TYPE_COMMON) < 0) {
        free(clt);
        if (privdata) {
            svr->type.on_privdata_free(svr, privdata);
        }
        return -1;
    }
    //memcpy(&clt->peer_addr, peer_addr, ses->addrlen);
    clt->host_addr   = ses->host_addr;
    clt->sockfd      = sockfd;
    clt->sock_type   = ses->sock_type;
    clt->privdata    = privdata;
    clt->svr         = svr;

    clt->id = svr->id_start++;
    if (clt->id == 0)
        clt->id = svr->id_start++;

    clt->decode_pkg  = svr->type.decode_pkg;
    clt->on_recv_pkg = svr->type.on_recv_pkg;
    clt->on_recv_fd  = svr->type.on_recv_fd == NULL ? on_recv_fd : svr->type.on_recv_fd;
    clt->on_error    = on_error;
    clt->on_close    = on_close;

    if (svr->clt_list_tail) {
        clt->prev = svr->clt_list_tail;
        svr->clt_list_tail->next = clt;
        svr->clt_list_tail = clt;
        clt->next = NULL;
    } else {
        svr->clt_list_head = clt;
        svr->clt_list_tail = clt;
        clt->prev = NULL;
        clt->next = NULL;
    }
    svr->clt_cnt++;
    nw_ses_start(clt);

    if (svr->type.on_new_connection) {
        svr->type.on_new_connection(clt);
    }

    return 0;
}

static int on_accept(nw_ses *ses, int sockfd, struct sockaddr *peer_addr)
{
    nw_svr *svr = (nw_svr *)ses->svr;
    if (svr->type.on_accept) {
        return svr->type.on_accept(ses, sockfd, peer_addr);
    }
    return nw_svr_add_clt(ses, sockfd, peer_addr);
}

int nw_svr_add_clt_fd(nw_svr *svr, int fd)
{
    struct sockaddr_storage peer_addr;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    if (getpeername(fd, (struct sockaddr*)&peer_addr, &addrlen) < 0) {
        return -1;
    }
    nw_ses *ses = NULL;
    for (uint32_t i = 0; i < svr->svr_cnt; ++i) {
        if (peer_addr.ss_family == svr->svr_list[i].host_addr->sa_family) {
            ses = &svr->svr_list[i];
            break;
        }
    }
    if (ses == NULL)
        return -1;
    return nw_svr_add_clt(ses, fd, (struct sockaddr*)&peer_addr);
}

nw_svr *nw_svr_create(nw_svr_cfg *cfg, nw_svr_type *type, void *privdata)
{
    nw_loop_init();

    if (cfg->bind_count == 0) 
        return NULL;
    if (cfg->max_pkg_size == 0)
        return NULL;
    if (type->decode_pkg == NULL)
        return NULL;
    if (type->on_recv_pkg == NULL)
        return NULL;
    if (type->on_privdata_alloc && !type->on_privdata_free)
        return NULL;

    nw_svr *svr = calloc(1, sizeof(nw_svr));
    if (svr == NULL)
        return NULL;

    svr->type = *type;
    svr->svr_cnt = cfg->bind_count;
    svr->svr_list = calloc(svr->svr_cnt, sizeof(nw_ses));
    if (svr->svr_list == NULL) {
        nw_svr_free(svr);
        return NULL;
    }
    svr->max_pkg_size = cfg->max_pkg_size;
    svr->buf_limit = cfg->buf_limit;
    svr->read_mem = cfg->read_mem;
    svr->write_mem = cfg->write_mem;
    svr->privdata = privdata;

    for (uint32_t i = 0; i < svr->svr_cnt; ++i) {
        nw_ses *ses = &svr->svr_list[i];
        int sockfd = create_socket(cfg->bind_arr[i].addr.ss_family, cfg->bind_arr[i].sock_type);
        if (sockfd < 0) {
            nw_svr_free(svr);
            return NULL;
        }
        socklen_t addrlen = nw_sockaddr_len(cfg->bind_arr[i].addr.ss_family);
        struct sockaddr *host_addr = (struct sockaddr*)malloc(addrlen);
        if (host_addr == NULL) {
            nw_svr_free(svr);
            return NULL;
        }
        //host_addr->sa_family = cfg->bind_arr[i].addr.ss_family;
        memcpy(host_addr, &cfg->bind_arr[i].addr, addrlen);
        if (nw_ses_init(ses, nw_default_loop, NULL, addrlen,
            svr->max_pkg_size, svr->buf_limit, NW_SES_TYPE_SERVER) < 0) {
            free(host_addr);
            nw_svr_free(svr);
            return NULL;
        }
        ses->sockfd      = sockfd;
        ses->sock_type   = cfg->bind_arr[i].sock_type;
        ses->host_addr   = host_addr;
        ses->svr         = svr;

        ses->on_accept   = on_accept;
        ses->decode_pkg  = type->decode_pkg;
        ses->on_recv_pkg = type->on_recv_pkg;
        ses->on_recv_fd  = type->on_recv_fd == NULL ? on_recv_fd : type->on_recv_fd;
        ses->on_error    = on_error;
        ses->on_close    = on_close;

        if (cfg->bind_arr[i].sock_type == SOCK_DGRAM) {
            ses->peer_addr->sa_family = host_addr->sa_family;
            //ses->peer_addr.addrlen = host_addr->addrlen;
            set_socket_option(svr, sockfd);
        }
    }

    return svr;
}

int nw_svr_start(nw_svr *svr)
{
    for (uint32_t i = 0; i < svr->svr_cnt; ++i) {
        nw_ses *ses = &svr->svr_list[i];
        if (nw_ses_bind(ses, ses->host_addr) < 0) {
            return -1;
        }
        if (nw_ses_start(ses) < 0) {
            return -1;
        }
    }

    return 0;
}

int nw_svr_stop(nw_svr *svr)
{
    for (uint32_t i = 0; i < svr->svr_cnt; ++i) {
        if (nw_ses_stop(&svr->svr_list[i]) < 0) {
            return -1;
        }
    }
    return 0;
}

void nw_svr_release(nw_svr *svr)
{
    nw_svr_stop(svr);
    nw_ses *curr = svr->clt_list_head;
    while (curr) {
        nw_ses *next = curr->next;
        if (svr->type.on_connection_close) {
            svr->type.on_connection_close(curr);
        }
        if (curr->privdata) {
            svr->type.on_privdata_free(svr, curr->privdata);
        }
        nw_ses_release(curr);
        free(curr);
        curr = next;
    }
    for (uint32_t i = 0; i < svr->svr_cnt; ++i) {
        nw_ses_release(&svr->svr_list[i]);
    }
    nw_svr_free(svr);
}

void nw_svr_close_clt(nw_svr *svr, nw_ses *ses)
{
    if (ses->id == 0)
        return;
    if (ses->ses_type != NW_SES_TYPE_COMMON)
        return;

    if (svr->type.on_connection_close) {
        svr->type.on_connection_close(ses);
    }
    if (ses->prev) {
        ses->prev->next = ses->next;
    } else {
        svr->clt_list_head = ses->next;
    }
    if (ses->next) {
        ses->next->prev = ses->prev;
    } else {
        svr->clt_list_tail = ses->prev;
    }
    if (ses->privdata) {
        svr->type.on_privdata_free(svr, ses->privdata);
    }
    nw_ses_release(ses);
    free(ses);
    --svr->clt_cnt;
}

