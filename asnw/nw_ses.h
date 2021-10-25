/*
 * Description: network session
 *     History: yang@haipo.me, 2016/03/18, create
 */

# ifndef _NW_SES_H_
# define _NW_SES_H_

# include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
# include "nw_evt.h"
# include "nw_sock.h"
#ifdef __cplusplus
extern "C" {
#endif
    /*
     * nw_ses is low level object for nw_svr and nw_clt,
     * represent a sockfd and the related data and operation,
     * should not use it directly
     */

    enum {
        NW_SES_TYPE_COMMON, /* stream connection */
        NW_SES_TYPE_CLIENT, /* clinet side */
        NW_SES_TYPE_SERVER, /* server side */
    };
    struct nw_buf;
    typedef struct nw_ses {
        /* the libev instance */
        ev_io ev;
        /* the loop instance, should be nw_default_loop */
        struct ev_loop* loop;
        int sockfd;
        struct {
            /* one of SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET */
            int sock_type : 16;
            /* one of NW_SES_TYPE_COMMON, NW_SES_TYPE_CLIENT, NW_SES_TYPE_SERVER */
            int ses_type : 16;
        };
        /* peer addr */
        nw_addr_t peer_addr;
        /* host addr */
        nw_addr_t* host_addr;

        uint32_t buf_limit;
        struct nw_buf* rbuf;

        uint32_t wlist_cnt;
        uint32_t wlist_limit;
        struct nw_buf* wlist_head;
        struct nw_buf* wlist_tail;
        /* nw_svr will assign every connection a uniq id */
        uint64_t id;
        void* privdata;
        void* svr;

        struct nw_ses* prev;
        struct nw_ses* next;

        int  (*decode_pkg)(struct nw_ses* ses, void* data, size_t max);
        union {
            int  (*on_accept)(struct nw_ses* ses, int sockfd, nw_addr_t* peer_addr);
            void (*on_connect)(struct nw_ses* ses, bool result);
        };
        void (*on_recv_pkg)(struct nw_ses* ses, void* data, size_t size);
        void (*on_recv_fd)(struct nw_ses* ses, int fd);
        void (*on_error)(struct nw_ses* ses, const char* msg);
        void (*on_close)(struct nw_ses* ses);
    } nw_ses;

    int nw_ses_bind(nw_ses* ses, nw_addr_t* addr);
    int nw_ses_listen(nw_ses* ses, int backlog);
    int nw_ses_connect(nw_ses* ses, nw_addr_t* addr);

    int nw_ses_start(nw_ses* ses);
    int nw_ses_stop(nw_ses* ses);
    int nw_ses_send(nw_ses* ses, const void* data, size_t size);
    /* send a fd, only when the connection is SOCK_SEQPACKET type */
    int nw_ses_send_fd(nw_ses* ses, int fd);

    int nw_ses_init(nw_ses* ses, struct ev_loop* loop, uint32_t buf_limit, uint32_t wlist_limit, int ses_type);
    int nw_ses_close(nw_ses* ses);
    int nw_ses_release(nw_ses* ses);
#ifdef __cplusplus
}
#endif
# endif

