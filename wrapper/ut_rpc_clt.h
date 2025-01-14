/*
 * Description: 
 *     History: yang@haipo.me, 2016/03/30, create
 */

# ifndef _UT_RPC_CLT_H_
# define _UT_RPC_CLT_H_

# include "ut_rpc.h"
# include "nw_clt.h"
# include "nw_timer.h"

typedef struct rpc_clt_cfg {
    char *name;
    uint32_t addr_count;
    nw_sockaddr *addr_arr;
    int sock_type;
    uint32_t read_mem;
    uint32_t write_mem;
    double reconnect_timeout;
} rpc_clt_cfg;

typedef struct rpc_clt_type {
    void (*on_recv_pkg)(nw_ses *ses, rpc_pkg *pkg);
    void (*on_connect)(nw_ses *ses, bool result);
} rpc_clt_type;

typedef struct rpc_clt {
    char *name;
    nw_clt *raw_clt;
    uint32_t addr_count;
    uint32_t curr_index;
    nw_sockaddr *addr_arr;
    nw_timer timer;
    double last_heartbeat;
    void (*on_recv_pkg)(nw_ses *ses, rpc_pkg *pkg);
    void (*on_connect)(nw_ses *ses, bool result);
} rpc_clt;

rpc_clt *rpc_clt_create(rpc_clt_cfg *cfg, rpc_clt_type *type);
int rpc_clt_start(rpc_clt *clt);
int rpc_clt_close(rpc_clt *clt);
int rpc_clt_send(rpc_clt *clt, rpc_pkg *pkg);
void rpc_clt_release(rpc_clt *clt);
bool rpc_clt_connected(rpc_clt *clt);

# endif

