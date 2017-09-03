
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Winshining
 */


#ifndef _NGX_RTMP_UPSTREAM_H_INCLUDED_
#define _NGX_RTMP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include "ngx_rtmp.h"


#define NGX_RTMP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_RTMP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_RTMP_UPSTREAM_FT_RTMP_500        0x00000010
#define NGX_RTMP_UPSTREAM_FT_RTMP_502        0x00000020
#define NGX_RTMP_UPSTREAM_FT_RTMP_403        0x00000100
#define NGX_RTMP_UPSTREAM_FT_RTMP_404        0x00000200
#define NGX_RTMP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_RTMP_UPSTREAM_FT_OFF             0x80000000


#define NGX_RTMP_WRITE_BUFFERED              0x10

#define NGX_RTMP_SPECIAL_RESPONSE            300

#define NGX_RTMP_BAD_REQUEST                 400
#define NGX_RTMP_FORBIDDEN                   403
#define NGX_RTMP_NOT_FOUND                   404

/* Our own RTMP codes */

/* The special code to close connection without any response */
#define NGX_RTMP_REQUEST_TIME_OUT            408
#define NGX_RTMP_CLIENT_CLOSED_REQUEST       499

#define NGX_RTMP_INTERNAL_SERVER_ERROR       500
#define NGX_RTMP_BAD_GATEWAY                 502
#define NGX_RTMP_GATEWAY_TIME_OUT            504


typedef struct ngx_rtmp_upstream_ctx_s ngx_rtmp_upstream_ctx_t;

struct ngx_rtmp_upstream_ctx_s {
    ngx_str_t                       name;
    ngx_str_t                       url;
    ngx_log_t                       log;
    ngx_rtmp_session_t             *session;
    ngx_rtmp_upstream_ctx_t        *publish;
    ngx_rtmp_upstream_ctx_t        *play;
    ngx_rtmp_upstream_ctx_t        *next;

    ngx_str_t                       app;
    ngx_str_t                       tc_url;
    ngx_str_t                       page_url;
    ngx_str_t                       swf_url;
    ngx_str_t                       flash_ver;
    ngx_str_t                       play_path;
    ngx_int_t                       live;
    ngx_int_t                       start;
    ngx_int_t                       stop;

    ngx_event_t                     push_evt;
    void                           *tag;
    void                           *data;
};


typedef struct {
    ngx_array_t                      upstreams;
                                             /* ngx_rtmp_upstream_srv_conf_t */

    ngx_log_t                       *log;
    ngx_uint_t                       nbuckets;
    ngx_msec_t                       buflen;
    ngx_flag_t                       session_upstream;
    ngx_msec_t                       push_reconnect;
    ngx_msec_t                       pull_reconnect;
    ngx_rtmp_upstream_ctx_t        **ctx;
} ngx_rtmp_upstream_main_conf_t;

typedef struct ngx_rtmp_upstream_srv_conf_s    ngx_rtmp_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_rtmp_upstream_init_pt)(ngx_conf_t *cf,
    ngx_rtmp_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_rtmp_upstream_init_peer_pt)(ngx_rtmp_session_t *s,
    ngx_rtmp_upstream_srv_conf_t *us);


typedef struct {
    ngx_rtmp_upstream_init_pt        init_upstream;
    ngx_rtmp_upstream_init_peer_pt   init;
    void                            *data;
} ngx_rtmp_upstream_peer_t;


typedef struct {
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_conns;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;

    unsigned                         down:1;
    unsigned                         backup:1;

    NGX_COMPAT_BEGIN(6)
    NGX_COMPAT_END
} ngx_rtmp_upstream_server_t;


typedef void (*ngx_rtmp_cleanup_pt)(void *data);


#define NGX_RTMP_UPSTREAM_CREATE        0x0001
#define NGX_RTMP_UPSTREAM_WEIGHT        0x0002
#define NGX_RTMP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_RTMP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_RTMP_UPSTREAM_DOWN          0x0010
#define NGX_RTMP_UPSTREAM_BACKUP        0x0020
#define NGX_RTMP_UPSTREAM_MAX_CONNS     0x0100


struct ngx_rtmp_upstream_srv_conf_s {
    ngx_rtmp_upstream_peer_t        peer;
    void                          **srv_conf;

    ngx_array_t                    *servers;  /* ngx_rtmp_upstream_server_t */

    ngx_uint_t                      flags;
    ngx_str_t                       host;
    u_char                         *file_name;
    ngx_uint_t                      line;
    in_port_t                       port;
    ngx_uint_t                      no_port;

#if (NGX_RTMP_UPSTREAM_ZONE)
    ngx_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_rtmp_complex_value_t        *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent;
#endif
} ngx_rtmp_upstream_local_t;


typedef struct {
    ngx_rtmp_upstream_srv_conf_t    *upstream;

    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       next_upstream_timeout;

    size_t                           send_lowat;
    size_t                           limit_rate;

    ngx_uint_t                       next_upstream;
    ngx_uint_t                       next_upstream_tries;

    ngx_flag_t                       ignore_client_abort;

    ngx_rtmp_upstream_local_t       *local;

    ngx_str_t                        module;

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
} ngx_rtmp_upstream_conf_t;


typedef struct {
    ngx_str_t                host;
    in_port_t                port;
    ngx_uint_t               no_port;

    ngx_uint_t               naddrs;
    ngx_resolver_addr_t     *addrs;

    struct sockaddr         *sockaddr;
    socklen_t                socklen;
    ngx_str_t                name;

    ngx_resolver_ctx_t       *ctx;
} ngx_rtmp_upstream_resolved_t;


typedef void (*ngx_rtmp_upstream_handler_pt)(ngx_rtmp_session_t *s,
        ngx_rtmp_upstream_t *u);


struct ngx_rtmp_upstream_s {
    ngx_rtmp_upstream_handler_pt     read_event_handler;
    ngx_rtmp_upstream_handler_pt     write_event_handler;

    ngx_peer_connection_t            peer;

    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

    /* for setting peer */
    ngx_rtmp_upstream_resolved_t    *resolved;

    ngx_rtmp_upstream_conf_t        *conf;
    ngx_rtmp_upstream_srv_conf_t    *upstream;

    /* to downstream */
    ngx_chain_t                     *out_bufs;
    /* not to downstream yet */
    ngx_chain_t                     *busy_bufs;
    ngx_chain_t                     *free_bufs;

    ngx_int_t                      (*rewrite_redirect)(ngx_rtmp_session_t *s,
                                         ngx_table_elt_t *h, size_t prefix);

    ngx_rtmp_cleanup_pt             *cleanup;

    ngx_str_t                        schema;
    ngx_str_t                        uri;

    unsigned                         keepalive:1;

    unsigned                         handshake_done:1;
};


ngx_int_t ngx_rtmp_upstream_create(ngx_rtmp_session_t *s);
ngx_rtmp_upstream_srv_conf_t *ngx_rtmp_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_rtmp_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
void ngx_rtmp_upstream_push_reconnect(ngx_event_t *ev);

void ngx_rtmp_upstream_recv(ngx_event_t *rev);
void ngx_rtmp_upstream_send(ngx_event_t *wev);

ngx_int_t ngx_rtmp_upstream_on_result(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_upstream_on_error(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_upstream_on_status(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_upstream_handshake_done(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);
void ngx_rtmp_upstream_close(ngx_rtmp_session_t *s);


extern ngx_module_t    ngx_rtmp_upstream_module;

typedef struct {
    ngx_url_t                       url;
    ngx_str_t                       app;
    ngx_str_t                       name;
    ngx_str_t                       tc_url;
    ngx_str_t                       page_url;
    ngx_str_t                       swf_url;
    ngx_str_t                       flash_ver;
    ngx_str_t                       play_path;
    ngx_int_t                       live;
    ngx_int_t                       start;
    ngx_int_t                       stop;

    void                           *tag;     /* usually module reference */
    void                           *data;    /* module-specific data */
} ngx_rtmp_upstream_target_t;


#endif /* _NGX_RTMP_UPSTREAM_H_INCLUDED_ */

