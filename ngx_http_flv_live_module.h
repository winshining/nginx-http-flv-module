
/*
 * Copyright (C) Winshining
 */

#ifndef _NGX_HTTP_FLV_LIVE_H_INCLUDED_
#define _NGX_HTTP_FLV_LIVE_H_INCLUDED_


#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_codec_module.h"


#define NGX_HASH_MAX_SIZE              0x80
#define NGX_HASH_MAX_BUKET_SIZE        0x40
#define NGX_BUFF_MAX_SIZE              0x80
#define NGX_FLV_TAG_HEADER_SIZE        11


extern ngx_module_t ngx_rtmp_module;


#define ngx_rtmp_cycle_get_module_main_conf(cycle, module)                \
    (cycle->conf_ctx[ngx_rtmp_module.index] ?                             \
        ((ngx_rtmp_conf_ctx_t *) cycle->conf_ctx[ngx_rtmp_module.index])  \
            ->main_conf[module.ctx_index]:                                \
        NULL)


typedef struct ngx_http_flv_live_ctx_s {
    ngx_rtmp_session_t  *s;
    ngx_flag_t           flv_live;
    ngx_flag_t           header_sent;

    ngx_str_t            app;
    ngx_str_t            port;
    ngx_str_t            stream;
} ngx_http_flv_live_ctx_t;


typedef struct ngx_http_flv_live_conf_s {
    ngx_flag_t    flv_live;
} ngx_http_flv_live_conf_t;


typedef struct {
    ngx_chain_t  *meta;
    ngx_chain_t  *apkt;
    ngx_chain_t  *acopkt;
    ngx_chain_t  *rpkt;

    ngx_int_t (*send_message_pt)(ngx_rtmp_session_t *s,
            ngx_chain_t *out, unsigned int priority);
    ngx_chain_t *(*meta_message_pt)(ngx_rtmp_session_t *s,
            ngx_chain_t *in);
    ngx_chain_t *(*append_message_pt)(ngx_rtmp_session_t *s,
            ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh,
            ngx_chain_t *in);
    void (*free_message_pt)(ngx_rtmp_session_t *s,
            ngx_chain_t *in);
} ngx_rtmp_live_process_handler_t;


ngx_int_t ngx_http_flv_live_join(ngx_rtmp_session_t *s, u_char *name,
        unsigned int publisher);
ngx_int_t ngx_http_flv_live_send_header(ngx_rtmp_session_t *s);
void ngx_http_flv_live_start(ngx_rtmp_session_t *s);
ngx_chain_t *ngx_http_flv_live_append_shared_bufs(
        ngx_rtmp_core_srv_conf_t *cscf,
        ngx_rtmp_header_t *h,
        ngx_chain_t *in,
        ngx_flag_t chunked);


#endif

