
/*
 * Copyright (C) Winshining
 */

#ifndef _NGX_HTTP_FLV_LIVE_H_INCLUDE_
#define _NGX_HTTP_FLV_LIVE_H_INCLUDE_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_codec_module.h"


#define NGX_HASH_MAX_SIZE              0x80
#define NGX_HASH_MAX_BUKET_SIZE        0x40
#define NGX_BUFF_MAX_SIZE              0X80
#define NGX_FLV_TAG_HEADER_SIZE        11


extern ngx_module_t ngx_rtmp_module;


#define ngx_rtmp_cycle_get_module_main_conf(cycle, module)                \
    (cycle->conf_ctx[ngx_rtmp_module.index] ?                             \
        ((ngx_rtmp_conf_ctx_t *) cycle->conf_ctx[ngx_rtmp_module.index])  \
            ->main_conf[module.ctx_index]:                                \
        NULL)


typedef struct ngx_http_flv_live_srv_info_s {
    ngx_uint_t srv_index;
} ngx_http_flv_live_srv_info_t;


typedef struct ngx_http_flv_live_app_info_s {
    ngx_uint_t app_index;
	ngx_str_t  app_name;
} ngx_http_flv_live_app_info_t;


typedef struct ngx_http_flv_live_app_s {
    ngx_str_t                    hash_name;
    ngx_http_flv_live_srv_info_t srv;
    ngx_http_flv_live_app_info_t app;
} ngx_http_flv_live_app_t;


typedef struct ngx_http_flv_live_ctx_s {
    ngx_flag_t               flv_live;
    ngx_flag_t               chunked;
    ngx_flag_t               joined;
    ngx_http_flv_live_app_t  app;
    ngx_str_t                stream;
    ngx_rtmp_session_t      *s;
} ngx_http_flv_live_ctx_t;


typedef struct ngx_http_flv_live_hash_s {
    ngx_hash_init_t        hint;
    ngx_hash_keys_arrays_t ha; /* temporary for hash */
    ngx_hash_combined_t    hash;
} ngx_http_flv_live_hash_t;


typedef struct ngx_http_flv_live_conf_s {
    ngx_flag_t               flv_live;
    ngx_flag_t               chunked;
    ngx_http_flv_live_hash_t app_hash;
    ngx_http_flv_live_app_t  default_hash;
} ngx_http_flv_live_conf_t;


typedef struct {
    ngx_int_t (*send_message_pt)(ngx_rtmp_session_t *s,
            ngx_chain_t *out, unsigned int priority);
    ngx_chain_t *(*append_message_pt)(ngx_rtmp_session_t *s,
            ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh,
            ngx_chain_t *in);
    void (*free_message_pt)(ngx_rtmp_session_t *s,
            ngx_chain_t *in);
} ngx_rtmp_process_handler_t;


ngx_chain_t *ngx_http_flv_live_append_shared_bufs(
        ngx_rtmp_core_srv_conf_t *cscf,
        ngx_rtmp_header_t *h,
        ngx_chain_t *in,
        ngx_flag_t chunked);


#endif

