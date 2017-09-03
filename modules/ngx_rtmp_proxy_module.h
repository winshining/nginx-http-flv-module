
/*
 * Copyright (C) Winshining
 */

#ifndef _NGX_RTMP_PROXY_H_INCLUDED_
#define _NGX_RTMP_PROXY_H_INCLUDED_


#include "ngx_rtmp.h"


typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_rtmp_proxy_vars_t;


typedef struct {
    ngx_rtmp_upstream_conf_t       upstream;

    u_char                         name[NGX_RTMP_MAX_NAME];
    u_char                         args[NGX_RTMP_MAX_ARGS];
    ngx_event_t                    push_evt;

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;

    ngx_str_t                      application;
    ngx_str_t                      url;

    ngx_rtmp_proxy_vars_t          vars;

    ngx_flag_t                     redirect;
} ngx_rtmp_proxy_app_conf_t;


extern ngx_module_t ngx_rtmp_proxy_module;


#endif /* _NGX_RTMP_PROXY_H_INCLUDED_ */

