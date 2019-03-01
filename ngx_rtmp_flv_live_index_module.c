
/*
 * Copyright (C) Winshining
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_http_flv_live_module.h"


static ngx_rtmp_play_pt         next_play;
static ngx_rtmp_close_stream_pt next_close_stream;


static ngx_int_t ngx_rtmp_flv_live_index_postconfiguration(ngx_conf_t *cf);


static ngx_rtmp_module_t ngx_rtmp_flv_live_module_ctx = {
    NULL,
    ngx_rtmp_flv_live_index_postconfiguration,  /* postconfiguration */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};


static ngx_command_t ngx_rtmp_flv_live_index_commands[] = {
    ngx_null_command
};


ngx_module_t ngx_rtmp_flv_live_index_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_flv_live_module_ctx,
    ngx_rtmp_flv_live_index_commands,
    NGX_RTMP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_rtmp_flv_live_index_postconfiguration(ngx_conf_t *cf)
{
    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_http_flv_live_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_http_flv_live_close_stream;

    http_flv_live_next_play = next_play;
    http_flv_live_next_close_stream = next_close_stream;

    return NGX_OK;
}

