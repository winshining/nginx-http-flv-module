
/*
 * Copyright (C) Winshining
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


#define NGX_RTMP_CACHE            0
#define NGX_RTMP_PROXY_TEMP_PATH  "rtmp_proxy_temp"


static ngx_int_t ngx_rtmp_proxy_create_request(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_proxy_reinit_request(ngx_rtmp_session_t *s);
static void ngx_rtmp_proxy_abort_request(ngx_rtmp_session_t *s);
static void ngx_rtmp_proxy_finalize_request(ngx_rtmp_session_t *s,
    ngx_int_t rc); /* rc may be useless */
static ngx_int_t ngx_rtmp_proxy_copy_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);

static void *ngx_rtmp_proxy_create_main_conf(ngx_conf_t *cf);
static void *ngx_rtmp_proxy_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_proxy_merge_app_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_rtmp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_path_init_t  ngx_rtmp_proxy_temp_path = {
    ngx_string(NGX_RTMP_PROXY_TEMP_PATH), { 1, 2, 0 }
}


static void
ngx_rtmp_proxy_abort_request(ngx_rtmp_session_t *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "abort rtmp proxy request");

    return;
}


static void
ngx_rtmp_proxy_finalize_request(ngx_rtmp_session_t *s,
    ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "finalize rtmp proxy request");

    return;
}


static void *
ngx_rtmp_proxy_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_proxy_main_conf_t    *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_proxy_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NGX_RTMP_CACHE)
    if (ngx_array_init(&conf->caches, cf->pool, 4,
           sizeof(ngx_rtmp_file_cache_t *)) != NGX_OK)
    {
        return NULL;
    }
#endif

    return conf;
}


static void *
ngx_rtmp_proxy_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_proxy_app_conf_t    *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_proxy_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_str_set(&conf->upstream.module, "rtmp_proxy");

    return conf;
}


static char *
ngx_rtmp_proxy_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_proxy_app_conf_t  *prev = parent;
    ngx_rtmp_proxy_app_conf_t  *conf = child;

#if (NGX_HTTP_CACHE)
    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_proxy_handler(ngx_rtmp_session_t *r)
{
    return NGX_OK;
}


static char *
ngx_rtmp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_proxy_loc_conf_t   *plcf;
    ngx_rtmp_core_app_conf_t    *cacf;

    plcf = conf;
    if (plcf->upstream.upstream || plcf->proxy_lengths) {
        return "is duplicate";
    }

    cacf->handler = ngx_rtmp_proxy_handler;

    return NGX_CONF_OK;
}

