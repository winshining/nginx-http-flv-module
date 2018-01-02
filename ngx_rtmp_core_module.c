
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Winshining
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include "ngx_rtmp.h"


static ngx_int_t ngx_rtmp_core_preconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_rtmp_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_rtmp_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_rtmp_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_rtmp_core_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_core_merge_app_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_rtmp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_rtmp_add_listen(ngx_conf_t *cf,
    ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_listen_opt_t *lsopt);
static ngx_int_t ngx_rtmp_add_addresses(ngx_conf_t *cf,
    ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_conf_port_t *port,
    ngx_rtmp_listen_opt_t *lsopt);
static ngx_int_t ngx_rtmp_add_address(ngx_conf_t *cf,
    ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_conf_port_t *port,
    ngx_rtmp_listen_opt_t *lsopt);
static ngx_int_t ngx_rtmp_add_server(ngx_conf_t *cf,
    ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_conf_addr_t *addr);

static char *ngx_rtmp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_rtmp_core_application(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_rtmp_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_rtmp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_rtmp_core_lowat_check(ngx_conf_t *cf, void *post, void *data);
static char *ngx_rtmp_core_pool_size(ngx_conf_t *cf, void *post, void *data);
static char *ngx_rtmp_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_post_t  ngx_rtmp_core_lowat_post =
    { ngx_rtmp_core_lowat_check };

static ngx_conf_post_handler_pt  ngx_rtmp_core_pool_size_p =
    ngx_rtmp_core_pool_size;

ngx_rtmp_core_main_conf_t      *ngx_rtmp_core_main_conf;


static ngx_conf_deprecated_t  ngx_conf_deprecated_so_keepalive = {
    ngx_conf_deprecated, "so_keepalive",
    "so_keepalive\" parameter of the \"listen"
};


static ngx_command_t  ngx_rtmp_core_commands[] = {

    { ngx_string("server"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_rtmp_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_RTMP_SRV_CONF|NGX_CONF_1MORE,
      ngx_rtmp_core_listen,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("server_name"),
      NGX_RTMP_SRV_CONF|NGX_CONF_1MORE,
      ngx_rtmp_core_server_name,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("application"),
      NGX_RTMP_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_rtmp_core_application,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("so_keepalive"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, so_keepalive),
      &ngx_conf_deprecated_so_keepalive },

    { ngx_string("timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, timeout),
      NULL },

    { ngx_string("ping"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, ping),
      NULL },

    { ngx_string("ping_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, ping_timeout),
      NULL },

    { ngx_string("max_streams"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, max_streams),
      NULL },

    { ngx_string("ack_window"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, ack_window),
      NULL },

    { ngx_string("chunk_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, chunk_size),
      NULL },

    { ngx_string("max_message"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, max_message),
      NULL },

    { ngx_string("out_queue"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, out_queue),
      NULL },

    { ngx_string("out_cork"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, out_cork),
      NULL },

    { ngx_string("busy"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, busy),
      NULL },

    /* time fixes are needed for flash clients */
    { ngx_string("play_time_fix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, play_time_fix),
      NULL },

    { ngx_string("publish_time_fix"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, publish_time_fix),
      NULL },

    { ngx_string("buflen"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, buflen),
      NULL },

    { ngx_string("tcp_nopush"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, tcp_nopush),
      NULL },

    { ngx_string("tcp_nodelay"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, tcp_nodelay),
      NULL },

    { ngx_string("send_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, send_timeout),
      NULL },

    { ngx_string("send_lowat"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, send_lowat),
      &ngx_rtmp_core_lowat_post },

    { ngx_string("postpone_output"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, postpone_output),
      NULL },

    { ngx_string("limit_rate"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF
                        /*|NGX_RTMP_LIF_CONF*/
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, limit_rate),
      NULL },

    { ngx_string("limit_rate_after"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF
                        /*|NGX_RTMP_LIF_CONF*/
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, limit_rate_after),
      NULL },

    { ngx_string("keepalive_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE12,
      ngx_rtmp_core_keepalive,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lingering_time"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, lingering_time),
      NULL },

    { ngx_string("lingering_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, lingering_timeout),
      NULL },

    { ngx_string("resolver"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_core_resolver,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("resolver_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, resolver_timeout),
      NULL },

    { ngx_string("connection_pool_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, connection_pool_size),
      &ngx_rtmp_core_pool_size_p },

    { ngx_string("merge_slashes"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_core_srv_conf_t, merge_slashes),
      NULL },

    { ngx_string("pure_audio_threshold"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_core_app_conf_t, pure_audio_threshold),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_core_module_ctx = {
    ngx_rtmp_core_preconfiguration,         /* preconfiguration */
    NULL,                                   /* postconfiguration */
    ngx_rtmp_core_create_main_conf,         /* create main configuration */
    ngx_rtmp_core_init_main_conf,           /* init main configuration */
    ngx_rtmp_core_create_srv_conf,          /* create server configuration */
    ngx_rtmp_core_merge_srv_conf,           /* merge server configuration */
    ngx_rtmp_core_create_app_conf,          /* create app configuration */
    ngx_rtmp_core_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_core_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_core_module_ctx,             /* module context */
    ngx_rtmp_core_commands,                /* module directives */
    NGX_RTMP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_rtmp_core_preconfiguration(ngx_conf_t *cf)
{
	return ngx_rtmp_variables_add_core_vars(cf);
}


static void *
ngx_rtmp_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    ngx_rtmp_core_main_conf = cmcf;

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_rtmp_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    cmcf->server_names_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->server_names_hash_bucket_size = NGX_CONF_UNSET_UINT;

    cmcf->variables_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cmcf;
}


static char *
ngx_rtmp_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_core_main_conf_t *cmcf = conf;

    ngx_conf_init_uint_value(cmcf->server_names_hash_max_size, 512);
    ngx_conf_init_uint_value(cmcf->server_names_hash_bucket_size,
                             ngx_cacheline_size);

    cmcf->server_names_hash_bucket_size =
            ngx_align(cmcf->server_names_hash_bucket_size, ngx_cacheline_size);

    ngx_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    ngx_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
            ngx_align(cmcf->variables_hash_bucket_size, ngx_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_core_srv_conf_t   *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_core_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->server_names, cf->temp_pool, 4,
                       sizeof(ngx_rtmp_server_name_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&conf->applications, cf->pool, 4,
                       sizeof(ngx_rtmp_core_app_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->ping = NGX_CONF_UNSET_MSEC;
    conf->ping_timeout = NGX_CONF_UNSET_MSEC;
    conf->so_keepalive = NGX_CONF_UNSET;
    conf->max_streams = NGX_CONF_UNSET;
    conf->chunk_size = NGX_CONF_UNSET;
    conf->ack_window = NGX_CONF_UNSET_UINT;
    conf->max_message = NGX_CONF_UNSET_SIZE;
    conf->out_queue = NGX_CONF_UNSET_SIZE;
    conf->out_cork = NGX_CONF_UNSET_SIZE;
    conf->play_time_fix = NGX_CONF_UNSET;
    conf->publish_time_fix = NGX_CONF_UNSET;
    conf->buflen = NGX_CONF_UNSET_MSEC;
    conf->busy = NGX_CONF_UNSET;
    conf->connection_pool_size = NGX_CONF_UNSET_SIZE;
    conf->merge_slashes = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_rtmp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_core_srv_conf_t *prev = parent;
    ngx_rtmp_core_srv_conf_t *conf = child;

    ngx_str_t                 name;
    ngx_rtmp_server_name_t   *sn;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    ngx_conf_merge_msec_value(conf->ping, prev->ping, 60000);
    ngx_conf_merge_msec_value(conf->ping_timeout, prev->ping_timeout, 30000);

    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);
    ngx_conf_merge_value(conf->max_streams, prev->max_streams, 32);
    ngx_conf_merge_value(conf->chunk_size, prev->chunk_size, 4096);
    ngx_conf_merge_uint_value(conf->ack_window, prev->ack_window, 5000000);
    ngx_conf_merge_size_value(conf->max_message, prev->max_message,
            1 * 1024 * 1024);
    ngx_conf_merge_size_value(conf->out_queue, prev->out_queue, 256);
    ngx_conf_merge_size_value(conf->out_cork, prev->out_cork,
            conf->out_queue / 8);
    ngx_conf_merge_value(conf->play_time_fix, prev->play_time_fix, 1);
    ngx_conf_merge_value(conf->publish_time_fix, prev->publish_time_fix, 1);
    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 1000);
    ngx_conf_merge_value(conf->busy, prev->busy, 0);
    ngx_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 64 * sizeof(void *));
    ngx_conf_merge_value(conf->merge_slashes, prev->merge_slashes, 1);

    if (prev->pool == NULL) {
        prev->pool = ngx_create_pool(4096, &cf->cycle->new_log);
        if (prev->pool == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    conf->pool = prev->pool;

    if (conf->server_names.nelts == 0) {
        /* the array has 4 empty preallocated elements, so push cannot fail */
        sn = ngx_array_push(&conf->server_names);
#if (NGX_PCRE)
        sn->regex = NULL;
#endif
        sn->server = conf;
        ngx_str_set(&sn->name, "");
    }

    sn = conf->server_names.elts;
    name = sn[0].name;

#if (NGX_PCRE)
    if (sn->regex) {
        name.len++;
        name.data--;
    } else
#endif

    if (name.data[0] == '.') {
        name.len--;
        name.data++;
    }

    conf->server_name.len = name.len;
    conf->server_name.data = ngx_pstrdup(cf->pool, &name);
    if (conf->server_name.data == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_core_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_core_app_conf_t   *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_core_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->applications, cf->pool, 1,
                       sizeof(ngx_rtmp_core_app_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    conf->tcp_nopush = NGX_CONF_UNSET;
    conf->tcp_nodelay = NGX_CONF_UNSET;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_lowat = NGX_CONF_UNSET_SIZE;
    conf->postpone_output = NGX_CONF_UNSET_SIZE;
    conf->limit_rate = NGX_CONF_UNSET_SIZE;
    conf->limit_rate_after = NGX_CONF_UNSET_SIZE;
    conf->keepalive_timeout = NGX_CONF_UNSET_MSEC;
    conf->lingering_time = NGX_CONF_UNSET_MSEC;
    conf->lingering_timeout = NGX_CONF_UNSET_MSEC;
    conf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    conf->pure_audio_threshold = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_rtmp_core_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_core_app_conf_t *prev = parent;
    ngx_rtmp_core_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->tcp_nopush, prev->tcp_nopush, 0);
    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
    ngx_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);

    ngx_conf_merge_size_value(conf->postpone_output, prev->postpone_output,
                              1460);
    ngx_conf_merge_size_value(conf->limit_rate, prev->limit_rate, 0);
    ngx_conf_merge_size_value(conf->limit_rate_after, prev->limit_rate_after,
                              0);
    ngx_conf_merge_size_value(conf->pure_audio_threshold,
                              prev->pure_audio_threshold, 160);
    ngx_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 75000);
    ngx_conf_merge_msec_value(conf->lingering_time,
                              prev->lingering_time, 30000);
    ngx_conf_merge_msec_value(conf->lingering_timeout,
                              prev->lingering_timeout, 5000);
    ngx_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in rtmp {} context
             * to inherit it in all servers
             */

            prev->resolver = ngx_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_module_t              **modules;
    ngx_rtmp_module_t          *module;
    struct sockaddr_in         *sin;
    ngx_rtmp_conf_ctx_t        *ctx, *rtmp_ctx;
    ngx_rtmp_listen_opt_t       lsopt;
    ngx_rtmp_core_srv_conf_t   *cscf, **cscfp;
    ngx_rtmp_core_main_conf_t  *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    rtmp_ctx = cf->ctx;
    ctx->main_conf = rtmp_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif

    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[modules[m]->ctx_index] = mconf;
        }

        if (module->create_app_conf) {
            mconf = module->create_app_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->app_conf[modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_rtmp_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_rtmp_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == NGX_CONF_OK && !cscf->listen) {
        ngx_memzero(&lsopt, sizeof(ngx_rtmp_listen_opt_t));

        sin = &lsopt.sockaddr.sockaddr_in;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(1935);
        sin->sin_addr.s_addr = INADDR_ANY;

        lsopt.socklen = sizeof(struct sockaddr_in);

        lsopt.backlog = NGX_LISTEN_BACKLOG;
        lsopt.rcvbuf = -1;
        lsopt.sndbuf = -1;
#if (NGX_HAVE_SETFIB)
        lsopt.setfib = -1;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
        lsopt.fastopen = -1;
#endif
        lsopt.wildcard = 1;

        (void) ngx_sock_ntop(&lsopt.sockaddr.sockaddr, lsopt.socklen,
                             lsopt.addr, NGX_SOCKADDR_STRLEN, 1);

        if (ngx_rtmp_add_listen(cf, cscf, &lsopt) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return rv;
}


static ngx_int_t
ngx_rtmp_add_listen(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_listen_opt_t *lsopt)
{
    in_port_t                   p;
    ngx_uint_t                  i;
    struct sockaddr            *sa;
    ngx_rtmp_conf_port_t       *port;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    if (cmcf->ports == NULL) {
        cmcf->ports = ngx_array_create(cf->temp_pool, 2,
                                       sizeof(ngx_rtmp_conf_port_t));
        if (cmcf->ports == NULL) {
            return NGX_ERROR;
        }
    }

    sa = &lsopt->sockaddr.sockaddr;
    p = ngx_inet_get_port(sa);

    port = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; i++) {

        if (p != port[i].port || sa->sa_family != port[i].family) {
            continue;
        }

        /* a port is already in the port list */

        return ngx_rtmp_add_addresses(cf, cscf, &port[i], lsopt);
    }

    /* add a port to the port list */

    port = ngx_array_push(cmcf->ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;
    port->addrs.elts = NULL;

    return ngx_rtmp_add_address(cf, cscf, port, lsopt);
}


static ngx_int_t
ngx_rtmp_add_addresses(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_port_t *port, ngx_rtmp_listen_opt_t *lsopt)
{
    ngx_uint_t             i, default_server, proxy_protocol;
    ngx_rtmp_conf_addr_t  *addr;

    /*
     * we cannot compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    addr = port->addrs.elts;

    for (i = 0; i < port->addrs.nelts; i++) {

        if (ngx_cmp_sockaddr(&lsopt->sockaddr.sockaddr, lsopt->socklen,
                             &addr[i].opt.sockaddr.sockaddr,
                             addr[i].opt.socklen, 0)
            != NGX_OK)
        {
            continue;
        }

        /* the address is already in the address list */

        if (ngx_rtmp_add_server(cf, cscf, &addr[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        /* preserve default_server bit during listen options overwriting */
        default_server = addr[i].opt.default_server;

        proxy_protocol = lsopt->proxy_protocol || addr[i].opt.proxy_protocol;

        if (lsopt->set) {

            if (addr[i].opt.set) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "duplicate listen options for %s", addr[i].opt.addr);
                return NGX_ERROR;
            }

            addr[i].opt = *lsopt;
        }

        /* check the duplicate "default" server for this address:port */

        if (lsopt->default_server) {

            if (default_server) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "a duplicate default server for %s", addr[i].opt.addr);
                return NGX_ERROR;
            }

            default_server = 1;
            addr[i].default_server = cscf;
        }

        addr[i].opt.default_server = default_server;
        addr[i].opt.proxy_protocol = proxy_protocol;

        return NGX_OK;
    }

    /* add the address to the addresses list that bound to this port */

    return ngx_rtmp_add_address(cf, cscf, port, lsopt);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */

static ngx_int_t
ngx_rtmp_add_address(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_port_t *port, ngx_rtmp_listen_opt_t *lsopt)
{
    ngx_rtmp_conf_addr_t  *addr;

    if (port->addrs.elts == NULL) {
        if (ngx_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(ngx_rtmp_conf_addr_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    addr->opt = *lsopt;
    addr->hash.buckets = NULL;
    addr->hash.size = 0;
    addr->wc_head = NULL;
    addr->wc_tail = NULL;
#if (NGX_PCRE)
    addr->nregex = 0;
    addr->regex = NULL;
#endif
    addr->default_server = cscf;
    addr->servers.elts = NULL;

    return ngx_rtmp_add_server(cf, cscf, addr);
}


/* add the server core module configuration to the address:port */

static ngx_int_t
ngx_rtmp_add_server(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_conf_addr_t *addr)
{
    ngx_uint_t                  i;
    ngx_rtmp_core_srv_conf_t  **server;

    if (addr->servers.elts == NULL) {
        if (ngx_array_init(&addr->servers, cf->temp_pool, 4,
                           sizeof(ngx_rtmp_core_srv_conf_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        server = addr->servers.elts;
        for (i = 0; i < addr->servers.nelts; i++) {
            if (server[i] == cscf) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a duplicate listen %s", addr->opt.addr);
                return NGX_ERROR;
            }
        }
    }

    server = ngx_array_push(&addr->servers);
    if (server == NULL) {
        return NGX_ERROR;
    }

    *server = cscf;

    return NGX_OK;
}


static char *
ngx_rtmp_core_application(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_int_t                   i;
    ngx_uint_t                  n;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_module_t              **modules;
    ngx_rtmp_module_t          *module;
    ngx_rtmp_conf_ctx_t        *ctx, *pctx;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_app_conf_t   *cacf, **cacfp;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

#if (nginx_version >= 1009011)
    modules = cf->cycle->modules;
#else
    modules = ngx_modules;
#endif

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = modules[i]->ctx;

        if (module->create_app_conf) {
            ctx->app_conf[modules[i]->ctx_index] = module->create_app_conf(cf);
            if (ctx->app_conf[modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    cacf = ctx->app_conf[ngx_rtmp_core_module.ctx_index];
    cacf->app_conf = ctx->app_conf;

    value = cf->args->elts;

    cacf->name = value[1];
    cscf = pctx->srv_conf[ngx_rtmp_core_module.ctx_index];

    cacfp = cscf->applications.elts;
    for (n = 0; n < cscf->applications.nelts; n++) {
        if (cacf->name.len == cacfp[n]->name.len
                && ngx_strncmp(cacf->name.data,
                        cacfp[n]->name.data, cacf->name.len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "duplicate application: \"%V\"", &cacf->name);

            return NGX_CONF_ERROR;
        }
    }

    cacfp = ngx_array_push(&cscf->applications);
    if (cacfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cacfp = cacf;

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_APP_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf= save;

    return rv;
}


static char *
ngx_rtmp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_core_app_conf_t  *cacf = conf;

    ngx_str_t  *value;

    if (cacf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cacf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cacf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_core_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_core_pool_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_MIN_POOL_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           NGX_MIN_POOL_SIZE);
        return NGX_CONF_ERROR;
    }

    if (*sp % NGX_POOL_ALIGNMENT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           NGX_POOL_ALIGNMENT);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_core_app_conf_t *cacf = conf;

    ngx_str_t  *value;

    if (cacf->keepalive_timeout != NGX_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cacf->keepalive_timeout = ngx_parse_time(&value[1], 0);

    if (cacf->keepalive_timeout == (ngx_msec_t) NGX_ERROR) {
        return "invalid value";
    }

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_core_srv_conf_t *cscf = conf;

    ngx_str_t              *value, size;
    ngx_url_t               u;
    ngx_uint_t              n;
    ngx_rtmp_listen_opt_t   lsopt;

    cscf->listen = 1;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;
    u.default_port = 1935;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    ngx_memzero(&lsopt, sizeof(ngx_rtmp_listen_opt_t));

    ngx_memcpy(&lsopt.sockaddr.sockaddr, &u.sockaddr, u.socklen);

    lsopt.socklen = u.socklen;
    lsopt.backlog = NGX_LISTEN_BACKLOG;
    lsopt.rcvbuf = -1;
    lsopt.sndbuf = -1;
#if (NGX_HAVE_SETFIB)
    lsopt.setfib = -1;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    lsopt.fastopen = -1;
#endif
    lsopt.wildcard = u.wildcard;
#if (NGX_HAVE_INET6)
    lsopt.ipv6only = 1;
#endif

    (void) ngx_sock_ntop(&lsopt.sockaddr.sockaddr, lsopt.socklen, lsopt.addr,
                         NGX_SOCKADDR_STRLEN, 1);

    for (n = 2; n < cf->args->nelts; n++) {

        if (ngx_strcmp(value[n].data, "default_server") == 0
            || ngx_strcmp(value[n].data, "default") == 0)
        {
            lsopt.default_server = 1;
            continue;
        }

        if (ngx_strcmp(value[n].data, "bind") == 0) {
            lsopt.set = 1;
            lsopt.bind = 1;
            continue;
        }

#if (NGX_HAVE_SETFIB)
        if (ngx_strncmp(value[n].data, "setfib=", 7) == 0) {
            lsopt.setfib = ngx_atoi(value[n].data + 7, value[n].len - 7);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.setfib == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid setfib \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
        if (ngx_strncmp(value[n].data, "fastopen=", 9) == 0) {
            lsopt.fastopen = ngx_atoi(value[n].data + 9, value[n].len - 9);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.fastopen == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid fastopen \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
#endif

        if (ngx_strncmp(value[n].data, "backlog=", 8) == 0) {
            lsopt.backlog = ngx_atoi(value[n].data + 8, value[n].len - 8);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.backlog == NGX_ERROR || lsopt.backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "rcvbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.rcvbuf = ngx_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.rcvbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "sndbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.sndbuf = ngx_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.sndbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "accept_filter=", 14) == 0) {
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            lsopt.accept_filter = (char *) &value[n].data[14];
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "accept filters \"%V\" are not supported "
                               "on this platform, ignored",
                               &value[n]);
#endif
            continue;
        }

        if (ngx_strcmp(value[n].data, "deferred") == 0) {
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            lsopt.deferred_accept = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the deferred accept is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (ngx_strncmp(value[n].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;

            sa = &lsopt.sockaddr.sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[n].data[10], "n") == 0) {
                    lsopt.ipv6only = 1;

                } else if (ngx_strcmp(&value[n].data[10], "ff") == 0) {
                    lsopt.ipv6only = 0;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[n].data[9]);
                    return NGX_CONF_ERROR;
                }

                lsopt.set = 1;
                lsopt.bind = 1;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%s\", ignored", lsopt.addr);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[n].data, "reuseport") == 0) {
#if (NGX_HAVE_REUSEPORT)
            lsopt.reuseport = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (ngx_strncmp(value[n].data, "so_keepalive=", 13) == 0) {

            if (ngx_strcmp(&value[n].data[13], "on") == 0) {
                lsopt.so_keepalive = 1;

            } else if (ngx_strcmp(&value[n].data[13], "off") == 0) {
                lsopt.so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[n].data + value[n].len;
                s.data = value[n].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepidle = ngx_parse_time(&s, 1);
                    if (lsopt.tcp_keepidle == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepintvl = ngx_parse_time(&s, 1);
                    if (lsopt.tcp_keepintvl == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    lsopt.tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if (lsopt.tcp_keepcnt == NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (lsopt.tcp_keepidle == 0 && lsopt.tcp_keepintvl == 0
                    && lsopt.tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                lsopt.so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[n].data[13]);
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[n].data, "proxy_protocol") == 0) {
            lsopt.proxy_protocol = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[n]);
        return NGX_CONF_ERROR;
    }

    if (ngx_rtmp_add_listen(cf, cscf, &lsopt) == NGX_OK) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}


static char *
ngx_rtmp_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_core_srv_conf_t *cscf = conf;

    u_char                   ch;
    ngx_str_t               *value;
    ngx_uint_t               i;
    ngx_rtmp_server_name_t  *sn;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        ch = value[i].data[0];

        if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
            || (ch == '.' && value[i].len < 2))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "server name \"%V\" is invalid", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strchr(value[i].data, '/')) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "server name \"%V\" has suspicious symbols",
                               &value[i]);
        }

        sn = ngx_array_push(&cscf->server_names);
        if (sn == NULL) {
            return NGX_CONF_ERROR;
        }

#if (NGX_PCRE)
        sn->regex = NULL;
#endif
        sn->server = cscf;

        if (ngx_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
            sn->name = cf->cycle->hostname;

        } else {
            sn->name = value[i];
        }

        if (value[i].data[0] != '~') {
            ngx_strlow(sn->name.data, sn->name.data, sn->name.len);
            continue;
        }

#if (NGX_PCRE)
        {
            u_char               *p;
            ngx_regex_compile_t   rc;
            u_char                errstr[NGX_MAX_CONF_ERRSTR];

            if (value[i].len == 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "empty regex in server name \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            value[i].len--;
            value[i].data++;

            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

            rc.pattern = value[i];
            rc.err.len = NGX_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            for (p = value[i].data; p < value[i].data + value[i].len; p++) {
                if (*p >= 'A' && *p <= 'Z') {
                    rc.options = NGX_REGEX_CASELESS;
                    break;
                }
            }

            sn->regex = ngx_rtmp_regex_compile(cf, &rc);
            if (sn->regex == NULL) {
                return NGX_CONF_ERROR;
            }

            sn->name = value[i];
            cscf->captures = (rc.captures > 0);
        }
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "using regex \"%V\" "
                           "requires PCRE library", &value[i]);

        return NGX_CONF_ERROR;
#endif
    }

    return NGX_CONF_OK;
}
