
/*
 * Copyright (C) Winshining
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_live_module.h"
#include "modules/ngx_rtmp_proxy_module.h"


static ngx_rtmp_publish_pt         next_publish;
static ngx_rtmp_play_pt            next_play;
static ngx_rtmp_delete_stream_pt   next_delete_stream;
static ngx_rtmp_close_stream_pt    next_close_stream;


typedef struct ngx_rtmp_proxy_rewrite_s  ngx_rtmp_proxy_rewrite_t;

typedef ngx_int_t (*ngx_rtmp_proxy_rewrite_pt)(ngx_rtmp_session_t *s,
    ngx_table_elt_t *h, size_t prefix, size_t len,
    ngx_rtmp_proxy_rewrite_t *pr);

struct ngx_rtmp_proxy_rewrite_s {
    ngx_rtmp_proxy_rewrite_pt      handler;

    union {
        ngx_rtmp_complex_value_t   complex;
#if (NGX_PCRE)
        ngx_rtmp_regex_t          *regex;
#endif
    } pattern;

    ngx_rtmp_complex_value_t       replacement;
};


typedef struct {
    ngx_rtmp_proxy_vars_t          vars;
    ngx_event_t                    push_evt;
} ngx_rtmp_proxy_ctx_t;


static ngx_int_t ngx_rtmp_proxy_eval(ngx_rtmp_session_t *s,
    ngx_rtmp_proxy_ctx_t *ctx, ngx_rtmp_proxy_app_conf_t *pacf);
static ngx_int_t ngx_rtmp_proxy_host_variable(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_proxy_port_variable(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_proxy_rewrite_redirect(ngx_rtmp_session_t *s,
    ngx_table_elt_t *h, size_t prefix);
static ngx_int_t ngx_rtmp_proxy_rewrite(ngx_rtmp_session_t *s,
    ngx_table_elt_t *h, size_t prefix, size_t len, ngx_str_t *replacement);
static ngx_int_t ngx_rtmp_proxy_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_proxy_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_proxy_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_proxy_merge_app_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_rtmp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_rtmp_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_rtmp_proxy_rewrite_complex_handler(ngx_rtmp_session_t *s,
    ngx_table_elt_t *h, size_t prefix,
    size_t len, ngx_rtmp_proxy_rewrite_t *pr);
static ngx_int_t ngx_rtmp_proxy_rewrite_regex(ngx_conf_t *cf,
    ngx_rtmp_proxy_rewrite_t *pr, ngx_str_t *regex, ngx_uint_t caseless);
static void ngx_rtmp_proxy_set_vars(ngx_url_t *u, ngx_rtmp_proxy_vars_t *v);

static ngx_int_t ngx_rtmp_proxy_publish(ngx_rtmp_session_t *s,
    ngx_rtmp_publish_t *v);
static ngx_int_t ngx_rtmp_proxy_play(ngx_rtmp_session_t *s,
    ngx_rtmp_play_t *v);
static ngx_int_t ngx_rtmp_proxy_handshake_done(ngx_rtmp_session_t *s,
     ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_proxy_delete_stream(ngx_rtmp_session_t *s,
    ngx_rtmp_delete_stream_t *v);
static ngx_int_t ngx_rtmp_proxy_close_stream(ngx_rtmp_session_t *s,
    ngx_rtmp_close_stream_t *v);
ngx_int_t ngx_rtmp_proxy_on_result(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_proxy_on_error(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_proxy_on_status(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);


static ngx_conf_bitmask_t  ngx_rtmp_proxy_next_upstream_masks[] = {
    { ngx_string("error"), NGX_RTMP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_RTMP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("rtmp_500"), NGX_RTMP_UPSTREAM_FT_RTMP_500 },
    { ngx_string("rtmp_502"), NGX_RTMP_UPSTREAM_FT_RTMP_502 },
    { ngx_string("rtmp_403"), NGX_RTMP_UPSTREAM_FT_RTMP_403 },
    { ngx_string("rtmp_404"), NGX_RTMP_UPSTREAM_FT_RTMP_404 },
    { ngx_string("off"), NGX_RTMP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_rtmp_proxy_commands[] = {

    { ngx_string("proxy_pass"),
        NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_rtmp_proxy_pass,
        NGX_RTMP_APP_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("proxy_redirect"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE12,
        ngx_rtmp_proxy_redirect,
        NGX_RTMP_APP_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("proxy_ignore_client_abort"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.ignore_client_abort),
        NULL },

    { ngx_string("proxy_bind"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE12,
        ngx_rtmp_upstream_bind_set_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.local),
        NULL },

    { ngx_string("proxy_connect_timeout"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.connect_timeout),
        NULL },

    { ngx_string("proxy_send_timeout"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.send_timeout),
        NULL },

    { ngx_string("proxy_read_timeout"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.read_timeout),
        NULL },

    { ngx_string("proxy_limit_rate"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.limit_rate),
        NULL },

    { ngx_string("proxy_next_upstream"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.next_upstream),
        &ngx_rtmp_proxy_next_upstream_masks },

    { ngx_string("proxy_next_upstream_tries"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.next_upstream_tries),
        NULL },

    { ngx_string("proxy_next_upstream_timeout"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.next_upstream_timeout),
        NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_proxy_module_ctx = {
    ngx_rtmp_proxy_add_variables,          /* preconfiguration */
    ngx_rtmp_proxy_postconfiguration,      /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_rtmp_proxy_create_app_conf,        /* create application configuration */
    ngx_rtmp_proxy_merge_app_conf          /* merge application configuration */
};


ngx_module_t  ngx_rtmp_proxy_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_proxy_module_ctx,            /* module context */
    ngx_rtmp_proxy_commands,               /* module directives */
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


static ngx_rtmp_variable_t  ngx_rtmp_proxy_vars[] = {

    { ngx_string("proxy_host"), NULL, ngx_rtmp_proxy_host_variable, 0,
      NGX_RTMP_VAR_CHANGEABLE|NGX_RTMP_VAR_NOCACHEABLE|NGX_RTMP_VAR_NOHASH, 0 },

    { ngx_string("proxy_port"), NULL, ngx_rtmp_proxy_port_variable, 0,
      NGX_RTMP_VAR_CHANGEABLE|NGX_RTMP_VAR_NOCACHEABLE|NGX_RTMP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_rtmp_proxy_host_variable(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_proxy_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.host_header.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.host_header.data;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_proxy_port_variable(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_proxy_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.port.data;

    return NGX_OK;
} 


static ngx_int_t
ngx_rtmp_proxy_rewrite_redirect(ngx_rtmp_session_t *s, ngx_table_elt_t *h,
    size_t prefix)
{
    size_t                      len;
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_rtmp_proxy_rewrite_t   *pr;
    ngx_rtmp_proxy_app_conf_t  *plaf;

    plaf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_proxy_module);

    pr = plaf->redirects->elts;

    if (pr == NULL) {
        return NGX_DECLINED;
    }

    len = h->value.len - prefix;

    for (i = 0; i < plaf->redirects->nelts; i++) {
        rc = pr[i].handler(s, h, prefix, len, &pr[i]);

        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    return NGX_DECLINED;
}

 
static ngx_int_t
ngx_rtmp_proxy_rewrite(ngx_rtmp_session_t *s, ngx_table_elt_t *h, size_t prefix,
    size_t len, ngx_str_t *replacement)
{
    u_char  *p, *data;
    size_t   new_len;

    new_len = replacement->len + h->value.len - len;

    if (replacement->len > len) {
        data = ngx_pnalloc(s->connection->pool, new_len + 1);
        if (data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_copy(data, h->value.data, prefix);
        p = ngx_copy(p, replacement->data, replacement->len);

        ngx_memcpy(p, h->value.data + prefix + len,
                   h->value.len - len - prefix + 1);

        h->value.data = data;
    } else {
        p = ngx_copy(h->value.data + prefix, replacement->data,
                     replacement->len);

        ngx_memmove(p, h->value.data + prefix + len,
                    h->value.len - len - prefix + 1);
    }

    h->value.len = new_len;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_proxy_add_variables(ngx_conf_t *cf)
{
    ngx_rtmp_variable_t  *var, *v;

    for (v = ngx_rtmp_proxy_vars; v->name.len; v++) {
        var = ngx_rtmp_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_proxy_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_HANDSHAKE_DONE]);
    *h = ngx_rtmp_proxy_handshake_done;

    /* chain handlers */

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_proxy_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_proxy_play;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_proxy_delete_stream;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_proxy_close_stream;

    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "_result");
    ch->handler = ngx_rtmp_proxy_on_result;

    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "_error");
    ch->handler = ngx_rtmp_proxy_on_error;

    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "onStatus");
    ch->handler = ngx_rtmp_proxy_on_status;

    return NGX_OK;
}


static void *
ngx_rtmp_proxy_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_proxy_app_conf_t    *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_proxy_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

    conf->upstream.local = NGX_CONF_UNSET_PTR;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;

    conf->redirect = NGX_CONF_UNSET;

    ngx_str_set(&conf->upstream.module, "proxy");

    return conf;
}


static char *
ngx_rtmp_proxy_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_proxy_app_conf_t  *prev = parent;
    ngx_rtmp_proxy_app_conf_t  *conf = child;

    u_char                     *p;
    ngx_rtmp_core_app_conf_t   *claf;
    ngx_rtmp_proxy_rewrite_t   *pr;

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, 0);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_RTMP_UPSTREAM_FT_ERROR
                               |NGX_RTMP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_RTMP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_RTMP_UPSTREAM_FT_OFF;
    }

    ngx_conf_merge_value(conf->redirect, prev->redirect, 1);

    if (conf->redirect) {
        if (conf->redirects == NULL) {
            conf->redirects = prev->redirects;
        }

        if (conf->redirects == NULL && conf->url.data) {
            conf->redirects = ngx_array_create(cf->pool, 1,
                                             sizeof(ngx_rtmp_proxy_rewrite_t));
            if (conf->redirects == NULL) {
                return NGX_CONF_ERROR;
            }

            pr = ngx_array_push(conf->redirects);
            if (pr == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&pr->pattern.complex,
                        sizeof(ngx_rtmp_complex_value_t));

            ngx_memzero(&pr->replacement, sizeof(ngx_rtmp_complex_value_t));

            pr->handler = ngx_rtmp_proxy_rewrite_complex_handler;

            if (conf->vars.uri.len) {
                pr->pattern.complex.value = conf->url;
                pr->replacement.value = conf->application;
            } else {
                pr->pattern.complex.value.len = conf->url.len
                                                + sizeof("/") - 1;

                p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
                if (p == NULL) {
                    return NGX_CONF_ERROR;
                }

                pr->pattern.complex.value.data = p;

                p = ngx_cpymem(p, conf->url.data, conf->url.len);
                *p = '/';

                ngx_str_set(&pr->replacement.value, "/");
            }
        }
    }

    claf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_core_module);

    if (claf->noname
        && conf->upstream.upstream == NULL && conf->proxy_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->application = prev->application;
        conf->vars = prev->vars;

        conf->proxy_lengths = prev->proxy_lengths;
        conf->proxy_values = prev->proxy_values;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_proxy_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_upstream_t         *u;
    ngx_rtmp_proxy_ctx_t        *ctx;
    ngx_rtmp_proxy_app_conf_t   *pacf;

    pacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_proxy_module);

    if (pacf == NULL || pacf->upstream.upstream == NULL) {
        goto next;
    }

    if (ngx_rtmp_upstream_create(s) != NGX_OK) {
        goto next;
    }

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_proxy_ctx_t));
    if (ctx == NULL) {
        goto next;
    }

    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_proxy_module);

    u = s->upstream;

    if (pacf->proxy_lengths == NULL) {
        ctx->vars = pacf->vars;
        u->schema = pacf->vars.schema;
    } else {
        if (ngx_rtmp_proxy_eval(s, ctx, pacf) != NGX_OK) {
            goto next;
        }
    }

    u->conf = &pacf->upstream;

    if (pacf->redirects) {
        u->rewrite_redirect = ngx_rtmp_proxy_rewrite_redirect;
    }

    ctx->push_evt.data = s;
    ctx->push_evt.log = s->connection->log;
    ctx->push_evt.handler = ngx_rtmp_upstream_push_reconnect;

    s->push_evt = ctx->push_evt;

    ngx_rtmp_upstream_push_reconnect(&ctx->push_evt);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_proxy_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    return next_play(s, v);
}


static ngx_int_t ngx_rtmp_proxy_handshake_done(ngx_rtmp_session_t *s,
     ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    return ngx_rtmp_upstream_handshake_done(s, h, in);
}

static ngx_int_t
ngx_rtmp_proxy_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_upstream_close(s);

    return next_delete_stream(s, v);
}


static ngx_int_t
ngx_rtmp_proxy_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_upstream_main_conf_t  *umcf;

    umcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_upstream_module);
    if (umcf && !umcf->session_upstream) {
        ngx_rtmp_upstream_close(s);
    }

    return next_close_stream(s, v);
}


ngx_int_t ngx_rtmp_proxy_on_result(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    return ngx_rtmp_upstream_on_result(s, h, in);
}


ngx_int_t ngx_rtmp_proxy_on_error(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    return ngx_rtmp_upstream_on_error(s, h, in);
}


ngx_int_t ngx_rtmp_proxy_on_status(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    return ngx_rtmp_upstream_on_status(s, h, in);
}


static ngx_int_t
ngx_rtmp_proxy_eval(ngx_rtmp_session_t *s, ngx_rtmp_proxy_ctx_t *ctx,
    ngx_rtmp_proxy_app_conf_t *pacf)
{
    u_char               *p;
    size_t                add;
    u_short               port;
    ngx_str_t             proxy;
    ngx_url_t             url;
    ngx_rtmp_upstream_t  *u;

    if (ngx_rtmp_script_run(s, &proxy, pacf->proxy_lengths->elts, 0,
                            pacf->proxy_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    if (proxy.len > 7
        && ngx_strncasecmp(proxy.data, (u_char *) "rtmp://", 7) == 0)
    {
        add = 7;
        port = 1935;
    } else {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "invalid URL prefix in \"%V\"", &proxy);
        return NGX_ERROR;
    }

    u = s->upstream;

    u->schema.len = add;
    u->schema.data = proxy.data;

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url.len = proxy.len - add;
    url.url.data = proxy.data + add;
    url.default_port = port;
    url.uri_part = 1;
    url.no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    if (url.uri.len) {
        if (url.uri.data[0] == '?') {
            p = ngx_pnalloc(s->connection->pool, url.uri.len + 1);
            if (p == NULL) {
                return NGX_ERROR;
            }

            *p++ = '/';
            ngx_memcpy(p, url.uri.data, url.uri.len);

            url.uri.len++;
            url.uri.data = p - 1;
        }
    }

    ctx->vars.key_start = u->schema;

    ngx_rtmp_proxy_set_vars(&url, &ctx->vars);

    u->resolved = ngx_pcalloc(s->connection->pool,
                                        sizeof(ngx_rtmp_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
    u->resolved->no_port = url.no_port;

    return NGX_OK;
}


static char *
ngx_rtmp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_proxy_app_conf_t  *pacf;

    size_t                      add;
    u_short                     port;
    ngx_str_t                  *value, *url;
    ngx_url_t                   u;
    ngx_uint_t                  n;
    ngx_rtmp_core_app_conf_t   *cacf;
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_rtmp_script_compile_t   sc;

    pacf = conf;

    if (pacf->upstream.upstream || pacf->proxy_lengths) {
        return "is duplicate";
    }

    lacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_live_module);

    cacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_core_module);

    value = cf->args->elts;

    url = &value[1];

    n = ngx_rtmp_script_variables_count(url);

    if (n) {
        ngx_memzero(&sc, sizeof(ngx_rtmp_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &pacf->proxy_lengths;
        sc.values = &pacf->proxy_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_rtmp_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (lacf) {
            lacf->live = 1;
        }

        return NGX_CONF_OK;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "rtmp://", 7) == 0) {
        add = 7;
        port = 1935;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    pacf->upstream.upstream = ngx_rtmp_upstream_add(cf, &u, 0);
    if (pacf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    pacf->vars.schema.len = add;
    pacf->vars.schema.data = url->data;
    pacf->vars.key_start = pacf->vars.schema;

    ngx_rtmp_proxy_set_vars(&u, &pacf->vars);

    pacf->application = cacf->name;

    if (cacf->named
#if (NGX_PCRE)
        || cacf->regex
#endif
    ) {
        if (pacf->vars.uri.len) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_pass\" cannot have URI part in "
                               "application given by regular expression, "
                               "or inside named application");
            return NGX_CONF_ERROR;
        }

        pacf->application.len = 0;
    }

    pacf->url = *url;

    if (lacf) {
        lacf->live = 1;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_proxy_rewrite_complex_handler(ngx_rtmp_session_t *s,
    ngx_table_elt_t *h, size_t prefix,
    size_t len, ngx_rtmp_proxy_rewrite_t *pr)
{
    ngx_str_t  pattern, replacement;

    if (ngx_rtmp_complex_value(s, &pr->pattern.complex, &pattern) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pattern.len > len
        || ngx_rstrncmp(h->value.data + prefix, pattern.data,
                        pattern.len) != 0)
    {
        return NGX_DECLINED;
    }

    if (ngx_rtmp_complex_value(s, &pr->replacement, &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_rtmp_proxy_rewrite(s, h, prefix, pattern.len, &replacement);
}


#if (NGX_PCRE)

static ngx_int_t
ngx_rtmp_proxy_rewrite_regex_handler(ngx_rtmp_session_t *s, ngx_table_elt_t *h,
    size_t prefix, size_t len, ngx_rtmp_proxy_rewrite_t *pr)
{
    ngx_str_t  pattern, replacement;

    pattern.len = len;
    pattern.data = h->value.data + prefix;

    if (ngx_rtmp_regex_exec(s, pr->pattern.regex, &pattern) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (ngx_rtmp_complex_value(s, &pr->replacement, &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    if (prefix == 0 && h->value.len == len) {
        h->value = replacement;
        return NGX_OK;
    }

    return ngx_rtmp_proxy_rewrite(s, h, prefix, len, &replacement);
}

#endif


static char *
ngx_rtmp_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_proxy_app_conf_t *plaf = conf;

    u_char                            *p;
    ngx_str_t                         *value;
    ngx_rtmp_proxy_rewrite_t          *pr;
    ngx_rtmp_compile_complex_value_t   ccv;

    if (plaf->redirect == 0) {
        return NGX_CONF_OK;
    }

    plaf->redirect = 1;

    value = cf->args->elts;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[1].data, "off") == 0) {
            plaf->redirect = 0;
            plaf->redirects = NULL;
            return NGX_CONF_OK;
        }

        if (ngx_strcmp(value[1].data, "false") == 0) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "invalid parameter \"false\", use \"off\" instead");
            plaf->redirect = 0;
            plaf->redirects = NULL;
            return NGX_CONF_OK;
        }

        if (ngx_strcmp(value[1].data, "default") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    if (plaf->redirects == NULL) {
        plaf->redirects = ngx_array_create(cf->pool, 1,
                                           sizeof(ngx_rtmp_proxy_rewrite_t));
        if (plaf->redirects == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pr = ngx_array_push(plaf->redirects);
    if (pr == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(value[1].data, "default") == 0) {
        if (plaf->proxy_lengths) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_redirect default\" cannot be used "
                               "with \"proxy_pass\" directive with variables");
            return NGX_CONF_ERROR;
        }

        if (plaf->url.data == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_redirect default\" should be placed "
                               "after the \"proxy_pass\" directive");
            return NGX_CONF_ERROR;
        }

        pr->handler = ngx_rtmp_proxy_rewrite_complex_handler;

        ngx_memzero(&pr->pattern.complex, sizeof(ngx_rtmp_complex_value_t));
        ngx_memzero(&pr->replacement, sizeof(ngx_rtmp_complex_value_t));

        if (plaf->vars.uri.len) {
            pr->pattern.complex.value = plaf->url;
            pr->replacement.value = plaf->application;
        } else {
            pr->pattern.complex.value.len = plaf->url.len + sizeof("/") - 1;

            p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
            if (p == NULL) {
                return NGX_CONF_ERROR;
            }

            pr->pattern.complex.value.data = p;

            p = ngx_cpymem(p, plaf->url.data, plaf->url.len);
            *p = '/';

            ngx_str_set(&pr->replacement.value, "/");
        }

        return NGX_CONF_OK;
    }

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (value[1].data[0] == '*') {
            value[1].len--;
            value[1].data++;

            if (ngx_rtmp_proxy_rewrite_regex(cf, pr, &value[1], 1) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        } else {
            if (ngx_rtmp_proxy_rewrite_regex(cf, pr, &value[1], 0) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    } else {
        ngx_memzero(&ccv, sizeof(ngx_rtmp_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (ngx_rtmp_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        pr->handler = ngx_rtmp_proxy_rewrite_complex_handler;
    }

    ngx_memzero(&ccv, sizeof(ngx_rtmp_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (ngx_rtmp_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_proxy_rewrite_regex(ngx_conf_t *cf, ngx_rtmp_proxy_rewrite_t *pr,
    ngx_str_t *regex, ngx_uint_t caseless)
{
#if (NGX_PCRE)
    u_char               errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t  rc;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (caseless) {
        rc.options = NGX_REGEX_CASELESS;
    }

    pr->pattern.regex = ngx_rtmp_regex_compile(cf, &rc);
    if (pr->pattern.regex == NULL) {
        return NGX_ERROR;
    }

    pr->handler = ngx_rtmp_proxy_rewrite_regex_handler;

    return NGX_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library", regex);
    return NGX_ERROR;

#endif
}


static void
ngx_rtmp_proxy_set_vars(ngx_url_t *u, ngx_rtmp_proxy_vars_t *v)
{
    if (u->family != AF_UNIX) {
        if (u->no_port || u->port == u->default_port) {
            v->host_header = u->host;

            if (u->default_port == 1935) {
                ngx_str_set(&v->port, "1935");
            }
        } else {
            v->host_header.len = u->host.len + 1 + u->port_text.len;
            v->host_header.data = u->host.data;
            v->port = u->port_text;
        }

        v->key_start.len += v->host_header.len;
    } else {
        ngx_str_set(&v->host_header, "localhost");
        ngx_str_null(&v->port);
        v->key_start.len += sizeof("unix:") - 1 + u->host.len + 1;
    }

    v->uri = u->uri;
}

