
/*
 * Copyright (C) Winshining
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


#define NGX_RTMP_CACHE            0
#define NGX_RTMP_SSL              0
#define NGX_RTMP_PROXY_TEMP_PATH  "rtmp_proxy_temp"


typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_rtmp_proxy_vars_t;


typedef struct {
    ngx_rtmp_upstream_conf_t       upstream;

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;

    ngx_str_t                      location;
    ngx_str_t                      url;

#if (NGX_RTMP_CACHE)
    ngx_rtmp_complex_value_t       cache_key;
#endif

    ngx_rtmp_proxy_vars_t          vars;

#if (NGX_RTMP_SSL)
    ngx_uint_t                     ssl;
    ngx_uint_t                     ssl_protocols;
    ngx_str_t                      ssl_ciphers;
    ngx_uint_t                     ssl_verify_depth;
    ngx_str_t                      ssl_trusted_certificate;
    ngx_str_t                      ssl_crl;
    ngx_str_t                      ssl_certificate;
    ngx_str_t                      ssl_certificate_key;
    ngx_array_t                   *ssl_passwords;
#endif
} ngx_rtmp_proxy_app_conf_t;


typedef struct {
    ngx_rtmp_proxy_vars_t          vars;
    off_t                          internal_body_length;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;
} ngx_rtmp_proxy_ctx_t;


static ngx_int_t ngx_rtmp_proxy_eval(ngx_rtmp_session_t *s,
    ngx_rtmp_proxy_ctx_t *ctx, ngx_rtmp_proxy_app_conf_t *pacf);
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

static void ngx_rtmp_proxy_set_vars(ngx_url_t *u, ngx_rtmp_proxy_vars_t *v);

static ngx_path_init_t  ngx_rtmp_proxy_temp_path = {
    ngx_string(NGX_RTMP_PROXY_TEMP_PATH), { 1, 2, 0 }
};


static ngx_command_t  ngx_rtmp_proxy_commands[] = {

    { ngx_string("proxy_pass"),
        NGX_RTMP_APP_CONF||NGX_RTMP_LMT_CONF|NGX_CONF_TAKE1,
        ngx_rtmp_proxy_pass,
        NGX_RTMP_APP_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("proxy_redirect"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE12,
        ngx_http_proxy_redirect,
        NGX_RTMP_APP_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("proxy_store"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_http_proxy_store,
        NGX_RTMP_APP_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("proxy_store_access"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE123,
        ngx_conf_set_access_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.store_access),
        NULL },

    { ngx_string("proxy_buffering"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.buffering),
        NULL },

    { ngx_string("proxy_request_buffering"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.request_buffering),
        NULL },

    { ngx_string("proxy_ignore_client_abort"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.ignore_client_abort),
        NULL },

    { ngx_string("proxy_bind"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE12,
        ngx_http_upstream_bind_set_slot,
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

    { ngx_string("proxy_send_lowat"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.send_lowat),
        &ngx_http_proxy_lowat_post },

    { ngx_string("proxy_intercept_errors"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.intercept_errors),
        NULL },
/*
    { ngx_string("proxy_set_header"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_keyval_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, headers_source),
        NULL },

    { ngx_string("proxy_headers_hash_max_size"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, headers_hash_max_size),
        NULL },

    { ngx_string("proxy_headers_hash_bucket_size"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, headers_hash_bucket_size),
        NULL },

    { ngx_string("proxy_pass_request_headers"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.pass_request_headers),
        NULL },

    { ngx_string("proxy_pass_request_body"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.pass_request_body),
        NULL },
*/
    { ngx_string("proxy_buffer_size"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.buffer_size),
        NULL },

    { ngx_string("proxy_read_timeout"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.read_timeout),
        NULL },

    { ngx_string("proxy_buffers"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_bufs_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.bufs),
        NULL },

    { ngx_string("proxy_busy_buffers_size"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.busy_buffers_size_conf),
        NULL },

    { ngx_string("proxy_limit_rate"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.limit_rate),
        NULL },

#if (NGX_RTMP_CACHE)

    { ngx_string("proxy_cache"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_http_proxy_cache,
        NGX_RTMP_APP_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("proxy_cache_key"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_http_proxy_cache_key,
        NGX_RTMP_APP_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("proxy_cache_path"),
        NGX_RTMP_MAIN_CONF|NGX_CONF_2MORE,
        ngx_http_file_cache_set_slot,
        NGX_RTMP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_proxy_main_conf_t, caches),
        &ngx_http_proxy_module },

    { ngx_string("proxy_cache_bypass"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
        ngx_http_set_predicate_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_bypass),
        NULL },

    { ngx_string("proxy_no_cache"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
        ngx_http_set_predicate_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.no_cache),
        NULL },

    { ngx_string("proxy_cache_valid"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
        ngx_http_file_cache_valid_set_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_valid),
        NULL },

    { ngx_string("proxy_cache_min_uses"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_min_uses),
        NULL },

    { ngx_string("proxy_cache_max_range_offset"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_off_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_max_range_offset),
        NULL },

    { ngx_string("proxy_cache_use_stale"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_use_stale),
        &ngx_http_proxy_next_upstream_masks },

    { ngx_string("proxy_cache_lock"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_lock),
        NULL },

    { ngx_string("proxy_cache_lock_timeout"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_lock_timeout),
        NULL },

    { ngx_string("proxy_cache_lock_age"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_lock_age),
        NULL },

    { ngx_string("proxy_cache_revalidate"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_revalidate),
        NULL },

    { ngx_string("proxy_cache_background_update"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.cache_background_update),
        NULL },

#endif

    { ngx_string("proxy_temp_path"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1234,
        ngx_conf_set_path_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.temp_path),
        NULL },

    { ngx_string("proxy_max_temp_file_size"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.max_temp_file_size_conf),
        NULL },

    { ngx_string("proxy_temp_file_write_size"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.temp_file_write_size_conf),
        NULL },

    { ngx_string("proxy_next_upstream"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.next_upstream),
        &ngx_http_proxy_next_upstream_masks },

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
/*
    { ngx_string("proxy_pass_header"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.pass_headers),
        NULL },

    { ngx_string("proxy_hide_header"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.hide_headers),
        NULL },

    { ngx_string("proxy_ignore_headers"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.ignore_headers),
        &ngx_http_upstream_ignore_headers_masks },
*/
#if (NGX_RTMP_SSL)

    { ngx_string("proxy_ssl_session_reuse"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.ssl_session_reuse),
        NULL },

    { ngx_string("proxy_ssl_protocols"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, ssl_protocols),
        &ngx_http_proxy_ssl_protocols },

    { ngx_string("proxy_ssl_ciphers"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, ssl_ciphers),
        NULL },

    { ngx_string("proxy_ssl_name"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.ssl_name),
        NULL },

    { ngx_string("proxy_ssl_server_name"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.ssl_server_name),
        NULL },

    { ngx_string("proxy_ssl_verify"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, upstream.ssl_verify),
        NULL },

    { ngx_string("proxy_ssl_verify_depth"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, ssl_verify_depth),
        NULL },

    { ngx_string("proxy_ssl_trusted_certificate"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, ssl_trusted_certificate),
        NULL },

    { ngx_string("proxy_ssl_crl"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, ssl_crl),
        NULL },

    { ngx_string("proxy_ssl_certificate"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, ssl_certificate),
        NULL },

    { ngx_string("proxy_ssl_certificate_key"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_proxy_app_conf_t, ssl_certificate_key),
        NULL },

    { ngx_string("proxy_ssl_password_file"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_http_proxy_ssl_password_file,
        NGX_RTMP_APP_CONF_OFFSET,
        0,
        NULL },

#endif

    ngx_null_command
};


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

#if (NGX_RTMP_CACHE)
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
ngx_rtmp_proxy_handler(ngx_rtmp_session_t *s)
{
    ngx_int_t                    rc;
    ngx_rtmp_upstream_t         *u;
    ngx_rtmp_proxy_ctx_t        *ctx;
    ngx_rtmp_proxy_app_conf_t   *pacf;
#if (NGX_RTMP_CACHE)
    ngx_rtmp_proxy_main_conf_t  *pmcf;
#endif

    if (ngx_rtmp_upstream_create(s) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_proxy_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_proxy_module);

    pacf = ngx_rtmp_get_module_loc_conf(s, ngx_rtmp_proxy_module);

    u = s->upstream;

    if (pacf->proxy_lengths == NULL) {
        ctx->vars = pacf->vars;
        u->schema = pacf->vars.schema;
#if (NGX_RTMP_SSL)
        u->ssl = (pacf->upstream.ssl != NULL);
#endif

    } else {
        if (ngx_rtmp_proxy_eval(s, ctx, pacf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    u->output.tag = (ngx_buf_tag_t) &ngx_rtmp_proxy_module;

    u->conf = &pacf->upstream;

#if (NGX_RTMP_CACHE)
    pmcf = ngx_http_get_module_main_conf(s, ngx_rtmp_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = ngx_rtmp_proxy_create_key;
#endif

    u->create_request = ngx_rtmp_proxy_create_request;
    u->reinit_request = ngx_rtmp_proxy_reinit_request;
    u->abort_request = ngx_rtmp_proxy_abort_request;
    u->finalize_request = ngx_rtmp_proxy_finalize_request;
    r->state = 0;

    if (pacf->redirects) {
        u->rewrite_redirect = ngx_rtmp_proxy_rewrite_redirect;
    }

    u->buffering = pacf->upstream.buffering;

    u->pipe = ngx_pcalloc(s->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_ERROR;
    }

    u->pipe->input_filter = ngx_rtmp_proxy_copy_filter;
    u->pipe->input_ctx = s;

    u->input_filter_init = ngx_rtmp_proxy_input_filter_init;
    u->input_filter = ngx_rtmp_proxy_non_buffered_copy_filter;
    u->input_filter_ctx = s;

    if (!pacf->upstream.request_buffering
        && pacf->body_values == NULL && pacf->upstream.pass_request_body)
    {
        r->request_body_no_buffering = 1;
    }
/*
    refers to ngx_rtmp_core_listen 
 
    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_RTMP_SPECIAL_RESPONSE) {
        return rc;
    }
*/
    return NGX_DONE;
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
    ngx_http_upstream_t  *u;

    if (ngx_http_script_run(s, &proxy, pacf->proxy_lengths->elts, 0,
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

#if (NGX_RTMP_SSL)

    } else if (proxy.len > 8
               && ngx_strncasecmp(proxy.data, (u_char *) "rtmps://", 8) == 0)
    {
        add = 8;
        port = 443;
        s->upstream->ssl = 1;

#endif

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

    if (ngx_parse_url(s->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    if (url.uri.len) {
        if (url.uri.data[0] == '?') {
            p = ngx_pnalloc(s->pool, url.uri.len + 1);
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

    ngx_http_proxy_set_vars(&url, &ctx->vars);

    u->resolved = ngx_pcalloc(s->pool, sizeof(ngx_rtmp_upstream_resolved_t));
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


static ngx_int_t
ngx_rtmp_proxy_reinit_request(ngx_rtmp_session_t *s)
{
    s->upstream->pipe->input_filter = ngx_rtmp_proxy_copy_filter;
    s->upstream->input_filter = ngx_rtmp_proxy_non_buffered_copy_filter;
    s->state = 0;

    return NGX_OK;
}


static char *
ngx_rtmp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_proxy_app_conf_t   *pacf;
    ngx_rtmp_core_app_conf_t    *cacf;

    pacf = conf;
    if (pacf->upstream.upstream || pacf->proxy_lengths) {
        return "is duplicate";
    }

    cacf->handler = ngx_rtmp_proxy_handler;

    return NGX_CONF_OK;
}


static void
ngx_rtmp_proxy_set_vars(ngx_url_t *u, ngx_rtmp_proxy_vars_t *v)
{
    if (u->family != AF_UNIX) {

        if (u->no_port || u->port == u->default_port) {

            v->host_header = u->host;

            if (u->default_port == 80) {
                ngx_str_set(&v->port, "80");

            } else {
                ngx_str_set(&v->port, "443");
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

