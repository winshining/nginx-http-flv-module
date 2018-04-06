
/*
 * Copyright (C) Winshining
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_flv_live_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_notify_module.h"
#include "ngx_rtmp_bandwidth.h"


static ngx_rtmp_play_pt         next_play;
static ngx_rtmp_close_stream_pt next_close_stream;


static ngx_int_t ngx_http_flv_live_init(ngx_conf_t *cf);
static void *ngx_http_flv_live_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_flv_live_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);


static ngx_int_t ngx_http_flv_live_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_flv_live_init_process(ngx_cycle_t *cycle);

static void ngx_http_flv_live_send_tail(ngx_rtmp_session_t *s);
static ngx_int_t ngx_http_flv_live_send_message(ngx_rtmp_session_t *s,
        ngx_chain_t *out, unsigned int priority);
static ngx_chain_t *ngx_http_flv_live_meta_message(ngx_rtmp_session_t *,
        ngx_chain_t *in);
static ngx_chain_t *ngx_http_flv_live_append_message(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in);
static void ngx_http_flv_live_free_message(ngx_rtmp_session_t *s,
        ngx_chain_t *in);
static void ngx_http_flv_live_close_http_request(ngx_rtmp_session_t *s);
static ngx_int_t ngx_http_flv_live_headers_filter(ngx_rtmp_session_t *s);
static ngx_int_t ngx_http_flv_live_header_filter(ngx_rtmp_session_t *s);


typedef struct ngx_http_header_val_s  ngx_http_header_val_t;

typedef ngx_int_t (*ngx_http_set_header_pt)(ngx_http_request_t *r,
    ngx_http_header_val_t *hv, ngx_str_t *value);


typedef struct {
    ngx_str_t                  name;
    ngx_uint_t                 offset;
    ngx_http_set_header_pt     handler;
} ngx_http_set_header_t;


struct ngx_http_header_val_s {
    ngx_http_complex_value_t   value;
    ngx_str_t                  key;
    ngx_http_set_header_pt     handler;
    ngx_uint_t                 offset;
    ngx_uint_t                 always;  /* unsigned  always:1 */
};


typedef enum {
    NGX_HTTP_EXPIRES_OFF,
} ngx_http_expires_t;


typedef struct {
    ngx_http_expires_t         expires;
    time_t                     expires_time;
    ngx_http_complex_value_t  *expires_value;
    ngx_array_t               *headers;
} ngx_http_headers_conf_t;


extern ngx_module_t    ngx_http_headers_filter_module;


static u_char ngx_http_server_string[] = "Server: nginx" CRLF;
static u_char ngx_http_server_full_string[] = "Server: " NGINX_VER CRLF;
#if (nginx_version >= 1011010)
static u_char ngx_http_server_build_string[] = "Server: " NGINX_VER_BUILD CRLF;
#endif


static ngx_str_t ngx_http_status_lines[] = {

    ngx_string("200 OK"),
    ngx_null_string,  /* "201 Created" */
    ngx_null_string,  /* "202 Accepted" */
    ngx_null_string,  /* "203 Non-Authoritative Information" */
    ngx_null_string,  /* "204 No Content" */
    ngx_null_string,  /* "205 Reset Content" */
    ngx_null_string,  /* "206 Partial Content" */

    /* ngx_null_string, */  /* "207 Multi-Status" */

#define NGX_HTTP_LAST_2XX  207
#define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 200)

    /* ngx_null_string, */  /* "300 Multiple Choices" */

    ngx_string("301 Moved Permanently"),
    ngx_string("302 Moved Temporarily"),
    ngx_null_string,  /* "303 See Other" */
    ngx_null_string,  /* "304 Not Modified" */
    ngx_null_string,  /* "305 Use Proxy" */
    ngx_null_string,  /* "306 unused" */
    ngx_string("307 Temporary Redirect"),

#define NGX_HTTP_LAST_3XX  308
#define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)

    ngx_string("400 Bad Request"),
    ngx_null_string,  /* "401 Unauthorized" */
    ngx_null_string,  /* "402 Payment Required" */
    ngx_string("403 Forbidden"),
    ngx_string("404 Not Found"),
    ngx_string("405 Not Allowed"),
    ngx_null_string,  /* "406 Not Acceptable" */
    ngx_null_string,  /* "407 Proxy Authentication Required" */
    ngx_null_string,  /* "408 Request Time-out" */
    ngx_null_string,  /* "409 Conflict" */
    ngx_null_string,  /* "410 Gone" */
    ngx_null_string,  /* "411 Length Required" */
    ngx_null_string,  /* "412 Precondition Failed" */
    ngx_null_string,  /* "413 Request Entity Too Large" */
    ngx_null_string,  /* "414 Request-URI Too Large" */
    ngx_null_string,  /* "415 Unsupported Media Type" */
    ngx_null_string,  /* "416 Requested Range Not Satisfiable" */
    ngx_null_string,  /* "417 Expectation Failed" */
    ngx_null_string,  /* "418 unused" */
    ngx_null_string,  /* "419 unused" */
    ngx_null_string,  /* "420 unused" */
    ngx_null_string,  /* "421 Misdirected Request" */

    /* ngx_null_string, */  /* "422 Unprocessable Entity" */
    /* ngx_null_string, */  /* "423 Locked" */
    /* ngx_null_string, */  /* "424 Failed Dependency" */

#define NGX_HTTP_LAST_4XX  422
#define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)

    ngx_string("500 Internal Server Error"),
    ngx_null_string,  /* "501 Not Implemented" */
    ngx_null_string,  /* "502 Bad Gateway" */
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_null_string,  /* "504 Gateway Time-out" */
    ngx_null_string,        /* "505 HTTP Version Not Supported" */
    ngx_null_string,        /* "506 Variant Also Negotiates" */
    ngx_null_string,  /* "507 Insufficient Storage" */

    /* ngx_null_string, */  /* "508 unused" */
    /* ngx_null_string, */  /* "509 unused" */
    /* ngx_null_string, */  /* "510 Not Extended" */

#define NGX_HTTP_LAST_5XX  508

};


extern ngx_rtmp_live_process_handler_t  ngx_rtmp_live_process_handler;
static ngx_rtmp_live_process_handler_t  ngx_http_flv_live_process_handler = {
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_flv_live_send_message,
    ngx_http_flv_live_meta_message,
    ngx_http_flv_live_append_message,
    ngx_http_flv_live_free_message
};

ngx_rtmp_live_process_handler_t  *ngx_rtmp_live_process_handlers[] = {
    &ngx_rtmp_live_process_handler,
    &ngx_http_flv_live_process_handler
};


static ngx_int_t ngx_http_flv_live_init_handlers(ngx_cycle_t *cycle);


static ngx_int_t ngx_http_flv_live_request(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);

static ngx_int_t ngx_http_flv_live_play(ngx_rtmp_session_t *s,
        ngx_rtmp_play_t *v);
static ngx_int_t ngx_http_flv_live_close_stream(ngx_rtmp_session_t *s,
        ngx_rtmp_close_stream_t *v);


static void ngx_http_flv_live_play_handler(ngx_event_t *ev);
static void ngx_http_flv_live_read_handler(ngx_event_t *rev);
static void ngx_http_flv_live_write_handler(ngx_event_t *wev);

static ngx_int_t ngx_http_flv_live_preprocess(ngx_http_request_t *r,
        ngx_rtmp_connection_t *rconn);

static ngx_rtmp_session_t *ngx_http_flv_live_init_connection(
        ngx_http_request_t *r, ngx_rtmp_connection_t *rconn);
static ngx_rtmp_session_t *ngx_http_flv_live_init_session(
        ngx_http_request_t *r, ngx_rtmp_addr_conf_t *add_conf);
static ngx_int_t ngx_http_flv_live_connect_init(ngx_rtmp_session_t *s,
        ngx_str_t *app, ngx_str_t *stream);


static ngx_http_module_t ngx_http_flv_live_module_ctx = {
    NULL,
    ngx_http_flv_live_init,            /* postconfiguration */
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_flv_live_create_loc_conf, /* create location configuration */
    ngx_http_flv_live_merge_loc_conf   /* merge location configuration */
};


static ngx_command_t ngx_http_flv_live_commands[] = {
    { ngx_string("flv_live"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_live_conf_t, flv_live),
      NULL },

    ngx_null_command
};


ngx_module_t ngx_http_flv_live_module = {
    NGX_MODULE_V1,
    &ngx_http_flv_live_module_ctx,
    ngx_http_flv_live_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_flv_live_init_process,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_flv_live_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* insert in the NGX_HTTP_CONTENT_PHASE */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_flv_live_handler;

    return NGX_OK;
}


void *
ngx_http_flv_live_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_flv_live_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flv_live_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->flv_live = NGX_CONF_UNSET;

    return (void *)conf;
}


char *
ngx_http_flv_live_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_flv_live_conf_t *prev = parent;
    ngx_http_flv_live_conf_t *conf = child;

    ngx_conf_merge_value(conf->flv_live, prev->flv_live, 0);

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_flv_live_init_handlers(ngx_cycle_t *cycle)
{
    ngx_rtmp_core_main_conf_t *cmcf;
    ngx_rtmp_handler_pt       *h;

    cmcf = ngx_rtmp_cycle_get_module_main_conf(cycle, ngx_rtmp_core_module);
    if (cmcf == NULL) {
        return NGX_OK;
    }

    /* rtmp live conf aready exsits, so add additional event handlers */
    h = ngx_array_push(&cmcf->events[NGX_HTTP_FLV_LIVE_REQUEST]);
    *h = ngx_http_flv_live_request;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_http_flv_live_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_http_flv_live_close_stream;

    return NGX_OK;
}


ngx_int_t
ngx_http_flv_live_init_process(ngx_cycle_t *cycle)
{
    return ngx_http_flv_live_init_handlers(cycle);
}


/*
 * chunk format:
 * hex1\r\n
 * content1(hex1)\r\n
 * hex2\r\n
 * content2(hex2)\r\n
 * ...
 * 0\r\n\r\n
 */
ngx_int_t
ngx_http_flv_live_send_header(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t        *cscf;
    ngx_http_core_loc_conf_t        *clcf;
    ngx_http_request_t              *r;
    ngx_rtmp_live_ctx_t             *live_ctx;
    ngx_rtmp_codec_ctx_t            *codec_ctx;
    ngx_list_part_t                 *part;
    ngx_table_elt_t                 *e, *header;
    u_char                          *p;
    ngx_chain_t                      cl_flv_hdr, *pkt;
    ngx_buf_t                        buf_flv_hdr;
    ngx_uint_t                       i;
    ngx_str_t                        chunked_flv_header;
    ngx_str_t                        consec_flv_header;
    u_char                           chunked_flv_header_data[18];
    ngx_flag_t                       connection_header;

    /**
     * |F|L|V|ver|00000101|header_size|0|0|0|0|, ngx_http_flv_module.c
     * for more details, please refer to http://www.adobe.com/devnet/f4v.html
     **/
    u_char flv_header[] = "FLV\x1\0\0\0\0\x9\0\0\0\0";

    r = s->data;

    r->headers_out.status = NGX_HTTP_OK;

    ngx_str_set(&r->headers_out.content_type, "video/x-flv");

    /* fill HTTP header 'Connection' according to headers_in */
    r->keepalive = 0;

    connection_header = 0;
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (ngx_strcasecmp(header[i].key.data, (u_char *) "connection") == 0) {
            connection_header = 1;
            if (ngx_strcasecmp(header[i].value.data, (u_char *) "keep-alive")
                == 0)
            {
                r->keepalive = 1;
            }

            break;
        }
    }

    if (!connection_header && r->http_version == NGX_HTTP_VERSION_11) {
        r->keepalive = 1;
    }

    live_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (live_ctx && !live_ctx->active) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "flv live: try to send header when session not active");

        return NGX_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    codec_ctx = ngx_rtmp_get_module_ctx(s->publisher, ngx_rtmp_codec_module);
    if (codec_ctx->video_codec_id != 0) {
        flv_header[4] |= 0x1;
    }

    if (codec_ctx->audio_codec_id != 0
        && codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_UNCOMPRESSED)
    {
        flv_header[4] |= (0x1 << 2);
    }

    if (clcf->chunked_transfer_encoding) {
        r->chunked = 1;

        p = chunked_flv_header_data;
        *p++ = 'd';
        *p++ = CR;
        *p++ = LF;
        ngx_memmove(p, flv_header, 13);
        p += 13;
        *p++ = CR;
        *p++ = LF;
        chunked_flv_header.data = chunked_flv_header_data;
        chunked_flv_header.len = 18;

        buf_flv_hdr.pos = chunked_flv_header.data;
        buf_flv_hdr.last = chunked_flv_header.data + chunked_flv_header.len;
    } else {
        consec_flv_header.data = flv_header;
        consec_flv_header.len = 13;

        buf_flv_hdr.pos = consec_flv_header.data;
        buf_flv_hdr.last = consec_flv_header.data + consec_flv_header.len;
    }

    e = r->headers_out.expires;
    if (e == NULL) {

        e = ngx_list_push(&r->headers_out.headers);
        if (e == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.expires = e;

        e->hash = 1;
        ngx_str_set(&e->key, "Expires");
    }

    e->value.data = (u_char *) "-1";
    e->value.len = ngx_strlen("-1");

    if (ngx_http_flv_live_headers_filter(s) == NGX_ERROR) {
        return NGX_ERROR;
    }

    buf_flv_hdr.start = buf_flv_hdr.pos;
    buf_flv_hdr.end = buf_flv_hdr.last;

    cl_flv_hdr.buf = &buf_flv_hdr;
    cl_flv_hdr.next = NULL;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &cl_flv_hdr);
    if (pkt == NULL) {
        return NGX_ERROR;
    }

    ngx_http_flv_live_send_message(s, pkt, 0);
    ngx_rtmp_free_shared_chain(cscf, pkt);

    return NGX_OK;
}


/**
 * for adding non-standard HTTP headers 
 **/
ngx_int_t
ngx_http_flv_live_headers_filter(ngx_rtmp_session_t *s)
{
    ngx_str_t                 value;
    ngx_uint_t                i, safe_status;
    ngx_http_header_val_t    *h;
    ngx_http_headers_conf_t  *conf;
    ngx_http_request_t       *r;

    r = s->data;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_headers_filter_module);

    /* force */
    conf->expires = NGX_HTTP_EXPIRES_OFF;

    if (conf->headers == NULL) {
        return ngx_http_flv_live_header_filter(s);
    }

    switch (r->headers_out.status) {

    case NGX_HTTP_OK:
    case NGX_HTTP_CREATED:
    case NGX_HTTP_NO_CONTENT:
    case NGX_HTTP_PARTIAL_CONTENT:
    case NGX_HTTP_MOVED_PERMANENTLY:
    case NGX_HTTP_MOVED_TEMPORARILY:
    case NGX_HTTP_SEE_OTHER:
    case NGX_HTTP_NOT_MODIFIED:
    case NGX_HTTP_TEMPORARY_REDIRECT:
        safe_status = 1;
        break;

    default:
        safe_status = 0;
    }

    if (conf->headers) {
        h = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {

            if (!safe_status && !h[i].always) {
                continue;
            }

            if (ngx_http_complex_value(r, &h[i].value, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            if (h[i].handler(r, &h[i], &value) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return ngx_http_flv_live_header_filter(s);
}


ngx_int_t
ngx_http_flv_live_header_filter(ngx_rtmp_session_t *s)
{
    u_char                    *p;
    size_t                     len;
    ngx_str_t                  *status_line;
    ngx_buf_t                 *b;
    ngx_uint_t                 status, i;
    ngx_chain_t                out, *pkt;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_http_request_t        *r;

    r = s->data;

    if (r->header_sent) {
        return NGX_OK;
    }

    r->header_sent = 1;

    if (r->chunked && r->http_version < NGX_HTTP_VERSION_11) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "flv live: chunked only supported by HTTP/1.1");

        r->chunked = 0;
    }

    len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
          /* the end of the header */
          + sizeof(CRLF) - 1;

    /* status line */

    if (r->headers_out.status_line.len) {
        len += r->headers_out.status_line.len;
        status_line = &r->headers_out.status_line;
#if (NGX_SUPPRESS_WARN)
        status = 0;
#endif

    } else {

        status = r->headers_out.status;

        if (status >= NGX_HTTP_OK
            && status < NGX_HTTP_LAST_2XX)
        {
            /* 2XX */

            status -= NGX_HTTP_OK;
            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_MOVED_PERMANENTLY
                   && status < NGX_HTTP_LAST_3XX)
        {
            /* 3XX */

            status = status - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;
            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_BAD_REQUEST
                   && status < NGX_HTTP_LAST_4XX)
        {
            /* 4XX */
            status = status - NGX_HTTP_BAD_REQUEST
                            + NGX_HTTP_OFF_4XX;

            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_INTERNAL_SERVER_ERROR
                   && status < NGX_HTTP_LAST_5XX)
        {
            /* 5XX */
            status = status - NGX_HTTP_INTERNAL_SERVER_ERROR
                            + NGX_HTTP_OFF_5XX;

            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else {
            len += NGX_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }

        if (status_line && status_line->len == 0) {
            status = r->headers_out.status;
            len += NGX_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_out.server == NULL) {
#if (nginx_version >= 1011010)
        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            len += sizeof(ngx_http_server_full_string) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            len += sizeof(ngx_http_server_build_string) - 1;

        } else {
            len += sizeof(ngx_http_server_string) - 1;
        }
#else
        len += clcf->server_tokens ? sizeof(ngx_http_server_full_string) - 1 :
                                     sizeof(ngx_http_server_string) - 1;
#endif
    }

    if (r->headers_out.date == NULL) {
        len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    if (r->headers_out.content_type.len) {
        len += sizeof("Content-Type: ") - 1
               + r->headers_out.content_type.len + 2;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + 2;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    if (r->chunked) {
        len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
    }

    if (r->keepalive) {
        len += sizeof("Connection: keep-alive" CRLF) - 1;

        /*
         * MSIE and Opera ignore the "Keep-Alive: timeout=<N>" header.
         * MSIE keeps the connection alive for about 60-65 seconds.
         * Opera keeps the connection alive very long.
         * Mozilla keeps the connection alive for N plus about 1-10 seconds.
         * Konqueror keeps the connection alive for about N seconds.
         */

        if (clcf->keepalive_header) {
            len += sizeof("Keep-Alive: timeout=") - 1 + NGX_TIME_T_LEN + 2;
        }

    } else {
        len += sizeof("Connection: close" CRLF) - 1;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len
               + sizeof(CRLF) - 1;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    /* "HTTP/1.x " */
    b->last = ngx_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */
    if (status_line) {
        b->last = ngx_copy(b->last, status_line->data, status_line->len);

    } else {
        b->last = ngx_sprintf(b->last, "%03ui ", status);
    }
    *b->last++ = CR; *b->last++ = LF;

    if (r->headers_out.server == NULL) {
#if (nginx_version >= 1011010)
        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            p = ngx_http_server_full_string;
            len = sizeof(ngx_http_server_full_string) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            p = ngx_http_server_build_string;
            len = sizeof(ngx_http_server_build_string) - 1;

        } else {
#else
        if (clcf->server_tokens) {
            p = (u_char *) ngx_http_server_full_string;
            len = sizeof(ngx_http_server_full_string) - 1;

        } else {
#endif
            p = ngx_http_server_string;
            len = sizeof(ngx_http_server_string) - 1;
        }

        b->last = ngx_cpymem(b->last, p, len);
    }

    if (r->headers_out.date == NULL) {
        b->last = ngx_cpymem(b->last, "Date: ", sizeof("Date: ") - 1);
        b->last = ngx_cpymem(b->last, ngx_cached_http_time.data,
                             ngx_cached_http_time.len);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_type.len) {
        b->last = ngx_cpymem(b->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        p = b->last;
        b->last = ngx_copy(b->last, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = ngx_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = ngx_copy(b->last, r->headers_out.charset.data,
                               r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = b->last - p;
            r->headers_out.content_type.data = p;
        }

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->chunked) {
        b->last = ngx_cpymem(b->last, "Transfer-Encoding: chunked" CRLF,
                             sizeof("Transfer-Encoding: chunked" CRLF) - 1);
    }

    if (r->keepalive) {
        b->last = ngx_cpymem(b->last, "Connection: keep-alive" CRLF,
                             sizeof("Connection: keep-alive" CRLF) - 1);

        if (clcf->keepalive_header) {
            b->last = ngx_sprintf(b->last, "Keep-Alive: timeout=%T" CRLF,
                                  clcf->keepalive_header);
        }

    } else {
        b->last = ngx_cpymem(b->last, "Connection: close" CRLF,
                             sizeof("Connection: close" CRLF) - 1);
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "%*s", (size_t) (b->last - b->pos), b->pos);

    /* the end of HTTP header */
    *b->last++ = CR; *b->last++ = LF;

    r->header_size = b->last - b->pos;

    out.buf = b;
    out.next = NULL;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &out);
    if (pkt == NULL) {
        return NGX_ERROR;
    }

    ngx_http_flv_live_send_message(s, pkt, 0);
    ngx_rtmp_free_shared_chain(cscf, pkt);

    return NGX_OK;
}


void
ngx_http_flv_live_send_tail(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t *cscf;
    ngx_chain_t               cl_resp_hdr, *pkt;
    ngx_buf_t                 buf_resp_hdr;

    const ngx_str_t response_tail = ngx_string("0" CRLF CRLF);

    buf_resp_hdr.pos = response_tail.data;
    buf_resp_hdr.last = response_tail.data + response_tail.len;
    buf_resp_hdr.start = buf_resp_hdr.pos;
    buf_resp_hdr.end = buf_resp_hdr.last;

    cl_resp_hdr.buf = &buf_resp_hdr;
    cl_resp_hdr.next = NULL;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &cl_resp_hdr);
    ngx_http_flv_live_send_message(s, pkt, 0);
    ngx_rtmp_free_shared_chain(cscf, pkt);
}


ngx_int_t
ngx_http_flv_live_send_message(ngx_rtmp_session_t *s,
        ngx_chain_t *out, unsigned int priority)
{
    ngx_uint_t                      nmsg;

    nmsg = (s->out_last - s->out_pos) % s->out_queue + 1;

    if (priority > 3) {
        priority = 3;
    }

    /* drop packet?
     * Note we always leave 1 slot free */
    if (nmsg + priority * s->out_queue / 4 >= s->out_queue) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "flv live: HTTP drop message bufs='%ui', priority='%ui'",
                nmsg, priority);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
    s->out_last %= s->out_queue;

    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "flv live: HTTP send nmsg='%ui', priority='%ui' '#%ui'",
            nmsg, priority, s->out_last);

    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {
        ngx_http_flv_live_write_handler(s->connection->write);
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_flv_live_request(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_play_t       v;

    ngx_http_request_t          *r;
    ngx_http_flv_live_ctx_t     *ctx;

    r = s->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    if (ngx_http_flv_live_connect_init(s, &ctx->app, &ctx->stream) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

    ngx_memcpy(v.name, ctx->stream.data, ngx_min(ctx->stream.len,
            sizeof(v.name) - 1));
    ngx_memcpy(v.args, s->args.data, ngx_min(s->args.len,
            sizeof(v.args) - 1));

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
           "flv live: name='%s' args='%s' start='%i' duration='%i' "
           "reset='%i' silent='%i'",
           v.name, v.args, (ngx_int_t) v.start,
           (ngx_int_t) v.duration, (ngx_int_t) v.reset,
           (ngx_int_t) v.silent);

    if (s->wait_notify_connect) {
        ngx_memzero(&ctx->play, sizeof(ngx_event_t));
        ctx->play.handler = ngx_http_flv_live_play_handler;
        ctx->play.log = s->connection->log;
        ctx->play.data = s->connection;

        ngx_http_flv_live_play_handler(&ctx->play);

        r->main->count++;

        return ctx->error ? NGX_ERROR : NGX_OK;
    }

    return ngx_rtmp_play(s, &v);
}


/* +--------------+                              +-------------+
 * |   Client     |              |               |    Server   |
 * +------+-------+              |               +------+------+
 *        |               Handshaking done              |
 *        |                      |                      |
 *        |                      |                      |
 *        |----------- Command Message(connect) ------->|
 *        |                                             |
 *        |<------- Window Acknowledgement Size --------|
 *        |                                             |
 *        |<----------- Set Peer Bandwidth -------------|
 *        |                                             |
 *        |-------- Window Acknowledgement Size ------->|
 *        |                                             |
 *        |<------ User Control Message(StreamBegin) ---|
 *        |                                             |
 *        |<------------ Command Message ---------------|
 *        |        (_result- connect response)          |
 *
 * omit the user control message feedback
 */
void
ngx_http_flv_live_set_status(ngx_rtmp_session_t *s, unsigned active)
{
    ngx_rtmp_live_ctx_t        *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ctx->active = active;

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


ngx_int_t
ngx_http_flv_live_join(ngx_rtmp_session_t *s, u_char *name,
        unsigned int publisher)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_stream_t        **stream;
    ngx_rtmp_live_app_conf_t       *lacf;

    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_flag_t                      create;

    /* only for subscribers */
    if (publisher) {
        return NGX_DECLINED;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx && ctx->stream) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "flv live: already joined");

        return NGX_DECLINED;
    }

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_live_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->session = s;
    create = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "flv live: join '%s'", name);

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf && racf->pulls.nelts) {
        create = 1;
    }

    stream = ngx_rtmp_live_get_stream(s, name,
                        lacf->idle_streams || s->wait_notify_play || create);

    if (stream == NULL ||
        !(publisher || (*stream)->publishing || lacf->idle_streams ||
           s->wait_notify_play || create))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "flv live: stream not found");

        /* TODO: restore the c->read/write->handler and send error info */
        return NGX_ERROR;
    }

    if ((*stream)->pub_ctx == NULL || !(*stream)->pub_ctx->publishing) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "flv live: stream not publishing, check relay pulls");

        do {
            if (s->wait_notify_play) {
                break;
            }

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                          "flv live: no on_play, check relay pulls");

            /* check if there are some pulls */
            if (!create) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, 
                              "flv live: no on_play and no relay pulls, quit");

                return NGX_ERROR;
            }
        } while (0);
    }

    ctx->stream = *stream;
    ctx->publishing = publisher;
    ctx->next = (*stream)->ctx;
    ctx->protocol = NGX_RTMP_PROTOCOL_HTTP;

    (*stream)->ctx = ctx;

    if (ctx->stream->pub_ctx) {
        s->publisher = ctx->stream->pub_ctx->session;
    }

    if (lacf->buflen) {
        s->out_buffer = 1;
    }

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

    if (!ctx->publishing && ctx->stream->active) {
        ngx_http_flv_live_set_status(s, 1);
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_flv_live_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_live_app_conf_t        *lacf;
    ngx_rtmp_notify_app_conf_t      *nacf;
    ngx_http_request_t              *r;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf && nacf->url[NGX_RTMP_NOTIFY_PLAY]) {
        s->wait_notify_play = 1;
    }

    r = s->data;
    if (r == NULL) {
        goto next;
    }

    r->main->count++;

#if (nginx_version >= 1013001)
        /** 
         * when playing from pull, the downstream requests on the most 
         * of time return before the upstream requests, flv.js always 
         * sends HTTP header 'Connection: keep-alive', but Nginx has 
         * deleted r->blocked in ngx_http_finalize_request, that causes 
         * ngx_http_set_keepalive to run the cleanup handlers to close 
         * the connection between downstream and server, so play fails
         **/
        r->keepalive = 0;
#endif

    if (s->wait_notify_play) {
        goto next;
    }

    /* join stream as a subscriber */

    if (ngx_http_flv_live_join(s, v->name, 0) == NGX_ERROR) {
        r->main->count--;

        return NGX_ERROR;
    }

    if (ngx_rtmp_process_request_line(s, v->name, v->args,
            (const u_char *) "flv live play") != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "flv live play: name='%s' start='%uD' duration='%uD' reset='%d'",
            v->name, (uint32_t) v->start,
            (uint32_t) v->duration, (uint32_t) v->reset);

next:
    return next_play(s, v);
}


static void
ngx_http_flv_live_close_http_request(ngx_rtmp_session_t *s)
{
    ngx_http_request_t         *r;

    r = s->data;
    if (r && r->connection && !r->connection->destroyed) {
        r->main->count--;

        if (r->chunked) {
            ngx_http_flv_live_send_tail(s);
        } else {
            ngx_http_finalize_request(r, NGX_DONE);
        }
    }

    s->data = NULL;
}


ngx_int_t
ngx_http_flv_live_close_stream(ngx_rtmp_session_t *s,
        ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_ctx_t        *ctx, **cctx, *unlink;
    ngx_rtmp_live_app_conf_t   *lacf;
    ngx_flag_t                  passive;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        goto next;
    }

    passive = 0;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "flv live: not joined");

        goto next;
    }

    if (ctx->protocol == NGX_RTMP_PROTOCOL_RTMP) {
        /* close RTMP live play */
        if (!ctx->publishing) {
            goto next;
        }

        /* close all http flv live streams */
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "flv live: push closed '%s', close live streams subscribed",
                        ctx->stream->name);

        passive = 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "flv live: leave '%s'", ctx->stream->name);

    if (passive) {
        /* TODO: maybe using red-black tree is more efficient */
        for (cctx = &ctx->stream->ctx; *cctx; /* void */) {
            if ((*cctx)->protocol == NGX_RTMP_PROTOCOL_HTTP) {
                ngx_http_flv_live_close_http_request((*cctx)->session);

                if (!(*cctx)->publishing && (*cctx)->stream->active) {
                    ngx_http_flv_live_set_status((*cctx)->session, 0);
                }

                unlink = *cctx;

                *cctx = (*cctx)->next;

                unlink->next = NULL;
            } else {
                ngx_rtmp_finalize_session((*cctx)->session);
                cctx = &(*cctx)->next;
            }
        }
    } else {
        for (cctx = &ctx->stream->ctx; *cctx; /* void */) {
            if (*cctx == ctx) {
                if (!ctx->publishing && ctx->stream->active) {
                    ngx_http_flv_live_set_status(s, 0);
                }

                *cctx = ctx->next;

                ctx->next = NULL;
                ctx->stream = NULL;

                break;
            } else {
                cctx = &(*cctx)->next;
            }
        }
    }

    /** 
     * close only http requests here, the other 
     * requests were left for next_clost_stream 
     **/

next:
    return next_close_stream(s, v);
}


void
ngx_http_flv_live_play_handler(ngx_event_t *ev)
{
    static ngx_rtmp_play_t      v;

    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_rtmp_session_t         *s;
    ngx_http_flv_live_ctx_t    *ctx;

    c = ev->data;
    if (c->destroyed) {
        return;
    }

    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
    s = ctx->s;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (!s->wait_notify_connect) {
        ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

        ngx_memcpy(v.name, ctx->stream.data, ngx_min(ctx->stream.len,
                sizeof(v.name) - 1));
        ngx_memcpy(v.args, s->args.data, ngx_min(s->args.len,
                sizeof(v.args) - 1));

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
               "flv live: name='%s' args='%s' start='%i' duration='%i' "
               "reset='%i' silent='%i'",
               v.name, v.args, (ngx_int_t) v.start,
               (ngx_int_t) v.duration, (ngx_int_t) v.reset,
               (ngx_int_t) v.silent);

        r->main->count--;

        if (ngx_rtmp_play(s, &v) != NGX_OK) {
            ctx->error = 1;
        }
    } else {
        ngx_add_timer(ev, 20);
    }
}


void
ngx_http_flv_live_read_handler(ngx_event_t *rev)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_rtmp_session_t         *s;
    ngx_int_t                   n;
    ngx_http_flv_live_ctx_t    *ctx;
    u_char                      buf[NGX_BUFF_MAX_SIZE];

    c = rev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    s = ctx->s;

    if (c->destroyed) {
        return;
    }

    n = c->recv(c, buf, sizeof(buf));

    if (n == NGX_AGAIN) {
        ngx_add_timer(c->read, s->timeout);

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_rtmp_finalize_session(s);
        }
    } else {
        ngx_rtmp_finalize_session(s);
    }
}


void
ngx_http_flv_live_write_handler(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_rtmp_session_t         *s;
    ngx_int_t                   n;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_http_flv_live_ctx_t    *ctx;

    c = wev->data;
    r = c->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
    s = ctx->s;

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                "flv live: client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (s->out_chain == NULL && s->out_pos != s->out_last) {
        s->out_chain = s->out[s->out_pos];
        s->out_bpos = s->out_chain->buf->pos;
    }

    while (s->out_chain) {
        n = c->send(c, s->out_bpos, s->out_chain->buf->last - s->out_bpos);

        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, s->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }
            return;
        }

        if (n < 0) {
            ngx_rtmp_finalize_session(s);
            return;
        }

        s->out_bytes += n;
        s->ping_reset = 1;
        ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_out, n);
        s->out_bpos += n;

        if (s->out_bpos == s->out_chain->buf->last) {
            s->out_chain = s->out_chain->next;
            if (s->out_chain == NULL) {
                cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
                ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos]);
                s->out[s->out_pos] = NULL;
                ++s->out_pos;
                s->out_pos %= s->out_queue;
                if (s->out_pos == s->out_last) {
                    break;
                }
                s->out_chain = s->out[s->out_pos];
            }
            s->out_bpos = s->out_chain->buf->pos;
        }
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }

    ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &s->posted_dry_events);
}


ngx_int_t
ngx_http_flv_live_preprocess(ngx_http_request_t *r,
    ngx_rtmp_connection_t *rconn)
{
    ngx_http_flv_live_ctx_t     *ctx;
    ngx_listening_t             *ls;
    struct sockaddr             *local_sockaddr;

    struct sockaddr_in          *ls_sin, *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6         *ls_sin6, *sin6;
#endif

    ngx_rtmp_in_addr_t          *addr;
#if (NGX_HAVE_INET6)
    ngx_rtmp_in6_addr_t         *addr6;
#endif

    ngx_rtmp_port_t             *rport;

    ngx_str_t                    arg_app = ngx_string("app");
    ngx_str_t                    arg_stream = ngx_string("stream");
    ngx_str_t                    arg_port = ngx_string("port");
    ngx_str_t                    app, stream, port;
    ngx_int_t                    in_port;
    ngx_uint_t                   i, n;
    ngx_flag_t                   port_match, addr_match;
    unsigned short               sa_family;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    /** 
     * if requested args are escaped, for example, urls in the 
     * history list of vlc for Android (or all mobile platforms) 
     **/
    if (r->args.len == 0 && r->uri.len) {
        ngx_http_split_args(r, &r->uri, &r->args);
    }

    if (ngx_http_arg(r, arg_port.data, arg_port.len, &port) != NGX_OK) {
        /* no port in args */
        port.data = (u_char *) "1935";
        port.len = ngx_strlen("1935");

        in_port = 1935;
    } else {
        in_port = ngx_atoi(port.data, port.len);
        if (in_port == NGX_ERROR || (in_port < 0 || in_port > 65535)) {
            return NGX_ERROR;
        }
    }

    in_port = htons(in_port);
    ctx->port = port;

    port_match = 1;
    addr_match = 1;

    ls = ngx_cycle->listening.elts;
    for (n = 0; n < ngx_cycle->listening.nelts; ++n, ++ls) {
        if (ls->handler == ngx_rtmp_init_connection) {
            local_sockaddr = r->connection->local_sockaddr;
            sa_family = ls->sockaddr->sa_family;

            if (local_sockaddr->sa_family != sa_family) {
                continue;
            }

            switch (sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                ls_sin6 = (struct sockaddr_in6 *) ls->sockaddr;
                if (in_port != ls_sin6->sin6_port) {
                    port_match = 0;
                }

                break;
#endif

            default:
                ls_sin = (struct sockaddr_in *) ls->sockaddr;
                if (in_port != ls_sin->sin_port) {
                    port_match = 0;
                }
            }

            if (!port_match) {
                port_match = 1;
                continue;
            }

            rport = ls->servers;

            if (rport->naddrs > 1) {
                /**
                 * listen xxx.xxx.xxx.xxx:port
                 * listen port
                 **/
                switch (sa_family) {

#if (NGX_HAVE_INET6)
                case AF_INET6:
                    sin6 = (struct sockaddr_in6 *) ls->sockaddr;

                    addr6 = rport->addrs;

                    /* the last address is "*" */

                    for (i = 0; i < rport->naddrs - 1; i++) {
                        if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16)
                            == 0)
                        {
                            break;
                        }
                    }

                    rconn->addr_conf = &addr6[i].conf;

                    break;
#endif

                default:
                    sin = (struct sockaddr_in *) ls->sockaddr;

                    addr = rport->addrs;

                    /* the last address is "*" */

                    for (i = 0; i < rport->naddrs - 1; i++) {
                        if (addr[i].addr == sin->sin_addr.s_addr) {
                            break;
                        }
                    }

                    rconn->addr_conf = &addr[i].conf;
                }
            } else {
                switch (sa_family) {

#if (NGX_HAVE_INET6)
                case AF_INET6:
                    sin6 = (struct sockaddr_in6 *) ls->sockaddr;

                    addr6 = rport->addrs;
                    if (ngx_memcmp(&addr6[0].addr6, &sin6->sin6_addr, 16)) {
                        addr_match = 0;
                    } else {
                        rconn->addr_conf = &addr6[0].conf;
                    }

                    break;
#endif

                default:
                    sin = (struct sockaddr_in *) ls->sockaddr;

                    addr = rport->addrs;
                    if (addr[0].addr != sin->sin_addr.s_addr) {
                        addr_match = 0;
                    } else {
                        rconn->addr_conf = &addr[0].conf;
                    }
                }
            }

            if (!addr_match) {
                addr_match = 1;
                continue;
            } else {
                break;
            }
        }
    }

    if (n == ngx_cycle->listening.nelts) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: failed to find configured port: '%V'", &port);

        return NGX_ERROR;
    }

    if (ngx_http_arg(r, arg_app.data, arg_app.len, &app) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "flv live: app args MUST be specified");

        return NGX_ERROR;
    } else {
        ctx->app = app;
    }

    if (ngx_http_arg(r, arg_stream.data, arg_stream.len, &stream) != NGX_OK) {
        ctx->stream.data = (u_char *) "";
        ctx->stream.len = 0;
    } else {
        ctx->stream = stream;
    }

    return NGX_OK;
}


ngx_rtmp_session_t *
ngx_http_flv_live_init_connection(ngx_http_request_t *r,
    ngx_rtmp_connection_t *rconn)
{
    ngx_rtmp_session_t        *s;
    ngx_connection_t          *c;
    void                      *data;

    c = r->connection;

    /* the default server configuration for the address:port */
    rconn->conf_ctx = rconn->addr_conf->default_server->ctx;

    ++ngx_rtmp_naccepted;

    data = c->data;
    c->data = rconn;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "flv live: *%ui client connected '%V'", c->number, &c->addr_text);

    s = ngx_http_flv_live_init_session(r, rconn->addr_conf);
    c->data = data;

    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: failed to init connection for session");

        return NULL;
    }

    /* only auto-pushed connections are
     * done through unix socket */

    s->auto_pushed = 0;

    c->write->handler = ngx_http_flv_live_write_handler;
    c->read->handler = ngx_http_flv_live_read_handler;

    return s;
}


ngx_rtmp_session_t *
ngx_http_flv_live_init_session(ngx_http_request_t *r,
        ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_rtmp_session_t             *s;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_error_log_ctx_t       *ctx;
    ngx_connection_t               *c;

    c = r->connection;

    s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t));
    if (s == NULL) {
        /* let other handlers process */
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    s->rtmp_connection = c->data;

    s->main_conf = addr_conf->default_server->ctx->main_conf;
    s->srv_conf = addr_conf->default_server->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    s->connection = c;

    ctx = ngx_palloc(c->pool, sizeof(ngx_rtmp_error_log_ctx_t));
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_rtmp_log_error;
    c->log->data = ctx;
    c->log->action = NULL;

    c->log_error = NGX_ERROR_INFO;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    s->out_pool = ngx_create_pool(4096, c->log);
    if (s->out_pool == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    s->out = ngx_pcalloc(s->out_pool, sizeof(ngx_chain_t *)
                         * ((ngx_rtmp_core_srv_conf_t *)
                            addr_conf->default_server->ctx->srv_conf
                            [ngx_rtmp_core_module.ctx_index])->out_queue);
    if (s->out == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    s->in_streams_pool = ngx_create_pool(4096, c->log);
    if (s->in_streams_pool == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(s->in_streams_pool, sizeof(ngx_rtmp_stream_t)
            * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

#if (nginx_version >= 1007005)
    ngx_queue_init(&s->posted_dry_events);
#endif

    s->epoch = ngx_current_msec;
    s->timeout = cscf->timeout;
    s->buflen = cscf->buflen;
    ngx_rtmp_set_chunk_size(s, NGX_RTMP_DEFAULT_CHUNK_SIZE);

    if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    s->data = (void *)r;

    return s;
}


ngx_int_t
ngx_http_flv_live_connect_init(ngx_rtmp_session_t *s, ngx_str_t *app,
        ngx_str_t *stream)
{
    ngx_rtmp_connect_t           v;
    ngx_http_request_t          *r;
    ngx_rtmp_notify_srv_conf_t  *nscf;

    r = s->data;

    ngx_memzero(&v, sizeof(ngx_rtmp_connect_t));

    ngx_memcpy(v.app, app->data, ngx_min(app->len, sizeof(v.app) - 1));
    ngx_memcpy(v.args, r->args.data, ngx_min(r->args.len, sizeof(v.args) - 1));
    ngx_memcpy(v.flashver, "flv_live 1.1", ngx_strlen("flv_live 1.1"));

    *ngx_snprintf(v.tc_url, NGX_RTMP_MAX_URL, "http://%V/%V",
            &r->headers_in.host->value, app) = 0;

#define NGX_RTMP_SET_STRPAR(name)                                          \
    s->name.len = ngx_strlen(v.name);                                      \
    s->name.data = ngx_palloc(s->connection->pool, s->name.len);           \
    ngx_memcpy(s->name.data, v.name, s->name.len)

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(args);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(tc_url);

#undef NGX_RTMP_SET_STRPAR

    if (ngx_rtmp_process_virtual_host(s) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "flv live: failed to process virtual host");

        return NGX_ERROR;
    }

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);
    if (nscf && nscf->url[NGX_RTMP_NOTIFY_CONNECT]) {
        s->wait_notify_connect = 1;
    }

    s->stream.len = stream->len;
    s->stream.data = ngx_pstrdup(s->connection->pool, stream);

    return ngx_rtmp_connect(s, &v);
}


ngx_chain_t *
ngx_http_flv_live_meta_message(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_header_t    ch;

    ch.timestamp = 0;
    ch.type = NGX_RTMP_MSG_AMF_META;

    return ngx_http_flv_live_append_message(s, &ch, NULL, in);
}


ngx_chain_t *
ngx_http_flv_live_append_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_header_t *lh, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t        *cscf;
    ngx_http_request_t              *r;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        ngx_rtmp_free_shared_chain(cscf, in);
        return NULL;
    }

    r = s->data;
    if (r == NULL || (r->connection && r->connection->destroyed)) {
        ngx_rtmp_free_shared_chain(cscf, in);
        return NULL;
    }

    return ngx_http_flv_live_append_shared_bufs(cscf, h, in, r->chunked);
}


/*
 * Brief format:
 * |Tag|PreviousTagSize|
 * Detailed format:
 * |Reserved(2b)+Filter(1b)+TagType(5b)|DataLength(3B)|TimeStamp(3B)|
 * TimeStampExt(1B)|StreamID(3B)|Data(DataLengthB)|PreviousTagSize|
 */
ngx_chain_t *
ngx_http_flv_live_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf,
        ngx_rtmp_header_t *h, ngx_chain_t *in, ngx_flag_t chunked)
{
    ngx_chain_t        *tag, *chunk_head, *chunk_tail, chunk,
                       *iter, *last_in, **tail, prev_tag_size;
    u_char             *pos, *p,
#if !(NGX_WIN32)
                        chunk_item[ngx_strlen("0000000000000000" CRLF) + 1];
#else
                        chunk_item[19];
#endif
    uint32_t            data_size, size;
    off_t               tag_size;
    ngx_buf_t           prev_tag_size_buf, chunk_buf;

    for (data_size = 0, iter = in, last_in = iter; iter; iter = iter->next) {
        last_in = iter;
        data_size += (iter->buf->last - iter->buf->pos);
    }

    tail = &last_in->next;
    *tail = &prev_tag_size;

    tag_size = data_size + NGX_FLV_TAG_HEADER_SIZE;

    prev_tag_size.buf = &prev_tag_size_buf;
    prev_tag_size.next = NULL;

    prev_tag_size_buf.start = (u_char *) &size;
    prev_tag_size_buf.end = prev_tag_size_buf.start + sizeof(uint32_t);
    prev_tag_size_buf.pos = prev_tag_size_buf.start;
    prev_tag_size_buf.last = prev_tag_size_buf.end;

    pos = prev_tag_size_buf.pos;
    p = (u_char *) &tag_size;
    *pos++ = p[3];
    *pos++ = p[2];
    *pos++ = p[1];
    *pos++ = p[0];

    /* ngx_rtmp_alloc_shared_buf returns the memory:
     * |4B|sizeof(ngx_chain_t)|sizeof(ngx_buf_t)|NGX_RTMP_MAX_CHUNK_HEADER|
     * chunk_size|
     * the tag->buf->pos points to the addr of last part of memory
     */
    tag = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
    if (tag == NULL) {
        return NULL;
    }

    /* it links to the local variable, unlink it */
    *tail = NULL;

    tag->buf->pos -= NGX_FLV_TAG_HEADER_SIZE;
    pos = tag->buf->pos;

    /* type, 5bits */
    *pos++ = (u_char) (h->type & 0x1f);

    /* data length, 3B */
    p = (u_char *) &data_size;
    *pos++ = p[2];
    *pos++ = p[1];
    *pos++ = p[0];

    /* timestamp, 3B + ext, 1B */
    p = (u_char *) &h->timestamp;
    *pos++ = p[2];
    *pos++ = p[1];
    *pos++ = p[0];
    *pos++ = p[3];

    /* streamId, 3B, always be 0 */
    *pos++ = 0;
    *pos++ = 0;
    *pos++ = 0;

    /* add chunk header and tail */
    if (chunked) {
        /* 4 is the size of previous tag size itself */
        *ngx_sprintf(chunk_item, "%xO" CRLF, tag_size + 4) = 0;

        chunk_buf.start = chunk_item;
        chunk_buf.pos = chunk_buf.start;
        chunk_buf.end = chunk_buf.start + ngx_strlen(chunk_item);
        chunk_buf.last = chunk_buf.end;

        chunk.buf = &chunk_buf;
        chunk.next = NULL;

        chunk_head = ngx_rtmp_append_shared_bufs(cscf, NULL, &chunk);
        if (chunk_head == NULL) {
            return NULL;
        }

        for (iter = tag, last_in = iter; iter; iter = iter->next) {
            last_in = iter;
        }

        /* save the memory, very likely */
#if !(NGX_WIN32)
        if (__builtin_expect(last_in->buf->last + 2 <= last_in->buf->end, 1)) {
#else
        if (last_in->buf->last + 2 <= last_in->buf->end) {
#endif
            *last_in->buf->last++ = CR;
            *last_in->buf->last++ = LF;
        } else {
            *ngx_sprintf(chunk_item, CRLF) = 0;
            chunk_buf.start = chunk_item;
            chunk_buf.pos = chunk_buf.start;
            chunk_buf.end = chunk_buf.start + ngx_strlen(chunk_item);
            chunk_buf.last = chunk_buf.end;

            chunk.buf = &chunk_buf;
            chunk.next = NULL;

            chunk_tail = ngx_rtmp_append_shared_bufs(cscf, NULL, &chunk);
            if (chunk_tail == NULL) {
                return NULL;
            }

            tail = &last_in->next;
            *tail = chunk_tail;
        }

        chunk_head->next = tag;

        return chunk_head;
    }

    return tag;
}


void
ngx_http_flv_live_free_message(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    ngx_rtmp_free_shared_chain(cscf, in);
}


static void
ngx_http_flv_live_close_session_handler(ngx_rtmp_session_t *s)
{
    ngx_connection_t               *c;
    ngx_rtmp_core_srv_conf_t       *cscf;

    c = s->connection;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "flv live: close session");

    ngx_rtmp_fire_event(s, NGX_RTMP_DISCONNECT, NULL, NULL);

    if (s->ping_evt.timer_set) {
        ngx_del_timer(&s->ping_evt);
    }

    if (s->in_old_pool) {
        ngx_destroy_pool(s->in_old_pool);
    }

    if (s->in_pool) {
        ngx_destroy_pool(s->in_pool);
    }

    while (s->out_pos != s->out_last) {
        ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }

    if (s->in_streams_pool) {
        ngx_destroy_pool(s->in_streams_pool);
    }

    if (s->out_pool) {
        ngx_destroy_pool(s->out_pool);
    }
}


static void
ngx_http_flv_live_cleanup(void *data)
{
    ngx_rtmp_session_t       *s;

    s = data;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "flv live: close connection");

    ngx_http_flv_live_close_session_handler(s);
}


ngx_int_t
ngx_http_flv_live_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_flv_live_conf_t        *hfcf;
    ngx_http_cleanup_t              *cln;
    ngx_http_flv_live_ctx_t         *ctx;
    ngx_rtmp_session_t              *s;
    ngx_rtmp_connection_t           *rconn;

    if (!(r->method & (NGX_HTTP_GET))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: HTTP method was not \"GET\"");

        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->http_version < NGX_HTTP_VERSION_10) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: HTTP version 0.9 not supported");

        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    hfcf = ngx_http_get_module_loc_conf(r, ngx_http_flv_live_module);
    if (!hfcf->flv_live) {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_flv_live_ctx_t));

        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_flv_live_module);
    }

    rconn = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_connection_t));
    if (rconn == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_flv_live_preprocess(r, rconn) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    s = ngx_http_flv_live_init_connection(r, rconn);
    if (s == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->s = s;

    /* live, ranges not allowed */
    r->allow_ranges = 0;
    r->read_event_handler = ngx_http_test_reading;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_DECLINED;
    }

    cln->handler = ngx_http_flv_live_cleanup;
    cln->data = s;

    if (ngx_rtmp_fire_event(s, NGX_HTTP_FLV_LIVE_REQUEST, NULL, NULL) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

