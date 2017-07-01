
/*
 * Copyright (C) Winshining
 */

#include "ngx_http_flv_live_module.h"


static ngx_rtmp_play_pt         next_play;
static ngx_rtmp_close_stream_pt next_close_stream;


static ngx_array_t        *ngx_http_flv_live_conf;


static ngx_int_t ngx_http_flv_live_init(ngx_conf_t *cf);
static void *ngx_http_flv_live_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_flv_live_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);


static ngx_int_t ngx_http_flv_live_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_flv_live_init_process(ngx_cycle_t *cycle);


static ngx_int_t ngx_http_flv_live_send_header(ngx_rtmp_session_t *s);
static void ngx_http_flv_live_send_tail(ngx_rtmp_session_t *s);
static ngx_int_t ngx_http_flv_live_send_message(ngx_rtmp_session_t *s,
        ngx_chain_t *out, unsigned int priority);
static ngx_chain_t *ngx_http_flv_live_append_message(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in);
static void ngx_http_flv_live_free_message(ngx_rtmp_session_t *s,
        ngx_chain_t *in);
static void ngx_http_flv_live_close_stream_handler(ngx_rtmp_session_t *s);

extern ngx_rtmp_process_handler_t ngx_rtmp_live_process_handler;
static ngx_rtmp_process_handler_t ngx_http_flv_live_process_handler = {
    ngx_http_flv_live_send_message,
    ngx_http_flv_live_append_message,
    ngx_http_flv_live_free_message
};

ngx_rtmp_process_handler_t *ngx_rtmp_process_handlers[] = {
    &ngx_rtmp_live_process_handler,
    &ngx_http_flv_live_process_handler
};


static ngx_int_t ngx_http_flv_live_init_handlers(ngx_cycle_t *cycle);


static ngx_chain_t *ngx_http_alloc_chunked_shared_buf(
        ngx_rtmp_core_srv_conf_t *cscf);
static ngx_chain_t *ngx_http_append_chunked_shared_bufs(
        ngx_rtmp_core_srv_conf_t *cscf, ngx_chain_t *in,
        u_char **payload);


static ngx_int_t ngx_http_flv_live_req(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);

static void ngx_http_flv_live_start(ngx_rtmp_session_t *s);
static void ngx_http_flv_live_stop(ngx_rtmp_session_t *s);
static ngx_int_t ngx_http_flv_live_join(ngx_rtmp_session_t *s, u_char *name,
        unsigned int publisher);
static ngx_int_t ngx_http_flv_live_play(ngx_rtmp_session_t *s,
        ngx_rtmp_play_t *v);
static ngx_int_t ngx_http_flv_live_close_stream(ngx_rtmp_session_t *s,
        ngx_rtmp_close_stream_t *v);


static void ngx_http_flv_live_read_handler(ngx_event_t *rev);
static void ngx_http_flv_live_write_handler(ngx_event_t *wev);

static ngx_int_t ngx_http_flv_live_preprocess(ngx_http_request_t *r);

/* simulate the ngx_rtmp_init_connection */
static ngx_rtmp_session_t *ngx_http_flv_live_init_connection(
        ngx_http_request_t *r);
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

    { ngx_string("chunked"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_live_conf_t, chunked),
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
    void                      **p;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flv_live_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->flv_live = NGX_CONF_UNSET;
    conf->chunked = NGX_CONF_UNSET;

    /* we must wait until walking through the whole conf to know
     * the rtmp conf info, but unfortunately, the ngx_http_block
     * does postconfiguration after creating location trees, the
     * only way to find the loc_conf in the loc level was destroyed,
     * because the queue pointer of the srv level that refers to
     * the loc level was a temporary pointer, so we use this
     * work-around to get the loc_conf
     */
    if (ngx_http_flv_live_conf == NULL) {
        ngx_http_flv_live_conf = ngx_array_create(cf->pool,
            4, sizeof(void *));
        if (ngx_http_flv_live_conf == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "flv live: failed to create array for global conf");

            return NULL;
        }
    }

    p = ngx_array_push(ngx_http_flv_live_conf);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "flv live: failed to get memory for global conf");

        return NULL;
    }

    *p = (void *)conf;

    return (void *)conf;
}


char *
ngx_http_flv_live_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_flv_live_conf_t *prev = parent;
    ngx_http_flv_live_conf_t *conf = child;

    ngx_conf_merge_value(conf->flv_live, prev->flv_live, 0);
    ngx_conf_merge_value(conf->chunked, prev->chunked, 0);

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
    h = ngx_array_push(&cmcf->events[NGX_HTTP_FLV_LIVE_REQ]);
    *h = ngx_http_flv_live_req;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_http_flv_live_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_http_flv_live_close_stream;

    return NGX_OK;
}


ngx_int_t
ngx_http_flv_live_init_process(ngx_cycle_t *cycle)
{
    ngx_rtmp_core_main_conf_t  *cmcf = ngx_rtmp_core_main_conf;
    ngx_rtmp_core_srv_conf_t  **pcscf, *cscf;
    ngx_rtmp_core_app_conf_t  **pcacf, *cacf;
    ngx_http_flv_live_conf_t   *hfcf;
    void                      **iter;
    ngx_http_flv_live_app_t    *app;
    ngx_uint_t                  i, n, m;

    if (cmcf == NULL || cmcf->listen.nelts == 0) {
        return NGX_OK;
    }

    iter = ngx_http_flv_live_conf->elts;
    for (i = 0; i < ngx_http_flv_live_conf->nelts; ++i) {
        hfcf = (ngx_http_flv_live_conf_t *)iter[i];

        if (!hfcf->flv_live || hfcf->flv_live == NGX_CONF_UNSET) {
            continue;
        }

        if (hfcf->app_hash.ha.temp_pool == NULL) {
            hfcf->app_hash.ha.temp_pool = ngx_create_pool(
                    NGX_HASH_LARGE_ASIZE, cycle->log);

            if (hfcf->app_hash.ha.temp_pool == NULL) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                        "flv live: create pool for app_hash "
                        "temp_pool failed");

                return NGX_ERROR;
            }

            hfcf->app_hash.ha.pool = cycle->pool;

            if (ngx_hash_keys_array_init(&hfcf->app_hash.ha,
                    NGX_HASH_SMALL) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                        "flv live: ngx_hash_keys_array_init "
                        "for app_hash failed");

                return NGX_ERROR;
            }
        }

        pcscf = cmcf->servers.elts;
        for (n = 0; n < cmcf->servers.nelts; ++n, ++pcscf) {
            cscf = *pcscf;
            pcacf = cscf->applications.elts;

            for (m = 0; m < cscf->applications.nelts; ++m, ++pcacf) {
                cacf = *pcacf;

                app = ngx_pcalloc(cycle->pool,
                        sizeof(ngx_http_flv_live_app_t));
                if (app == NULL) {
                    return NGX_ERROR;
                }

                app->hash_name.data = ngx_pcalloc(cycle->pool,
                        NGX_RTMP_MAX_NAME + NGX_INT_T_LEN);
                if (app->hash_name.data == NULL) {
                    return NGX_ERROR;
                }

                app->hash_name.len = ngx_sprintf(app->hash_name.data,
                        "%V:%O", &cacf->name, n) - app->hash_name.data;
                app->srv.srv_index = n;
                app->app.app_index = m;
                app->app.app_name = cacf->name;

                if (n == 0 && m == 0) {
                    hfcf->default_hash.hash_name = app->hash_name;

                    hfcf->default_hash.srv.srv_index = 0;
                    hfcf->default_hash.app.app_index = 0; 
                    hfcf->default_hash.app.app_name = cacf->name;
                }

                ngx_hash_add_key(&hfcf->app_hash.ha,
                        &app->hash_name, app, 0);
            }
        }

        if (hfcf->app_hash.ha.keys.nelts) {
            hfcf->app_hash.hint.key = ngx_hash_key_lc;
            hfcf->app_hash.hint.max_size = NGX_HASH_MAX_SIZE;
            hfcf->app_hash.hint.bucket_size = NGX_HASH_MAX_BUKET_SIZE; 
            hfcf->app_hash.hint.name = "hash_for_app";
            hfcf->app_hash.hint.pool = cycle->pool;

            hfcf->app_hash.hint.hash = &hfcf->app_hash.hash.hash;
            hfcf->app_hash.hint.temp_pool = NULL;

            if (ngx_hash_init(&hfcf->app_hash.hint,
                    hfcf->app_hash.ha.keys.elts,
                    hfcf->app_hash.ha.keys.nelts) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                        "flv live: ngx_hash_init for app_hash failed");

                return NGX_ERROR;
            }
        }
    }

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
    ngx_http_flv_live_ctx_t         *ctx;
    ngx_http_request_t              *r;
    ngx_chain_t                      cl_resp_hdr, cl_flv_hdr, *pkt;
    ngx_buf_t                        buf_resp_hdr, buf_flv_hdr;
    ngx_flag_t                       chunked;

    const ngx_str_t chunked_resp_header = ngx_string(
        "HTTP/1.1 200 OK"
        CRLF
        "Content-Type: video/x-flv"
        CRLF
        "Connection: keep-alive"
        CRLF
        "Cache-Control: no-cache"
        CRLF
        "Transfer-Encoding: chunked"
        CRLF
        CRLF);

    const ngx_str_t consec_resp_header = ngx_string(
        "HTTP/1.1 200 OK"
        CRLF
        "Content-Type: video/x-flv"
        CRLF
        "Connection: keep-alive"
        CRLF
        "Cache-Control: no-cache"
        CRLF
        "Expires: -1"
        CRLF
        CRLF);

    // |F|L|V|ver|00000101|header_size|0|0|0|0|, ngx_http_flv_module.c
    const ngx_str_t chunked_flv_header = ngx_string(
        "d"
        CRLF
        "FLV\x1\x5\0\0\0\x9\0\0\0\0"
        CRLF
    );

    const ngx_str_t consec_flv_header = ngx_string(
        "FLV\x1\x5\0\0\0\x9\0\0\0\0"
    );

    r = s->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
    chunked = ctx->chunked;

    if (chunked) {
        buf_resp_hdr.pos = chunked_resp_header.data;
        buf_resp_hdr.last = chunked_resp_header.data + chunked_resp_header.len;

        buf_flv_hdr.pos = chunked_flv_header.data;
        buf_flv_hdr.last = chunked_flv_header.data + chunked_flv_header.len;
    } else {
        buf_resp_hdr.pos = consec_resp_header.data;
        buf_resp_hdr.last = consec_resp_header.data + consec_resp_header.len;

        buf_flv_hdr.pos = consec_flv_header.data;
        buf_flv_hdr.last = consec_flv_header.data + consec_flv_header.len;
    }

    buf_resp_hdr.start = buf_resp_hdr.pos;
    buf_resp_hdr.end = buf_resp_hdr.end;

    buf_flv_hdr.start = buf_flv_hdr.pos;
    buf_flv_hdr.end = buf_flv_hdr.end;

    cl_resp_hdr.buf = &buf_resp_hdr;
    cl_flv_hdr.buf = &buf_flv_hdr;

    cl_resp_hdr.next = &cl_flv_hdr;
    cl_flv_hdr.next = NULL;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    pkt = ngx_rtmp_append_shared_bufs(cscf, NULL, &cl_resp_hdr);

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
    buf_resp_hdr.end = buf_resp_hdr.end;

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
                "flv live: HTTP drop message bufs=%ui, priority=%ui",
                nmsg, priority);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
    s->out_last %= s->out_queue;

    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "flv live: HTTP send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);

    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {
        ngx_http_flv_live_write_handler(s->connection->write);
    }

    return NGX_OK;
}


ngx_chain_t *
ngx_http_alloc_chunked_shared_buf(ngx_rtmp_core_srv_conf_t *cscf)
{
    u_char             *p;
    ngx_chain_t        *out;
    ngx_buf_t          *b;
    size_t              size, fmt_size, min_size;
    ngx_str_t           delimiter = ngx_string(CRLF);
    ngx_str_t           chunk_header = ngx_string("ffffff" CRLF);
 
    fmt_size = NGX_FLV_TAG_HEADER_SIZE + chunk_header.len + delimiter.len;
    min_size = fmt_size + 1; /* at least 1 byte in the payload */

    out = cscf->free;

    if (out && (out->buf->end - out->buf->start >= (ssize_t)min_size)) {
        cscf->free = out->next;
    } else {
        size = fmt_size + cscf->chunk_size;

        p = ngx_pcalloc(cscf->pool, NGX_RTMP_REFCOUNT_BYTES
                + sizeof(ngx_chain_t)
                + sizeof(ngx_buf_t)
                + size);
        if (p == NULL) {
            return NULL;
        }

        p += NGX_RTMP_REFCOUNT_BYTES;
        out = (ngx_chain_t *)p;

        p += sizeof(ngx_chain_t);
        out->buf = (ngx_buf_t *)p;

        p += sizeof(ngx_buf_t);
        out->buf->start = p;
        out->buf->end = p + size;
    }

    out->next = NULL;
    b = out->buf;
    b->pos = b->last = b->start + NGX_FLV_TAG_HEADER_SIZE + chunk_header.len;
    b->memory = 1;

    /* buffer has refcount =1 when created! */
    ngx_rtmp_ref_set(out, 1);

    return out;
}


ngx_chain_t *
ngx_http_append_chunked_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf,
        ngx_chain_t *in, u_char **payload)
{
    ngx_chain_t        *head, *l, **ll;
    u_char             *p;
    size_t              size, delta;
    ngx_str_t           delimiter = ngx_string(CRLF);
    ngx_str_t           chunk_header = ngx_string("ffffff" CRLF);

    head = NULL;
    ll = &head;
    l = head;
    p = in->buf->pos;

    delta = 0;

    for ( ;; ) {
        /* delimiter.len: chunk tail length */
        if (l == NULL || l->buf->last == l->buf->end - delimiter.len) {
            l = ngx_http_alloc_chunked_shared_buf(cscf);
            if (l == NULL || l->buf == NULL) {
                break;
            }

            *ll = l;
            ll = &l->next;
        }

        while (l->buf->end - delimiter.len - l->buf->last
                >= in->buf->last - p)
        {
            l->buf->last = ngx_cpymem(l->buf->last, p,
                    in->buf->last - p);
            delta += in->buf->last - p;

            in = in->next;
            if (in == NULL) {
                l->buf->last = ngx_cpymem(l->buf->last, delimiter.data,
                        delimiter.len);
                goto done;
            }
            p = in->buf->pos;
        }

        size = l->buf->end - delimiter.len - l->buf->last;
        l->buf->last = ngx_cpymem(l->buf->last, p, size);
        p += size;
        delta += size;
    }

done:
    *ll = NULL;

    /* add hex\r\n */
    p = head->buf->pos - NGX_FLV_TAG_HEADER_SIZE - chunk_header.len;
    delta += NGX_FLV_TAG_HEADER_SIZE;
    delta = ngx_sprintf(p, "%xO" CRLF, delta) - p;

    /* |hex\r\n|FLVTag|PreviousTagSize|\r\n|, return the actual data addr */
    ngx_memmove((char *)(head->buf->pos - NGX_FLV_TAG_HEADER_SIZE - delta),
            (char *)p, delta);

    if (payload) {
        *payload = head->buf->pos - NGX_FLV_TAG_HEADER_SIZE - delta;
    }

    return head;
}


ngx_int_t
ngx_http_flv_live_req(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_play_t       v;

    ngx_http_request_t          *r;
    ngx_http_flv_live_ctx_t     *ctx;

    r = s->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    if (ngx_http_flv_live_connect_init(s, &ctx->app.app.app_name,
            &ctx->stream) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

    ngx_memcpy(v.name, ctx->stream.data, ngx_min(ctx->stream.len,
            sizeof(v.name) - 1));
    ngx_memcpy(v.args, s->args.data, ngx_min(s->args.len,
            sizeof(v.args) - 1));

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
           "flv live: name='%s' args='%s' start=%i duration=%i "
           "reset=%i silent=%i",
           v.name, v.args, (ngx_int_t) v.start,
           (ngx_int_t) v.duration, (ngx_int_t) v.reset,
           (ngx_int_t) v.silent);

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
ngx_http_flv_live_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t        *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ctx->active = 1;

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


void
ngx_http_flv_live_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t        *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ctx->active = 0;

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

    /* only for subscriber */
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

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "flv live: join '%s'", name);

    stream = ngx_rtmp_live_get_stream(s, name, lacf->idle_streams);

    if (stream == NULL ||
        !(publisher || (*stream)->publishing || lacf->idle_streams))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "flv live: stream not found");

        /* TODO: restore the c->read/write->handler and send error info */
        return NGX_ERROR;
    }

    if ((*stream)->pub_ctx == NULL || !(*stream)->pub_ctx->publishing) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "flv live: stream not publishing");

        return NGX_ERROR;
    }

    ctx->stream = *stream;
    ctx->publishing = publisher;
    ctx->next = (*stream)->ctx;
    ctx->protocol = NGX_RTMP_PROTOCOL_HTTP;

    (*stream)->ctx = ctx;

    if (lacf->buflen) {
        s->out_buffer = 1;
    }

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

    if (!ctx->publishing && ctx->stream->active) {
        ngx_http_flv_live_start(s);
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_flv_live_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_live_app_conf_t        *lacf;
    ngx_http_flv_live_ctx_t         *ctx;
    ngx_http_request_t              *r;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    r = s->data;
    if (r == NULL) {
        goto next;
    }

    r->main->count++;

    /* join stream as subscriber */

    if (ngx_http_flv_live_join(s, v->name, 0) == NGX_ERROR) {
        r->main->count--;

        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "flv live play: name='%s' start=%uD duration=%uD reset=%d",
            v->name, (uint32_t) v->start,
            (uint32_t) v->duration, (uint32_t) v->reset);

    if (!ctx->joined) {
        ngx_http_flv_live_send_header(s);

        ctx->joined = 1;
    }

next:
    return next_play(s, v);
}


static void
ngx_http_flv_live_close_stream_handler(ngx_rtmp_session_t *s)
{
    ngx_http_flv_live_ctx_t    *sctx;
    ngx_http_request_t         *r;

    r = s->data;
    if (r && r->connection && !r->connection->destroyed) {
        r->main->count--;

        sctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
        if (sctx->chunked) {
            sctx->chunked = 0;
            ngx_http_flv_live_send_tail(s);
        } else {
            r->blocked = 0;
            r->keepalive = 0;
            ngx_http_finalize_request(r, NGX_DONE);
        }
    }
}


ngx_int_t
ngx_http_flv_live_close_stream(ngx_rtmp_session_t *s,
        ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_ctx_t        *ctx, **cctx, *head, **iter;
    ngx_rtmp_live_stream_t    **stream;
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
        /* close all http flv stream */
        passive = 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "flv live: leave '%s'", ctx->stream->name);

    if (passive) {
        head = ctx->stream->ctx;
        iter = &head;

        /* TODO: maybe using red-black tree is more efficient */
        for (cctx = &ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
            if ((*cctx)->protocol == NGX_RTMP_PROTOCOL_HTTP) {
                ngx_http_flv_live_close_stream_handler((*cctx)->session);

                *iter = (*cctx)->next;
            } else {
                iter = &(*cctx)->next;
            }
        }

        ctx->stream->ctx = head;
        goto next;
    } else {
        for (cctx = &ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
            if (*cctx == ctx) {
                *cctx = ctx->next;
                break;
            }
        }
    }

    if (!ctx->publishing && ctx->stream->active) {
        ngx_http_flv_live_stop(s);
    }

    if (ctx->stream->ctx || ctx->stream->pub_ctx) {
        ctx->stream = NULL;
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "flv live: delete empty stream '%s'", ctx->stream->name);

    stream = ngx_rtmp_live_get_stream(s, ctx->stream->name, 0);
    if (stream == NULL) {
        goto next;
    }

    *stream = (*stream)->next;
    
    ctx->stream->next = lacf->free_streams;
    lacf->free_streams = ctx->stream;
    ctx->stream = NULL;

next:
    return next_close_stream(s, v);
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

    do {
        n = c->recv(c, buf, sizeof(buf));

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_finalize_session(s);

            break;
        }
    } while (n != NGX_EAGAIN);
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


static ngx_int_t
ngx_rtmp_preprocess_addrs(ngx_http_request_t *r, ngx_rtmp_port_t *mport,
    ngx_rtmp_conf_addr_t *addr)
{
    u_char              *p;
    size_t               len;
    ngx_uint_t           i;
    ngx_rtmp_in_addr_t  *addrs;
    struct sockaddr_in  *sin;
    u_char               buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(r->pool,
        mport->naddrs * sizeof(ngx_rtmp_in_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {
        sin = (struct sockaddr_in *) addr[i].sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].ctx;

        len = ngx_sock_ntop(addr[i].sockaddr,
#if (nginx_version >= 1005003)
                            addr[i].socklen,
#endif
                            buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
        addrs[i].conf.proxy_protocol = addr->proxy_protocol;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_rtmp_preprocess_addrs6(ngx_http_request_t *r, ngx_rtmp_port_t *mport,
    ngx_rtmp_conf_addr_t *addr)
{
    u_char               *p;
    size_t                len;
    ngx_uint_t            i;
    ngx_rtmp_in6_addr_t  *addrs6;
    struct sockaddr_in6  *sin6;
    u_char               buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(r->pool,
        mport->naddrs * sizeof(ngx_rtmp_in6_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {
        sin6 = (struct sockaddr_in6 *) addr[i].sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].ctx;

        len = ngx_sock_ntop(addr[i].sockaddr,
#if (nginx_version >= 1005003)
                            addr[i].socklen,
#endif
                            buf, NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs6[i].conf.addr_text.len = len;
        addrs6[i].conf.addr_text.data = p;
        addrs6[i].conf.proxy_protocol = addr->proxy_protocol;
    }

    return NGX_OK;
}

#endif


static ngx_int_t 
ngx_http_flv_live_preprocess_port(ngx_http_request_t *r)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_listen_t           *ls, listen;
    in_port_t                    p;
    struct sockaddr             *sa;
    struct sockaddr_in          *sin;
    ngx_rtmp_conf_port_t        *port;
    ngx_rtmp_conf_addr_t        *addr, *address;
    ngx_rtmp_port_t             *mport;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6         *sin6;
#endif
    ngx_http_flv_live_ctx_t     *ctx;
    ngx_uint_t                   iter, index;
    ngx_flag_t                   found;
    ngx_connection_t            *c;
    unsigned short               family;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf->listen.nelts == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: listen configuration not found");

        return NGX_ERROR;
    }

    iter = 0;
    found = 0;
    c = r->connection;
    family = c->local_sockaddr->sa_family;
    ls = cmcf->listen.elts;

    for (index = 0; index < cmcf->listen.nelts; index++) {
        if (iter == ctx->app.srv.srv_index) {
            if (family == AF_INET) {
#if (NGX_HAVE_INET6)
                    if (ls[index].ipv6only) {
                        continue;
                    }
#endif
            }

            found = 1;
            break;
        }

        if (!ls[index].consecutive) {
            iter++;
        }
    }

    if (!found) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: failed to found listen configuration: %O",
                ctx->app.srv.srv_index);

        return NGX_ERROR;
    }

    listen = ls[index];
    sa = (struct sockaddr *)&listen.sockaddr;

    switch (sa->sa_family) {
#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;
            p = sin6->sin6_port;
            break;
#endif

        default:
            sin = (struct sockaddr_in *) sa;
            p = sin->sin_port;
    }

    port = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_conf_port_t));
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;

    if (ngx_array_init(&port->addrs, r->pool, 1,
            sizeof(ngx_rtmp_conf_addr_t)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    addr = ngx_array_push(&port->addrs);

    addr->sockaddr = (struct sockaddr *) &listen.sockaddr;
    addr->socklen = listen.socklen;
    addr->ctx = listen.ctx;
    addr->bind = listen.bind;
    addr->wildcard = listen.wildcard;
    addr->so_keepalive = listen.so_keepalive;
    addr->proxy_protocol = listen.proxy_protocol;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    addr->tcp_keepidle = listen.tcp_keepidle;
    addr->tcp_keepintvl = listen.tcp_keepintvl;
    addr->tcp_keepcnt = listen.tcp_keepcnt;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    addr->ipv6only = listen.ipv6only;
#endif

    mport = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_port_t));
    if (mport == NULL) {
        return NGX_ERROR;
    }

    address = port->addrs.elts;
    mport->naddrs = 1;

    switch (address[0].sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
        case AF_INET6:
            if (ngx_rtmp_preprocess_addrs6(r, mport, address) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
#endif
        default: /* AF_INET */
            if (ngx_rtmp_preprocess_addrs(r, mport, address) != NGX_OK) {
                return NGX_ERROR;
            }
    }

    cmcf->data = mport;

    return NGX_OK;
}


ngx_int_t
ngx_http_flv_live_preprocess(ngx_http_request_t *r)
{
    ngx_http_flv_live_conf_t    *hfcf;
    ngx_http_flv_live_app_t     *value;
    ngx_http_flv_live_ctx_t     *ctx;
    ngx_str_t                    arg_srv = ngx_string("srv");
    ngx_str_t                    arg_app = ngx_string("app");
    ngx_str_t                    arg_stream = ngx_string("stream");
    ngx_str_t                    srv, app, stream;

    hfcf = ngx_http_get_module_loc_conf(r, ngx_http_flv_live_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
    
    if (ngx_http_arg(r, arg_srv.data, arg_srv.len, &srv) != NGX_OK) {
        ctx->app.srv.srv_index = 0;
    } else {
        ctx->app.srv.srv_index = ngx_atoi(srv.data, srv.len);
    }
    
    if (ngx_http_arg(r, arg_app.data, arg_app.len, &app) != NGX_OK) {
        ctx->app.app.app_index = hfcf->default_hash.app.app_index;
        ctx->app.app.app_name = hfcf->default_hash.app.app_name;
    } else {
        // ctx->app.app_index will be filled after ngx_hash_find
        ctx->app.app.app_name = app;
    }
    
    if (ctx->app.app.app_name.len == 0 && ctx->app.srv.srv_index == 0) {
        ctx->app.hash_name = hfcf->default_hash.hash_name;
    } else {
        ctx->app.hash_name.data = ngx_pcalloc(r->pool,
                NGX_RTMP_MAX_NAME + NGX_INT_T_LEN);
        if (ctx->app.hash_name.data == NULL) {
            return NGX_ERROR;
        }
        
        ctx->app.hash_name.len = ngx_sprintf(ctx->app.hash_name.data, "%V:%O",
                &ctx->app.app.app_name, ctx->app.srv.srv_index)
        - ctx->app.hash_name.data;
    }
    
    value = ngx_hash_find(&hfcf->app_hash.hash.hash,
            ngx_hash_key_lc(ctx->app.hash_name.data,
                    ctx->app.hash_name.len),
            ctx->app.hash_name.data, ctx->app.hash_name.len);
    if (value == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: failed to find configured app: \"%V\"", &ctx->app);
        
        return NGX_ERROR;
    }
    
    ctx->app.app.app_index = value->app.app_index;
    
    if (ngx_http_arg(r, arg_stream.data, arg_stream.len, &stream) != NGX_OK) {
        ctx->stream.data = (u_char *)"";
        ctx->stream.len = 0;
    } else {
        ctx->stream = stream;
    }

    if (ngx_http_flv_live_preprocess_port(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: preprocess port failed");

        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_rtmp_session_t *
ngx_http_flv_live_init_connection(ngx_http_request_t *r)
{
    ngx_uint_t                 i;
    ngx_rtmp_port_t           *port;
    struct sockaddr           *sa;
    struct sockaddr_in        *sin;
    ngx_rtmp_in_addr_t        *addr;
    ngx_rtmp_session_t        *s;
    ngx_rtmp_addr_conf_t      *addr_conf;
    ngx_int_t                  unix_socket;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    ngx_rtmp_in6_addr_t       *addr6;
#endif
    ngx_connection_t          *c;
    ngx_rtmp_core_main_conf_t *cmcf;

    /* find the server configuration for the address:port */

    /* AF_INET only */

    c = r->connection;

    cmcf = ngx_rtmp_core_main_conf;
    port = cmcf->data;

    unix_socket = 0;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return NULL;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "flv live: *%ui client connected '%V'",
            c->number, &c->addr_text);

    s = ngx_http_flv_live_init_session(r, addr_conf);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: failed to init connection for session");

        return NULL;
    }

    /* only auto-pushed connections are
     * done through unix socket */

    s->auto_pushed = unix_socket;

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

    s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t) +
            sizeof(ngx_chain_t *) * ((ngx_rtmp_core_srv_conf_t *)
                addr_conf->ctx->srv_conf[ngx_rtmp_core_module
                    .ctx_index])->out_queue);
    if (s == NULL) {
        /* let other handlers process */
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

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

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_stream_t)
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
    ngx_rtmp_connect_t     v;
    ngx_http_request_t    *r;

    r = (ngx_http_request_t *)s->data;

    ngx_memzero(&v, sizeof(ngx_rtmp_connect_t));

    ngx_memcpy(v.app, app->data, ngx_min(app->len, sizeof(v.app) - 1));
    ngx_memcpy(v.args, r->args.data, ngx_min(r->args.len, sizeof(v.args) - 1));
    ngx_memcpy(v.flashver, "flv_live 1.0", ngx_strlen("flv_live 1.0"));

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

    s->stream.len = stream->len;
    s->stream.data = ngx_pstrdup(r->pool, stream);

    return ngx_rtmp_connect(s, &v);
}


ngx_chain_t *
ngx_http_flv_live_append_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_header_t *lh, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t        *cscf;
    ngx_http_flv_live_ctx_t         *ctx;
    ngx_http_request_t              *r;
    ngx_flag_t                       chunked;

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

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
    chunked = ctx->chunked;

    return ngx_http_flv_live_append_shared_bufs(cscf, h, in, chunked);
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
    ngx_chain_t        *tag, *iter, *last_in, **tail, prev_tag_size;
    u_char             *pos, *p, *payload;
    uint32_t            data_size, tag_size, size;
    ngx_buf_t           prev_tag_size_buf;

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

    payload = NULL;

    /* ngx_rtmp_alloc_shared_buf returns the memory:
     * |4B|sizeof(ngx_chain_t)|sizeof(ngx_buf_t)|NGX_RTMP_MAX_CHUNK_HEADER|
     * chunk_size|
     * the tag->buf->pos points to the addr of last part of memory
     */
    if (chunked) {
        tag = ngx_http_append_chunked_shared_bufs(cscf, in, &payload);
    } else {
        tag = ngx_rtmp_append_shared_bufs(cscf, NULL, in);
    }

    /* it links to the local variable, unlink it */
    *tail = NULL;

    tag->buf->pos -= NGX_FLV_TAG_HEADER_SIZE;
    pos = tag->buf->pos;

    // type, 5bits
    *pos++ = (u_char) (h->type & 0x1f);

    // data length, 3B
    p = (u_char *) &data_size;
    *pos++ = p[2];
    *pos++ = p[1];
    *pos++ = p[0];

    // timestamp, 3B + ext, 1B
    p = (u_char *) &h->timestamp;
    *pos++ = p[2];
    *pos++ = p[1];
    *pos++ = p[0];
    *pos++ = p[3];

    *pos++ = 0;
    *pos++ = 0;
    *pos++ = 0;

    if (chunked) {
        tag->buf->pos = payload;
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
ngx_http_flv_close_session_handler(ngx_rtmp_session_t *s)
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

    ngx_rtmp_free_handshake_buffers(s);

    while (s->out_pos != s->out_last) {
        ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }
}


static void
ngx_http_flv_live_cleanup(void *data)
{
    ngx_http_request_t       *r = data;
    ngx_rtmp_session_t       *s;
    ngx_http_flv_live_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    s = ctx->s;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "flv live: close connection");

    ngx_http_flv_close_session_handler(s);
}


ngx_int_t
ngx_http_flv_live_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_flv_live_conf_t        *hfcf;
    ngx_http_cleanup_t              *cln;
    ngx_http_flv_live_ctx_t         *ctx;
    ngx_rtmp_session_t              *s;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "flv live: HTTP method was not \"GET\" or \"HEAD\"");

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

    if (ngx_http_flv_live_preprocess(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    s = ngx_http_flv_live_init_connection(r);
    if (s == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->chunked = hfcf->chunked;
    ctx->s = s;

    /* live, ranges not allowed */
    r->allow_ranges = 0;
    r->read_event_handler = ngx_http_test_reading;
    
    if (ngx_rtmp_fire_event(s, NGX_HTTP_FLV_LIVE_REQ, NULL, NULL) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_DECLINED;
    }

    cln->handler = ngx_http_flv_live_cleanup;
    cln->data = r;

    return NGX_OK;
}

