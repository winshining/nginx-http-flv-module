
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Winshining
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_upstream_round_robin.h"


#define NGX_RTMP_LAST   1
#define NGX_RTMP_FLUSH  2

#define NGX_RTMP_UPSTREAM_CONNECT_TRANS        1
#define NGX_RTMP_UPSTREAM_CREATE_STREAM_TRANS  2


#define NGX_RTMP_UPSTREAM_CSID_AMF_INI         3
#define NGX_RTMP_UPSTREAM_CSID_AMF             5
#define NGX_RTMP_UPSTREAM_MSID                 1


/* default flashVer */
#define NGX_RTMP_UPSTREAM_FLASHVER             "LNX.11,1,102,55"


typedef ngx_rtmp_upstream_ctx_t *(*ngx_rtmp_upstream_create_ctx_pt)
    (ngx_rtmp_session_t *s, ngx_str_t *name, ngx_rtmp_upstream_target_t *target);


static void ngx_rtmp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_rtmp_upstream_rd_check_broken_connection(ngx_rtmp_session_t *s);
static void ngx_rtmp_upstream_wr_check_broken_connection(ngx_rtmp_session_t *s);
static void ngx_rtmp_upstream_check_broken_connection(ngx_rtmp_session_t *s,
    ngx_event_t *ev);
static ngx_int_t ngx_rtmp_upstream_test_connect(ngx_connection_t *c);
#if 0
static ngx_int_t ngx_rtmp_output_filter(void *data,
    ngx_chain_t *chain);
#endif

static ngx_int_t ngx_rtmp_send_special(ngx_rtmp_session_t *s,
    ngx_uint_t flags);
static ngx_int_t ngx_rtmp_write_filter(ngx_rtmp_session_t *s,
    ngx_chain_t *in);

static void ngx_rtmp_upstream_next(ngx_rtmp_session_t *s,
    ngx_rtmp_upstream_t *u, ngx_uint_t ft_type);
static void ngx_rtmp_upstream_cleanup(void *data);
static void ngx_rtmp_upstream_finalize_session(ngx_rtmp_session_t *s,
    ngx_rtmp_upstream_t *u, ngx_int_t rc);

static char *ngx_rtmp_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);
static char *ngx_rtmp_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_rtmp_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_rtmp_upstream_init_main_conf(ngx_conf_t *cf, void *conf);

static ngx_int_t ngx_rtmp_upstream_set_local(ngx_rtmp_session_t *s,
    ngx_rtmp_upstream_t *u, ngx_rtmp_upstream_local_t *local);

static ngx_int_t ngx_rtmp_upstream_copy_str(ngx_pool_t *pool,
    ngx_str_t *dst, ngx_str_t *src);
static ngx_rtmp_upstream_ctx_t *ngx_rtmp_upstream_create_connection(
    ngx_rtmp_session_t *s, ngx_rtmp_conf_ctx_t *cctx, ngx_str_t* name,
    ngx_rtmp_upstream_target_t *target);
static ngx_rtmp_upstream_ctx_t *ngx_rtmp_upstream_create_remote_ctx(
    ngx_rtmp_session_t *s, ngx_str_t* name,
    ngx_rtmp_upstream_target_t *target);
static ngx_rtmp_upstream_ctx_t *ngx_rtmp_upstream_create_local_ctx(
    ngx_rtmp_session_t *s, ngx_str_t *name,
    ngx_rtmp_upstream_target_t *target);
static ngx_int_t ngx_rtmp_upstream_relay_create(ngx_rtmp_session_t *s,
    ngx_str_t *name,
    ngx_rtmp_upstream_target_t *target,
    ngx_rtmp_upstream_create_ctx_pt create_publish_ctx,
    ngx_rtmp_upstream_create_ctx_pt create_play_ctx);

#if 0
static ngx_int_t ngx_rtmp_upstream_pull(ngx_rtmp_session_t *s, ngx_str_t *name,
    ngx_rtmp_upstream_target_t *target);
#endif

static ngx_int_t ngx_rtmp_upstream_push(ngx_rtmp_session_t *s, ngx_str_t *name,
    ngx_rtmp_upstream_target_t *target);
static ngx_int_t ngx_rtmp_upstream_play_local(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_upstream_publish_local(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_upstream_send_connect(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_upstream_send_create_stream(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_upstream_send_publish(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_upstream_send_play(ngx_rtmp_session_t *s);


static ngx_command_t  ngx_rtmp_upstream_commands[] = {

    { ngx_string("upstream"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_rtmp_upstream,
      0,
      0,
      NULL },

    { ngx_string("server"),
      NGX_RTMP_UPS_CONF|NGX_CONF_1MORE,
      ngx_rtmp_upstream_server,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_upstream_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_rtmp_upstream_create_main_conf,    /* create main configuration */
    ngx_rtmp_upstream_init_main_conf,      /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create application configuration */
    NULL                                   /* merge application configuration */
};


ngx_module_t  ngx_rtmp_upstream_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_upstream_module_ctx,         /* module context */
    ngx_rtmp_upstream_commands,            /* module directives */
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


ngx_int_t
ngx_rtmp_upstream_create(ngx_rtmp_session_t *s)
{
    ngx_rtmp_upstream_t  *u;

    u = s->upstream;

    if (u && u->cleanup) {
        ngx_rtmp_upstream_cleanup(s);
    }

    u = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_upstream_t));
    if (u == NULL) {
        return NGX_ERROR;
    }

    s->upstream = u;

    u->peer.log = s->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;

    return NGX_OK;
}


static void
ngx_rtmp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_connection_t              *c;
    ngx_rtmp_session_t            *s;
    ngx_rtmp_upstream_t           *u;
    ngx_rtmp_upstream_resolved_t  *ur;

    s = ctx->data;
    c = s->connection;

    u = s->upstream;
    ur = u->resolved;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "rtmp upstream resolve: \"%V?%V\"", &s->uri, &s->args);

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_rtmp_upstream_finalize_session(s, u, NGX_RTMP_BAD_GATEWAY);
        goto failed;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
    u_char      text[NGX_SOCKADDR_STRLEN];
    ngx_str_t   addr;
    ngx_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, NGX_SOCKADDR_STRLEN, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (ngx_rtmp_upstream_create_round_robin_peer(s, ur) != NGX_OK) {
        ngx_rtmp_upstream_finalize_session(s, u,
                                          NGX_RTMP_INTERNAL_SERVER_ERROR);
        goto failed;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = ngx_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    ngx_rtmp_upstream_push_reconnect(&s->push_evt);

failed:

    ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &s->posted_dry_events);
}


void
ngx_rtmp_upstream_recv(ngx_event_t *rev)
{
    ngx_int_t                   n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s, *downstream;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_header_t          *h;
    ngx_rtmp_stream_t          *st, *st0;
    ngx_chain_t                *in, *head;
    ngx_buf_t                  *b;
    u_char                     *p, *pp, *old_pos;
    ngx_rtmp_upstream_t        *u;
    size_t                      size, fsize, old_size;
    uint8_t                     fmt, ext;
    uint32_t                    csid, timestamp;

    c = rev->data;
    s = c->data;
    downstream = s->data;
    u = downstream->upstream;
    b = NULL;
    old_pos = NULL;
    old_size = 0;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (c->destroyed) {
        return;
    }

    for( ;; ) {

        st = &s->in_streams[s->in_csid];

        /* allocate new buffer */
        if (st->in == NULL) {
            st->in = ngx_rtmp_alloc_in_buf(s);
            if (st->in == NULL) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                        "in buf alloc failed");
                ngx_rtmp_finalize_session(s);
                return;
            }
        }

        h  = &st->hdr;
        in = st->in;
        b  = in->buf;

        if (old_size) {

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "reusing formerly read data: %d", old_size);

            b->pos = b->start;
            b->last = ngx_movemem(b->pos, old_pos, old_size);

            if (s->in_chunk_size_changing) {
                ngx_rtmp_finalize_set_chunk_size(s);
            }

        } else {

            if (old_pos) {
                b->pos = b->last = b->start;
            }

            n = c->recv(c, b->last, b->end - b->last);

            if (n == NGX_ERROR || n == 0) {
                ngx_rtmp_finalize_session(s);
                return;
            }

            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                    ngx_rtmp_finalize_session(s);
                }
                return;
            }

            s->ping_reset = 1;
            ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_in, n);
            b->last += n;
            s->in_bytes += n;

            if (s->in_bytes >= 0xf0000000) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                               "resetting byte counter");
                s->in_bytes = 0;
                s->in_last_ack = 0;
            }

            if (s->ack_size && s->in_bytes - s->in_last_ack >= s->ack_size) {

                s->in_last_ack = s->in_bytes;

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                        "sending RTMP ACK(%uD)", s->in_bytes);

                if (ngx_rtmp_send_ack(s, s->in_bytes)) {
                    ngx_rtmp_upstream_next(s, u, NGX_RTMP_UPSTREAM_FT_RTMP_500);
                    return;
                }
            }
        }

        old_pos = NULL;
        old_size = 0;

        /* parse headers */
        if (b->pos == b->start) {
            p = b->pos;

            /* chunk basic header */
            fmt  = (*p >> 6) & 0x03;
            csid = *p++ & 0x3f;

            if (csid == 0) {
                if (b->last - p < 1)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;

            } else if (csid == 1) {
                if (b->last - p < 2)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;
                csid += (uint32_t)256 * (*(uint8_t*)p++);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP bheader fmt=%d csid=%D",
                    (int)fmt, csid);

            if (csid >= (uint32_t)cscf->max_streams) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "RTMP in chunk stream too big: %D >= %D",
                    csid, cscf->max_streams);
                ngx_rtmp_upstream_next(s, u, NGX_RTMP_UPSTREAM_FT_RTMP_500);
                return;
            }

            /* link orphan */
            if (s->in_csid == 0) {

                /* unlink from stream #0 */
                st->in = st->in->next;

                /* link to new stream */
                s->in_csid = csid;
                st = &s->in_streams[csid];
                if (st->in == NULL) {
                    in->next = in;
                } else {
                    in->next = st->in->next;
                    st->in->next = in;
                }
                st->in = in;
                h = &st->hdr;
                h->csid = csid;
            }

            ext = st->ext;
            timestamp = st->dtime;
            if (fmt <= 2 ) {
                if (b->last - p < 3)
                    continue;
                /* timestamp:
                 *  big-endian 3b -> little-endian 4b */
                pp = (u_char*)&timestamp;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;
                pp[3] = 0;

                ext = (timestamp == 0x00ffffff);

                if (fmt <= 1) {
                    if (b->last - p < 4)
                        continue;
                    /* size:
                     *  big-endian 3b -> little-endian 4b
                     * type:
                     *  1b -> 1b*/
                    pp = (u_char*)&h->mlen;
                    pp[2] = *p++;
                    pp[1] = *p++;
                    pp[0] = *p++;
                    pp[3] = 0;
                    h->type = *(uint8_t*)p++;

                    if (fmt == 0) {
                        if (b->last - p < 4)
                            continue;
                        /* stream:
                         *  little-endian 4b -> little-endian 4b */
                        pp = (u_char*)&h->msid;
                        pp[0] = *p++;
                        pp[1] = *p++;
                        pp[2] = *p++;
                        pp[3] = *p++;
                    }
                }
            }

            /* extended header */
            if (ext) {
                if (b->last - p < 4)
                    continue;
                pp = (u_char*)&timestamp;
                pp[3] = *p++;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;
            }

            if (st->len == 0) {
                /* Messages with type=3 should
                 * never have ext timestamp field
                 * according to standard.
                 * However that's not always the case
                 * in real life */
                st->ext = (ext && cscf->publish_time_fix);
                if (fmt) {
                    st->dtime = timestamp;
                } else {
                    h->timestamp = timestamp;
                    st->dtime = 0;
                }
            }

            ngx_log_debug8(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP mheader fmt=%d %s (%d) "
                    "time=%uD+%uD mlen=%D len=%D msid=%D",
                    (int)fmt, ngx_rtmp_message_type(h->type), (int)h->type,
                    h->timestamp, st->dtime, h->mlen, st->len, h->msid);

            /* header done */
            b->pos = p;

            if (h->mlen > cscf->max_message) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                        "too big message: %uz, %uz",
                                h->mlen, cscf->max_message);
                ngx_rtmp_upstream_next(s, u, NGX_RTMP_UPSTREAM_FT_RTMP_500);
                return;
            }
        }

        size = b->last - b->pos;
        fsize = h->mlen - st->len;

        if (size < ngx_min(fsize, s->in_chunk_size))
            continue;

        /* buffer is ready */

        if (fsize > s->in_chunk_size) {
            /* collect fragmented chunks */
            st->len += s->in_chunk_size;
            b->last = b->pos + s->in_chunk_size;
            old_pos = b->last;
            old_size = size - s->in_chunk_size;

        } else {
            /* handle! */
            head = st->in->next;
            st->in->next = NULL;
            b->last = b->pos + fsize;
            old_pos = b->last;
            old_size = size - fsize;
            st->len = 0;
            h->timestamp += st->dtime;

            if (ngx_rtmp_receive_message(s, h, head) != NGX_OK) {
                ngx_rtmp_upstream_next(s, u, NGX_RTMP_UPSTREAM_FT_RTMP_500);
                return;
            }

            if (s->in_chunk_size_changing) {
                /* copy old data to a new buffer */
                if (!old_size) {
                    ngx_rtmp_finalize_set_chunk_size(s);
                }

            } else {
                /* add used bufs to stream #0 */
                st0 = &s->in_streams[0];
                st->in->next = st0->in;
                st0->in = head;
                st->in = NULL;
            }
        }

        s->in_csid = 0;
    }
}


void
ngx_rtmp_upstream_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_int_t                   n;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_upstream_t        *u;

    c = wev->data;
    s = c->data;
    u = s->upstream;

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                "upstream timed out");
        ngx_rtmp_upstream_next(s, u, NGX_RTMP_UPSTREAM_FT_TIMEOUT);
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
            ngx_rtmp_upstream_next(s, u, NGX_RTMP_UPSTREAM_FT_ERROR);
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


static void
ngx_rtmp_upstream_rd_check_broken_connection(ngx_rtmp_session_t *s)
{
    ngx_rtmp_upstream_check_broken_connection(s, s->connection->read);
}


static void
ngx_rtmp_upstream_wr_check_broken_connection(ngx_rtmp_session_t *s)
{
    ngx_rtmp_upstream_check_broken_connection(s, s->connection->write);
}


static void
ngx_rtmp_upstream_check_broken_connection(ngx_rtmp_session_t *s,
    ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_int_t            event;
    ngx_connection_t     *c;
    ngx_rtmp_upstream_t  *u;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ev->log, 0,
                   "rtmp upstream check client, write event:%d, \"%V\"",
                   ev->write, &s->uri);

    c = s->connection;
    u = s->upstream;

    if (c->error) {
        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

            if (ngx_del_event(ev, event, 0) != NGX_OK) {
                ngx_rtmp_upstream_finalize_session(s, u,
                                            NGX_RTMP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client prematurely closed "
                          "connection, so upstream connection is closed too");
            ngx_rtmp_upstream_finalize_session(s, u,
                                              NGX_RTMP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            ngx_rtmp_upstream_finalize_session(s, u,
                                              NGX_RTMP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
        socklen_t  len;

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            ev->error = 1;
        }

        if (u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, err,
                        "epoll_wait() reported that client prematurely closed "
                        "connection, so upstream connection is closed too");
            ngx_rtmp_upstream_finalize_session(s, u,
                                              NGX_RTMP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "epoll_wait() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            ngx_rtmp_upstream_finalize_session(s, u,
                                              NGX_RTMP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ev->log, err,
                   "rtmp upstream recv(): %d", n);

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

        if (ngx_del_event(ev, event, 0) != NGX_OK) {
            ngx_rtmp_upstream_finalize_session(s, u,
                                            NGX_RTMP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (u->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "client prematurely closed connection, "
                      "so upstream connection is closed too");
        ngx_rtmp_upstream_finalize_session(s, u,
                                            NGX_RTMP_CLIENT_CLOSED_REQUEST);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    if (u->peer.connection == NULL) {
        ngx_rtmp_upstream_finalize_session(s, u,
                                            NGX_RTMP_CLIENT_CLOSED_REQUEST);
    }
}


/** 
 * when descriptor set as nonblocking, if connect succeeded,
 * descriptor becomes writeable, if connect failed, descriptor 
 * becomes both writeable and readable, the function used for 
 * distinguishing the two conditions 
**/
static ngx_int_t
ngx_rtmp_upstream_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


#if 0
static ngx_int_t
ngx_rtmp_output_filter(void *data, ngx_chain_t *chain)
{
    ngx_rtmp_session_t  *s;

    s = data;

    return ngx_rtmp_write_filter(s, chain);
}
#endif


static ngx_int_t
ngx_rtmp_write_filter(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    off_t                      size, sent, nsent, limit;
    ngx_uint_t                 last, flush, sync;
    ngx_msec_t                 delay;
    ngx_chain_t               *cl, *ln, **ll, *chain;
    ngx_connection_t          *c;
    ngx_rtmp_core_app_conf_t  *cacf;

    c = s->connection;

    if (c->error) {
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &s->client;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = s->client; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d s:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next) {
        cl = ngx_alloc_chain_link(s->connection->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d s:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "rtmp write filter: l:%ui f:%ui s:%O", last, flush, size);

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    if (!last && !flush && in && size < (off_t) cacf->postpone_output) {
        /* TODO: check if returning NGX_OK is OK */
        return NGX_OK;
    }

    /* c->buffered is not 0 means there is data to be sent */
    if (c->write->delayed) {
        c->buffered |= NGX_RTMP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    if (size == 0
        && !(c->buffered & NGX_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        if (last || flush || sync) {
            for (cl = s->client; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(s->connection->pool, ln);
            }

            s->client = NULL;
            c->buffered &= ~NGX_RTMP_WRITE_BUFFERED;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the rtmp output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    if (s->limit_rate) {
        if (s->limit_rate_after == 0) {
            s->limit_rate_after = cacf->limit_rate_after;
        }

        limit = (off_t) s->limit_rate * (ngx_time() - s->start_sec + 1)
                - (c->sent - s->limit_rate_after);

        if (limit <= 0) {
            c->write->delayed = 1;
            delay = (ngx_msec_t) (- limit * 1000 / s->limit_rate + 1);
            ngx_add_timer(c->write, delay);

            c->buffered |= NGX_RTMP_WRITE_BUFFERED;

            return NGX_AGAIN;
        }

        if (cacf->sendfile_max_chunk
            && (off_t) cacf->sendfile_max_chunk < limit)
        {
            limit = cacf->sendfile_max_chunk;
        }

    } else {
        limit = cacf->sendfile_max_chunk;
    }

    sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "rtmp write filter limit %O", limit);

    chain = c->send_chain(c, s->client, limit);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "rtmp write filter %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    if (s->limit_rate) {

        nsent = c->sent;

        if (s->limit_rate_after) {

            sent -= s->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= s->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        delay = (ngx_msec_t) ((nsent - sent) * 1000 / s->limit_rate);

        if (delay > 0) {
            limit = 0;
            c->write->delayed = 1;
            ngx_add_timer(c->write, delay);
        }
    }

    if (limit
        && c->write->ready
        && c->sent - sent >= limit - (off_t) (2 * ngx_pagesize))
    {
        c->write->delayed = 1;
        ngx_add_timer(c->write, 1);
    }

    for (cl = s->client; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(s->connection->pool, ln);
    }

    s->client = chain;

    if (chain) {
        c->buffered |= NGX_RTMP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    c->buffered &= ~NGX_RTMP_WRITE_BUFFERED;

    if (c->buffered & NGX_LOWLEVEL_BUFFERED) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static void
ngx_rtmp_upstream_next(ngx_rtmp_session_t *s, ngx_rtmp_upstream_t *u,
    ngx_uint_t ft_type)
{
    ngx_msec_t  timeout;
    ngx_uint_t  status, state;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "rtmp next upstream, %xi", ft_type);

    if (u->peer.sockaddr) {
        state = NGX_PEER_FAILED;

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (ft_type == NGX_RTMP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == NGX_RTMP_UPSTREAM_FT_ERROR) {
        /* TODO: inform balancer instead */
        u->peer.tries++;
    }

    /* construct _error */
    switch (ft_type) {

    case NGX_RTMP_UPSTREAM_FT_TIMEOUT:
        status = NGX_RTMP_GATEWAY_TIME_OUT;
        break;

    case NGX_RTMP_UPSTREAM_FT_RTMP_500:
        status = NGX_RTMP_INTERNAL_SERVER_ERROR;
        break;

    case NGX_RTMP_UPSTREAM_FT_RTMP_403:
        status = NGX_RTMP_FORBIDDEN;
        break;

    case NGX_RTMP_UPSTREAM_FT_RTMP_404:
        status = NGX_RTMP_NOT_FOUND;
        break;

    /*
     * NGX_RTMP_UPSTREAM_FT_BUSY_LOCK and NGX_RTMP_UPSTREAM_FT_MAX_WAITING
     * never reach here
     */

    default:
        status = NGX_RTMP_BAD_GATEWAY;
    }

    if (s->connection->error) {
        ngx_rtmp_upstream_finalize_session(s, u,
                                              NGX_RTMP_CLIENT_CLOSED_REQUEST);
        return;
    }

    timeout = u->conf->next_upstream_timeout;

    if (u->peer.tries == 0
        || ((u->conf->next_upstream & ft_type) != ft_type)
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
        ngx_rtmp_upstream_finalize_session(s, u, status);
        return;
    }

    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "close rtmp upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
        u->peer.connection = NULL;
    }

    ngx_rtmp_upstream_push_reconnect(&s->push_evt);
}


static void
ngx_rtmp_upstream_cleanup(void *data)
{
    ngx_rtmp_session_t *s = data;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "cleanup rtmp upstream request: \"%V\"", &s->uri);

    ngx_rtmp_upstream_finalize_session(s, s->upstream, NGX_DONE);
}


static void
ngx_rtmp_upstream_finalize_session(ngx_rtmp_session_t *s,
    ngx_rtmp_upstream_t *u, ngx_int_t rc)
{
    ngx_uint_t  flush;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "finalize rtmp upstream request: %i", rc);
#if 0
    if (u->cleanup == NULL) {
        /* the request was already finalized */
        ngx_rtmp_finalize_session(s);
        return;
    }

    *u->cleanup = NULL;
    u->cleanup = NULL;
#endif
    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->peer.free && u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;
    }

    if (u->peer.connection) {

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "close rtmp upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    s->connection->log->action = "sending to client";

    if (!u->handshake_sent
        || rc == NGX_RTMP_REQUEST_TIME_OUT
        || rc == NGX_RTMP_CLIENT_CLOSED_REQUEST)
    {
        ngx_rtmp_finalize_session(s);
        return;
    }

    flush = 0;

    if (rc >= NGX_RTMP_SPECIAL_RESPONSE) {
        rc = NGX_ERROR;
        flush = 1;
    }

    if (rc == 0) {
        rc = ngx_rtmp_send_special(s, NGX_RTMP_LAST);

    } else if (flush) {
        s->keepalive = 0;
        rc = ngx_rtmp_send_special(s, NGX_RTMP_FLUSH);
    }

    ngx_rtmp_finalize_session(s);
}


static ngx_int_t
ngx_rtmp_send_special(ngx_rtmp_session_t *s, ngx_uint_t flags)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;

    b = ngx_calloc_buf(s->connection->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (flags & NGX_RTMP_LAST) {
        b->last_buf = 1;
        b->sync = 1;
        b->last_in_chain = 1;
    }

    if (flags & NGX_RTMP_FLUSH) {
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_rtmp_write_filter(s, &out);
}


static char *
ngx_rtmp_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                          *rv;
    void                          *mconf;
    ngx_str_t                     *value;
    ngx_url_t                      u;
    ngx_uint_t                     m;
    ngx_conf_t                     pcf;
    ngx_rtmp_module_t             *module;
    ngx_rtmp_conf_ctx_t           *ctx, *rtmp_ctx;
    ngx_rtmp_upstream_srv_conf_t  *uscf;

    ngx_memzero(&u, sizeof(ngx_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = ngx_rtmp_upstream_add(cf, &u, NGX_RTMP_UPSTREAM_CREATE
                                         |NGX_RTMP_UPSTREAM_WEIGHT
                                         |NGX_RTMP_UPSTREAM_MAX_CONNS
                                         |NGX_RTMP_UPSTREAM_MAX_FAILS
                                         |NGX_RTMP_UPSTREAM_FAIL_TIMEOUT
                                         |NGX_RTMP_UPSTREAM_DOWN
                                         |NGX_RTMP_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    rtmp_ctx = cf->ctx;
    ctx->main_conf = rtmp_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->srv_conf[ngx_rtmp_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;

    /* the upstream{}'s app_conf */

    ctx->app_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ctx->app_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_RTMP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }

        if (module->create_app_conf) {
            mconf = module->create_app_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->app_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    uscf->servers = ngx_array_create(cf->pool, 4,
                                     sizeof(ngx_rtmp_upstream_server_t));
    if (uscf->servers == NULL) {
        return NGX_CONF_ERROR;
    }

    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_RTMP_UPS_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (uscf->servers->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return NGX_CONF_ERROR;
    }

    return rv;
}


static char *
ngx_rtmp_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_upstream_srv_conf_t  *uscf = conf;

    time_t                         fail_timeout;
    ngx_str_t                     *value, s;
    ngx_url_t                      u;
    ngx_int_t                      weight, max_conns, max_fails;
    ngx_uint_t                     i;
    ngx_rtmp_upstream_server_t    *us;

    us = ngx_array_push(uscf->servers);
    if (us == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(us, sizeof(ngx_rtmp_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NGX_RTMP_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NGX_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_conns=", 10) == 0) {

            if (!(uscf->flags & NGX_RTMP_UPSTREAM_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NGX_RTMP_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NGX_RTMP_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = ngx_parse_time(&s, 1);

            if (fail_timeout == (time_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & NGX_RTMP_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (ngx_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & NGX_RTMP_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 1935;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    us->name = u.url;
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_conns = max_conns;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;

not_supported:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return NGX_CONF_ERROR;
}


ngx_rtmp_upstream_srv_conf_t *
ngx_rtmp_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags)
{
    ngx_uint_t                      i;
    ngx_rtmp_upstream_server_t     *us;
    ngx_rtmp_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_rtmp_upstream_main_conf_t  *umcf;

    if (!(flags & NGX_RTMP_UPSTREAM_CREATE)) {

        if (ngx_parse_url(cf->pool, u) != NGX_OK) {
            if (u->err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || ngx_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & NGX_RTMP_UPSTREAM_CREATE)
             && (uscfp[i]->flags & NGX_RTMP_UPSTREAM_CREATE))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & NGX_RTMP_UPSTREAM_CREATE) && !u->no_port) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & NGX_RTMP_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port && u->port
            && uscfp[i]->port != u->port)
        {
            continue;
        }

        if (flags & NGX_RTMP_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
            uscfp[i]->port = 0;
        }

        return uscfp[i];
    }

    uscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->no_port = u->no_port;

    if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
        uscf->servers = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_rtmp_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = ngx_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        ngx_memzero(us, sizeof(ngx_rtmp_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    uscfp = ngx_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


char *
ngx_rtmp_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    ngx_int_t                           rc;
    ngx_str_t                          *value;
    ngx_rtmp_complex_value_t            cv;
    ngx_rtmp_upstream_local_t         **plocal, *local;
    ngx_rtmp_compile_complex_value_t    ccv;

    plocal = (ngx_rtmp_upstream_local_t **) (p + cmd->offset);

    if (*plocal != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        *plocal = NULL;
        return NGX_CONF_OK;
    }

    ngx_memzero(&ccv, sizeof(ngx_rtmp_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_rtmp_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    local = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_upstream_local_t));
    if (local == NULL) {
        return NGX_CONF_ERROR;
    }

    *plocal = local;

    if (cv.lengths) {
        local->value = ngx_palloc(cf->pool, sizeof(ngx_rtmp_complex_value_t));
        if (local->value == NULL) {
            return NGX_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
        if (local->addr == NULL) {
            return NGX_CONF_ERROR;
        }

        rc = ngx_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case NGX_OK:
            local->addr->name = value[1];
            break;

        case NGX_DECLINED:
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return NGX_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (ngx_strcmp(value[2].data, "transparent") == 0) {
#if (NGX_HAVE_TRANSPARENT_PROXY)
            local->transparent = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_upstream_set_local(ngx_rtmp_session_t *s, ngx_rtmp_upstream_t *u,
    ngx_rtmp_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NGX_OK;
    }

#if (NGX_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NGX_OK;
    }

    if (ngx_rtmp_complex_value(s, local->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        return NGX_OK;
    }

    addr = ngx_palloc(s->connection->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return NGX_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NGX_OK;
}


static void *
ngx_rtmp_upstream_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_upstream_main_conf_t  *umcf;

    umcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(ngx_rtmp_upstream_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    /* TODO: configurable */
    umcf->nbuckets = 1024;
    umcf->log = &cf->cycle->new_log;
    umcf->buflen = 5000;
    umcf->session_upstream = 0;
    umcf->push_reconnect = 3000;
    umcf->pull_reconnect = 3000;

    return umcf;
}


static char *
ngx_rtmp_upstream_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_upstream_main_conf_t  *umcf = conf;

    ngx_uint_t                      i;
    ngx_rtmp_upstream_init_pt       init;
    ngx_rtmp_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
                                            ngx_rtmp_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    umcf->ctx = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_upstream_ctx_t *)
            * umcf->nbuckets);
    if (umcf->ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                      "allocate for upstream context failed");

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


void
ngx_rtmp_upstream_push_reconnect(ngx_event_t *ev)
{
    ngx_str_t                      *host;
    ngx_uint_t                      i;
    ngx_rtmp_upstream_target_t      at;
    u_char                          path[sizeof("unix:") + NGX_MAX_PATH];
    u_char                          flash_ver[sizeof("APSH ,") +
                                              NGX_INT_T_LEN * 2];
    u_char                          tc_url[NGX_RTMP_MAX_NAME];
    u_char                          play_path[NGX_RTMP_MAX_NAME];
    ngx_str_t                       name;
    ngx_pid_t                       pid;
    ngx_file_info_t                 fi;
    size_t                          add;
    ngx_int_t                       rc;
    u_char                         *p, *old;
    ngx_str_t                      *url;
    ngx_resolver_ctx_t             *ctx, temp;
    ngx_rtmp_upstream_t            *u;
    ngx_rtmp_core_app_conf_t       *cacf;
    ngx_rtmp_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_rtmp_upstream_main_conf_t  *umcf;
    ngx_rtmp_session_t             *s;
    struct sockaddr_un             *saun;

    s = ev->data;
    u = s->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "upstream_push: reconnect");

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

    if (!u->conf->ignore_client_abort) {
        s->read_event_handler = ngx_rtmp_upstream_rd_check_broken_connection;
        s->write_event_handler = ngx_rtmp_upstream_wr_check_broken_connection;
    }

    if (ngx_rtmp_upstream_set_local(s, u, u->conf->local) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (u->resolved == NULL) {
        uscf = u->conf->upstream;
    } else {
        host = &u->resolved->host;

        umcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "no port in upstream \"%V\"", host);
                ngx_rtmp_upstream_finalize_session(s, u,
                                               NGX_RTMP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_rtmp_upstream_create_round_robin_peer(s, u->resolved)
                != NGX_OK)
            {
                ngx_rtmp_upstream_finalize_session(s, u,
                                               NGX_RTMP_INTERNAL_SERVER_ERROR);
                return;
            }

            goto upstream;
        }

        if (u->resolved->port == 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "no port in upstream \"%V\"", host);
            ngx_rtmp_upstream_finalize_session(s, u,
                                               NGX_RTMP_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        ctx = ngx_resolve_start(cacf->resolver, &temp);
        if (ctx == NULL) {
            ngx_rtmp_upstream_finalize_session(s, u,
                                               NGX_RTMP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "no resolver defined to resolve %V", host);

            ngx_rtmp_upstream_finalize_session(s, u,
                                               NGX_RTMP_BAD_GATEWAY);
            return;
        }

        ctx->name = *host;

        /* called in ngx_resolve_name */
        ctx->handler = ngx_rtmp_upstream_resolve_handler;
        ctx->data = s;
        ctx->timeout = cacf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_rtmp_upstream_finalize_session(s, u,
                                      NGX_RTMP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      "no upstream configuration");
        ngx_rtmp_upstream_finalize_session(s, u,
                                           NGX_RTMP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

    if (uscf->peer.init(s, uscf) != NGX_OK) {
        ngx_rtmp_upstream_finalize_session(s, u,
                                           NGX_RTMP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

upstream:

    rc = ngx_event_connect_peer(&u->peer);
    if (rc == NGX_ERROR) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "upstream: connection failed");

        ngx_rtmp_upstream_finalize_session(s, u,
                                           NGX_RTMP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "upstream: no live upstreams");
        ngx_rtmp_upstream_finalize_session(s, u,
                                           NGX_RTMP_UPSTREAM_FT_NOLIVE);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_rtmp_upstream_next(s, u, NGX_RTMP_UPSTREAM_FT_ERROR);
        return;
    }

    name = s->stream;
    ngx_memzero(&at, sizeof(at));
    ngx_str_set(&at.page_url, "nginx-upstream-push");
    at.tag = &ngx_rtmp_upstream_module;

    if (s->args.len) {
        at.play_path.data = play_path;
        at.play_path.len = ngx_snprintf(play_path, sizeof(play_path),
                                        "%V?%V", &name, &s->args) -
                           play_path;
    }

    pid = ngx_pid;

    ngx_memzero(&at.url, sizeof(at.url));
    url = &at.url.url;

    switch (u->peer.type) {
    case AF_UNIX:
        saun = (struct sockaddr_un *)u->peer.sockaddr;

        p = ngx_snprintf(path, sizeof(path) - 1, "unix:%s", saun->sun_path);
        *p = 0;

        if (ngx_file_info(path + sizeof("unix:") - 1, &fi) != NGX_OK) {
            ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "upstream_push: " ngx_file_info_n " failed: "
                           "pid=%P socket='%s'" "url='%V' name='%V'",
                           pid, path, url, &name);

            ngx_rtmp_upstream_finalize_session(s, u,
                                               NGX_RTMP_INTERNAL_SERVER_ERROR);
            return;
        }

        url->data = path;
        url->len = p - path;

        break;

    default:
        if (s->tc_url.len > 7
            && ngx_strncasecmp(s->tc_url.data, (u_char *) "rtmp://", 7) == 0)
        {
            add = 7;
        } else {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "invalid URL prefix in \"%V\"", &s->tc_url);
            ngx_rtmp_upstream_finalize_session(s, u,
                                               NGX_RTMP_BAD_REQUEST);
            return;
        }

        ngx_memzero(tc_url, sizeof(tc_url));
        ngx_memcpy(tc_url, u->peer.name->data, u->peer.name->len);

        url->data = s->tc_url.data + add;
        url->len = s->tc_url.len - add;
        p = url->data;
        p = ngx_strlchr(p, url->data + url->len, '/');
        if (p == NULL) {
            url->data = u->peer.name->data;
            url->len = u->peer.name->len;
        } else {
            /* check if there is one more '/' */
            old = ++p;

            p = ngx_strlchr(p, url->data + url->len, '/');
            if (p) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "invalid URL in \"%V\"", &s->tc_url);
                ngx_rtmp_upstream_finalize_session(s, u,
                                                   NGX_RTMP_BAD_REQUEST);
                return;
            }

            url->len = url->data + url->len - old;
            url->data = old;
            url->data--;
            url->len++;

            p = ngx_snprintf(tc_url + u->peer.name->len, url->len, "%s",
                             url->data);
            *p = 0;

            url->data = tc_url;
            url->len = p - tc_url;
        }
    }

    at.url.uri_part = 1;

    if (ngx_parse_url(s->connection->pool, &at.url) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream_push: parse_url failed "
                      "url='%V' name='%V'", url, &name);

        ngx_rtmp_upstream_finalize_session(s, u,
                                           NGX_RTMP_INTERNAL_SERVER_ERROR);
        return;
    }

    p = ngx_snprintf(flash_ver, sizeof(flash_ver) - 1, "APSH %i,%i",
                     (ngx_int_t) ngx_process_slot, (ngx_int_t) ngx_pid);
    at.flash_ver.data = flash_ver;
    at.flash_ver.len = p - flash_ver;

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "upstream_push: connect pid=%P socket='%s' name='%V'",
                   pid, path, &name);

    if (ngx_rtmp_upstream_push(s, &name, &at) != NGX_OK) {
        ngx_rtmp_upstream_finalize_session(s, u,
                                           NGX_RTMP_INTERNAL_SERVER_ERROR);
    }
}


static ngx_int_t
ngx_rtmp_upstream_copy_str(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    if (src->len == 0) {
        return NGX_OK;
    }
    dst->len = src->len;
    dst->data = ngx_palloc(pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    return NGX_OK;
}


static ngx_rtmp_upstream_ctx_t *
ngx_rtmp_upstream_create_connection(ngx_rtmp_session_t *s,
        ngx_rtmp_conf_ctx_t *cctx, ngx_str_t* name,
        ngx_rtmp_upstream_target_t *target)
{
    ngx_rtmp_upstream_main_conf_t  *umcf;
    ngx_rtmp_upstream_ctx_t        *rctx;
    ngx_rtmp_addr_conf_t           *addr_conf;
    ngx_rtmp_conf_ctx_t            *addr_ctx;
    ngx_rtmp_session_t             *rs;
    ngx_peer_connection_t          *pc;
    ngx_connection_t               *c;
    ngx_pool_t                     *pool;
    ngx_str_t                       v, *uri;
    u_char                         *first, *last, *p;

    umcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_upstream_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, umcf->log, 0,
                   "upstream: create remote context");

    pool = NULL;
    pool = ngx_create_pool(4096, umcf->log);
    if (pool == NULL) {
        return NULL;
    }

    rctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_upstream_ctx_t));
    if (rctx == NULL) {
        goto clear;
    }

    if (name && ngx_rtmp_upstream_copy_str(pool, &rctx->name, name)
        != NGX_OK)
    {
        goto clear;
    }

    if (ngx_rtmp_upstream_copy_str(pool, &rctx->url, &target->url.url)
        != NGX_OK)
    {
        goto clear;
    }

    rctx->tag = target->tag;
    rctx->data = target->data;

#define NGX_RTMP_RELAY_STR_COPY(to, from)                                     \
    if (ngx_rtmp_upstream_copy_str(pool, &rctx->to, &target->from)            \
                                   != NGX_OK)                                 \
    {                                                                         \
        goto clear;                                                           \
    }

    NGX_RTMP_RELAY_STR_COPY(app,        app);
    NGX_RTMP_RELAY_STR_COPY(tc_url,     tc_url);
    NGX_RTMP_RELAY_STR_COPY(page_url,   page_url);
    NGX_RTMP_RELAY_STR_COPY(swf_url,    swf_url);
    NGX_RTMP_RELAY_STR_COPY(flash_ver,  flash_ver);
    NGX_RTMP_RELAY_STR_COPY(play_path,  play_path);

    rctx->live  = target->live;
    rctx->start = target->start;
    rctx->stop  = target->stop;

#undef NGX_RTMP_RELAY_STR_COPY

    if (rctx->app.len == 0 || rctx->play_path.len == 0) {
        /* parse uri */
        uri = &target->url.uri;
        first = uri->data;
        last  = uri->data + uri->len;
        if (first != last && *first == '/') {
            ++first;
        }

        if (first != last) {

            /* deduce app */
            p = ngx_strlchr(first, last, '/');
            if (p == NULL) {
                p = last;
            }

            if (rctx->app.len == 0 && first != p) {
                v.data = first;
                v.len = p - first;
                if (ngx_rtmp_upstream_copy_str(pool, &rctx->app, &v)
                    != NGX_OK)
                {
                    goto clear;
                }
            }

            /* deduce play_path */
            if (p != last) {
                ++p;
            }

            if (rctx->play_path.len == 0 && p != last) {
                v.data = p;
                v.len = last - p;
                if (ngx_rtmp_upstream_copy_str(pool, &rctx->play_path, &v)
                        != NGX_OK)
                {
                    goto clear;
                }
            }
        }
    }

    pc = &s->upstream->peer;

    if (target->url.naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, umcf->log, 0,
                      "upstream: no address");
        goto clear;
    }

    /* copy log to keep shared log unchanged */
    rctx->log = *umcf->log;
    pc->log = &rctx->log;

    c = pc->connection;
    c->pool = pool;
    c->addr_text = rctx->url;

    addr_conf = ngx_pcalloc(pool, sizeof(ngx_rtmp_addr_conf_t));
    if (addr_conf == NULL) {
        goto clear;
    }
    addr_ctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (addr_ctx == NULL) {
        goto clear;
    }
    addr_conf->ctx = addr_ctx;
    addr_ctx->main_conf = cctx->main_conf;
    addr_ctx->srv_conf  = cctx->srv_conf;

    addr_conf->addr_text.data = target->url.host.data;
    addr_conf->addr_text.len = target->url.host.len;

    rs = ngx_rtmp_init_session(c, addr_conf);
    if (rs == NULL) {
        /* no need to destroy pool */
        return NULL;
    }
    rs->app_conf = cctx->app_conf;
    rs->relay = 1;
    rctx->session = rs;
    ngx_rtmp_set_ctx(rs, rctx, ngx_rtmp_upstream_module);

    rs->flashver.data = rctx->flash_ver.data;
    rs->flashver.len = rctx->flash_ver.len;

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

    if (ngx_rtmp_upstream_test_connect(c) != NGX_OK) {
        ngx_rtmp_upstream_next(s, s->upstream, NGX_RTMP_UPSTREAM_FT_ERROR);
        return NULL;
    }

    s->upstream->handshake_sent = 0;

    ngx_rtmp_client_handshake(rs, 1);
    return rctx;

clear:
    if (pool) {
        ngx_destroy_pool(pool);
    }
    return NULL;
}


static ngx_rtmp_upstream_ctx_t *
ngx_rtmp_upstream_create_remote_ctx(ngx_rtmp_session_t *s, ngx_str_t* name,
        ngx_rtmp_upstream_target_t *target)
{
    ngx_rtmp_conf_ctx_t         cctx;

    cctx.app_conf = s->app_conf;
    cctx.srv_conf = s->srv_conf;
    cctx.main_conf = s->main_conf;

    return ngx_rtmp_upstream_create_connection(s, &cctx, name, target);
}


static ngx_rtmp_upstream_ctx_t *
ngx_rtmp_upstream_create_local_ctx(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_upstream_target_t *target)
{
    ngx_rtmp_upstream_ctx_t           *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "upstream: create local context");

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_upstream_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_upstream_module);
    }
    ctx->session = s;

    ctx->push_evt.data = s;
    ctx->push_evt.log = s->connection->log;
    ctx->push_evt.handler = ngx_rtmp_upstream_push_reconnect;

    if (ctx->publish) {
        return NULL;
    }

    if (ngx_rtmp_upstream_copy_str(s->connection->pool, &ctx->name, name)
            != NGX_OK)
    {
        return NULL;
    }

    return ctx;
}


static ngx_int_t
ngx_rtmp_upstream_relay_create(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_upstream_target_t *target,
        ngx_rtmp_upstream_create_ctx_pt create_publish_ctx,
        ngx_rtmp_upstream_create_ctx_pt create_play_ctx)
{
    ngx_rtmp_upstream_main_conf_t     *umcf;
    ngx_rtmp_upstream_ctx_t           *publish_ctx, *play_ctx, **cctx;
    ngx_uint_t                         hash;


    umcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_upstream_module);
    if (umcf == NULL) {
        return NGX_ERROR;
    }

    play_ctx = create_play_ctx(s, name, target);
    if (play_ctx == NULL) {
        return NGX_ERROR;
    }

    /* for upstream */
    play_ctx->session->data = s;

    hash = ngx_hash_key(name->data, name->len);
    cctx = &umcf->ctx[hash % umcf->nbuckets];
    for (; *cctx; cctx = &(*cctx)->next) {
        if ((*cctx)->name.len == name->len
            && !ngx_memcmp(name->data, (*cctx)->name.data,
                name->len))
        {
            break;
        }
    }

    if (*cctx) {
        play_ctx->publish = (*cctx)->publish;
        play_ctx->next = (*cctx)->play;
        (*cctx)->play = play_ctx;
        return NGX_OK;
    }

    publish_ctx = create_publish_ctx(s, name, target);
    if (publish_ctx == NULL) {
        ngx_rtmp_finalize_session(play_ctx->session);
        return NGX_ERROR;
    }

    publish_ctx->publish = publish_ctx;
    publish_ctx->play = play_ctx;
    play_ctx->publish = publish_ctx;
    *cctx = publish_ctx;

    return NGX_OK;
}


#if 0
static ngx_int_t
ngx_rtmp_upstream_pull(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_upstream_target_t *target)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "upstream: create pull name='%V' app='%V' playpath='%V' url='%V'",
            name, &target->app, &target->play_path, &target->url.url);

    return ngx_rtmp_upstream_relay_create(s, name, target,
            ngx_rtmp_upstream_create_remote_ctx,
            ngx_rtmp_upstream_create_local_ctx);
}
#endif


static ngx_int_t
ngx_rtmp_upstream_push(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_upstream_target_t *target)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "upstream: create push name='%V' app='%V' playpath='%V' url='%V'",
            name, &target->app, &target->play_path, &target->url.url);

    return ngx_rtmp_upstream_relay_create(s, name, target,
            ngx_rtmp_upstream_create_local_ctx,
            ngx_rtmp_upstream_create_remote_ctx);
}


static ngx_int_t
ngx_rtmp_upstream_play_local(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_t             v;
    ngx_rtmp_upstream_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));
    v.silent = 1;
    *(ngx_cpymem(v.name, ctx->name.data,
            ngx_min(sizeof(v.name) - 1, ctx->name.len))) = 0;

    return ngx_rtmp_play(s, &v);
}


static ngx_int_t
ngx_rtmp_upstream_publish_local(ngx_rtmp_session_t *s)
{
    ngx_rtmp_publish_t          v;
    ngx_rtmp_upstream_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_publish_t));
    v.silent = 1;
    *(ngx_cpymem(v.name, ctx->name.data,
            ngx_min(sizeof(v.name) - 1, ctx->name.len))) = 0;

    return ngx_rtmp_publish(s, &v);
}


static ngx_int_t
ngx_rtmp_upstream_send_connect(ngx_rtmp_session_t *s)
{
    static double               trans = NGX_RTMP_UPSTREAM_CONNECT_TRANS;
    static double               acodecs = 3575;
    static double               vcodecs = 252;

    static ngx_rtmp_amf_elt_t   out_cmd[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("app"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("tcUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("pageUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("swfUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("flashVer"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audioCodecs"),
          &acodecs, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videoCodecs"),
          &vcodecs, 0 }
    };

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "connect", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_cmd, sizeof(out_cmd) }
    };

    ngx_rtmp_core_app_conf_t   *cacf;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_upstream_ctx_t    *ctx;
    ngx_rtmp_header_t           h;
    size_t                      len, url_len;
    u_char                     *p, *url_end;


    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (cacf == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    /* app */
    if (ctx->app.len) {
        out_cmd[0].data = ctx->app.data;
        out_cmd[0].len  = ctx->app.len;
    } else {
        out_cmd[0].data = cacf->name.data;
        out_cmd[0].len  = cacf->name.len;
    }

    /* tcUrl */
    if (ctx->tc_url.len) {
        out_cmd[1].data = ctx->tc_url.data;
        out_cmd[1].len  = ctx->tc_url.len;
    } else {
        len = sizeof("rtmp://") - 1 + ctx->url.len +
            sizeof("/") - 1 + ctx->app.len;
        p = ngx_palloc(s->connection->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }
        out_cmd[1].data = p;
        p = ngx_cpymem(p, "rtmp://", sizeof("rtmp://") - 1);

        url_len = ctx->url.len;
        url_end = ngx_strlchr(ctx->url.data, ctx->url.data + ctx->url.len, '/');
        if (url_end) {
            url_len = (size_t) (url_end - ctx->url.data);
        }

        p = ngx_cpymem(p, ctx->url.data, url_len);
        *p++ = '/';
        p = ngx_cpymem(p, ctx->app.data, ctx->app.len);
        out_cmd[1].len = p - (u_char *)out_cmd[1].data;
    }

    /* pageUrl */
    out_cmd[2].data = ctx->page_url.data;
    out_cmd[2].len  = ctx->page_url.len;

    /* swfUrl */
    out_cmd[3].data = ctx->swf_url.data;
    out_cmd[3].len  = ctx->swf_url.len;

    /* flashVer */
    if (ctx->flash_ver.len) {
        out_cmd[4].data = ctx->flash_ver.data;
        out_cmd[4].len  = ctx->flash_ver.len;
    } else {
        out_cmd[4].data = NGX_RTMP_UPSTREAM_FLASHVER;
        out_cmd[4].len  = sizeof(NGX_RTMP_UPSTREAM_FLASHVER) - 1;
    }

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_UPSTREAM_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_chunk_size(s, cscf->chunk_size) != NGX_OK
        || ngx_rtmp_send_ack_size(s, cscf->ack_window) != NGX_OK
        || ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
        ? NGX_ERROR
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_upstream_send_create_stream(ngx_rtmp_session_t *s)
{
    static double               trans = NGX_RTMP_UPSTREAM_CREATE_STREAM_TRANS;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "createStream", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 }
    };

    ngx_rtmp_header_t           h;


    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_UPSTREAM_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_upstream_send_publish(ngx_rtmp_session_t *s)
{
    static double               trans;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "publish", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 }, /* <- to fill */

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "live", 0 }
    };

    ngx_rtmp_header_t           h;
    ngx_rtmp_upstream_ctx_t       *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->play_path.len) {
        out_elts[3].data = ctx->play_path.data;
        out_elts[3].len  = ctx->play_path.len;
    } else {
        out_elts[3].data = ctx->name.data;
        out_elts[3].len  = ctx->name.len;
    }

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_UPSTREAM_CSID_AMF;
    h.msid = NGX_RTMP_UPSTREAM_MSID;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_upstream_send_play(ngx_rtmp_session_t *s)
{
    static double               trans;
    static double               start, duration;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "play", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 }, /* <- fill */

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &start, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &duration, 0 },
    };

    ngx_rtmp_header_t               h;
    ngx_rtmp_upstream_ctx_t        *ctx;
    ngx_rtmp_upstream_main_conf_t  *umcf;


    umcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_upstream_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (umcf == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->play_path.len) {
        out_elts[3].data = ctx->play_path.data;
        out_elts[3].len  = ctx->play_path.len;
    } else {
        out_elts[3].data = ctx->name.data;
        out_elts[3].len  = ctx->name.len;
    }

    if (ctx->live) {
        start = -1000;
        duration = -1000;
    } else {
        start    = (ctx->start ? ctx->start : -2000);
        duration = (ctx->stop  ? ctx->stop - ctx->start : -1000);
    }

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_UPSTREAM_CSID_AMF;
    h.msid = NGX_RTMP_UPSTREAM_MSID;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
           || ngx_rtmp_send_set_buflen(s, NGX_RTMP_UPSTREAM_MSID,
                   umcf->buflen) != NGX_OK
           ? NGX_ERROR
           : NGX_OK;
}


ngx_int_t
ngx_rtmp_upstream_on_result(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_upstream_ctx_t       *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "upstream: _result: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    switch ((ngx_int_t)v.trans) {
        case NGX_RTMP_UPSTREAM_CONNECT_TRANS:
            return ngx_rtmp_upstream_send_create_stream(s);

        case NGX_RTMP_UPSTREAM_CREATE_STREAM_TRANS:
            if (ctx->publish != ctx && !s->static_relay) {
                if (ngx_rtmp_upstream_send_publish(s) != NGX_OK) {
                    return NGX_ERROR;
                }
                return ngx_rtmp_upstream_play_local(s);

            } else {
                if (ngx_rtmp_upstream_send_play(s) != NGX_OK) {
                    return NGX_ERROR;
                }
                return ngx_rtmp_upstream_publish_local(s);
            }

        default:
            return NGX_OK;
    }
}


ngx_int_t
ngx_rtmp_upstream_on_error(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_upstream_ctx_t    *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "upstream: _error: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_upstream_on_status(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_upstream_ctx_t    *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };

    static ngx_rtmp_amf_elt_t   in_elts_meta[] = {

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (h->type == NGX_RTMP_MSG_AMF_META) {
        ngx_rtmp_receive_amf(s, in, in_elts_meta,
                sizeof(in_elts_meta) / sizeof(in_elts_meta[0]));
    } else {
        ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0]));
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "upstream: onStatus: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_upstream_handshake_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_upstream_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    return ngx_rtmp_upstream_send_connect(s);
}


void
ngx_rtmp_upstream_close(ngx_rtmp_session_t *s)
{
    ngx_rtmp_upstream_main_conf_t      *umcf;
    ngx_rtmp_upstream_ctx_t            *ctx, **cctx;
    ngx_uint_t                          hash;

    umcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_upstream_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_upstream_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->publish == NULL) {
        return;
    }

    /* play end disconnect? */
    if (ctx->publish != ctx) {
        for (cctx = &ctx->publish->play; *cctx; cctx = &(*cctx)->next) {
            if (*cctx == ctx) {
                *cctx = ctx->next;
                break;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0,
                "upstream: play disconnect app='%V' name='%V'",
                &ctx->app, &ctx->name);

        /* push reconnect */
        if (s->relay && ctx->tag == &ngx_rtmp_upstream_module &&
            !ctx->publish->push_evt.timer_set)
        {
            ngx_add_timer(&ctx->publish->push_evt, umcf->push_reconnect);
        }

#ifdef NGX_DEBUG
        {
            ngx_uint_t  n = 0;
            for (cctx = &ctx->publish->play; *cctx; cctx = &(*cctx)->next, ++n);
            ngx_log_debug3(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0,
                "upstream: play left after disconnect app='%V' name='%V': %ui",
                &ctx->app, &ctx->name, n);
        }
#endif

        if (ctx->publish->play == NULL && ctx->publish->session->relay) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP,
                 ctx->publish->session->connection->log, 0,
                "upstream: publish disconnect empty app='%V' name='%V'",
                &ctx->app, &ctx->name);
            ngx_rtmp_finalize_session(ctx->publish->session);
        }

        ctx->publish = NULL;

        return;
    }

    /* publish end disconnect */
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ctx->session->connection->log, 0,
            "upstream: publish disconnect app='%V' name='%V'",
            &ctx->app, &ctx->name);

    if (ctx->push_evt.timer_set) {
        ngx_del_timer(&ctx->push_evt);
    }

    for (cctx = &ctx->play; *cctx; cctx = &(*cctx)->next) {
        (*cctx)->publish = NULL;
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, (*cctx)->session->connection->log,
            0, "upstream: play disconnect orphan app='%V' name='%V'",
            &(*cctx)->app, &(*cctx)->name);
        ngx_rtmp_finalize_session((*cctx)->session);
    }
    ctx->publish = NULL;

    hash = ngx_hash_key(ctx->name.data, ctx->name.len);
    cctx = &umcf->ctx[hash % umcf->nbuckets];
    for (; *cctx && *cctx != ctx; cctx = &(*cctx)->next);
    if (*cctx) {
        *cctx = ctx->next;
    }
}

