
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Winshining
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_proxy_protocol.h"


static void ngx_rtmp_close_connection(ngx_connection_t *c);

static void ngx_rtmp_process_unix_socket(ngx_rtmp_connection_t *rconn);

static void ngx_rtmp_set_lingering_close(ngx_rtmp_session_t *s);
static void ngx_rtmp_lingering_close_handler(ngx_event_t *rev);
static void ngx_rtmp_empty_handler(ngx_event_t *wev);

extern ngx_module_t        ngx_rtmp_auto_push_module;


void
ngx_rtmp_init_connection(ngx_connection_t *c)
{
    ngx_uint_t                 i;
    ngx_rtmp_port_t           *port;
    struct sockaddr_in        *sin;
    ngx_rtmp_in_addr_t        *addr;
    ngx_rtmp_connection_t     *rconn;
    ngx_rtmp_session_t        *s;
    struct sockaddr_un        *saun;
    u_char                    *un;
    size_t                     unlen;
    ngx_int_t                  unix_socket;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    ngx_rtmp_in6_addr_t       *addr6;
#endif

    rconn = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_connection_t));
    if (rconn == NULL) {
        ngx_rtmp_close_connection(c);
        return;
    }

    ++ngx_rtmp_naccepted;

    c->data = rconn;

    /* find the server configuration for the address:port */

    port = c->listening->servers;
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
            ngx_rtmp_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            rconn->addr_conf = &addr6[i].conf;

            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

            ngx_rtmp_process_unix_socket(rconn);

            break;

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            rconn->addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            rconn->addr_conf = &addr6[0].conf;
            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

            ngx_rtmp_process_unix_socket(rconn);

            break;

        default: /* AF_INET */
            addr = port->addrs;
            rconn->addr_conf = &addr[0].conf;
            break;
        }
    }

    /* the default server configuration for the address:port */
    rconn->conf_ctx = rconn->addr_conf->default_server->ctx;

    if (unix_socket) {
        saun = (struct sockaddr_un *) c->local_sockaddr;
        unlen = sizeof("unix:") + ngx_strlen(saun->sun_path) + 1;
        un = ngx_pcalloc(c->pool, unlen);

        *ngx_snprintf(un, unlen, "unix:%s", saun->sun_path) = 0;

        rconn->addr_conf->addr_text.data = un;
        rconn->addr_conf->addr_text.len = ngx_strlen(un);
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client connected '%V'",
                  c->number, &c->addr_text);

    s = ngx_rtmp_init_session(c, rconn->addr_conf);
    if (s == NULL) {
        return;
    }

    /* only auto-pushed connections are
     * done through unix socket */

    s->auto_pushed = unix_socket;

    if (rconn->proxy_protocol) {
        ngx_rtmp_proxy_protocol(s);

    } else {
        ngx_rtmp_handshake(s);
    }
}


ngx_rtmp_session_t *
ngx_rtmp_init_session(ngx_connection_t *c, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_rtmp_session_t             *s;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_error_log_ctx_t       *ctx;

    s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t));
    if (s == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    s->signature = NGX_RTMP_MODULE;
    s->rtmp_connection = c->data;

    s->main_conf = addr_conf->default_server->ctx->main_conf;
    s->srv_conf = addr_conf->default_server->ctx->srv_conf;
    s->app_conf = addr_conf->default_server->ctx->app_conf;

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    ctx = ngx_palloc(c->pool, sizeof(ngx_rtmp_error_log_ctx_t));
    if (ctx == NULL) {
        ngx_rtmp_close_connection(c);
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
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    s->out_pool = ngx_create_pool(4096, c->log);
    if (s->out_pool == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    s->out = ngx_pcalloc(s->out_pool, sizeof(ngx_chain_t *)
                         * ((ngx_rtmp_core_srv_conf_t *)
                            addr_conf->default_server->ctx->srv_conf
                            [ngx_rtmp_core_module.ctx_index])->out_queue);
    if (s->out == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    s->in_streams_pool = ngx_create_pool(4096, c->log);
    if (s->in_streams_pool == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(s->in_streams_pool, sizeof(ngx_rtmp_stream_t)
            * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

#if (nginx_version >= 1007005)
    ngx_queue_init(&s->posted_dry_events);
#endif

    s->epoch = ngx_current_msec;
    s->timeout = cscf->timeout;
    s->buflen = cscf->buflen;
    s->uri_changes = NGX_RTMP_MAX_URI_CHANGES + 1;
    ngx_rtmp_set_chunk_size(s, NGX_RTMP_DEFAULT_CHUNK_SIZE);

    if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    return s;
}


u_char *
ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_error_log_ctx_t   *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", server: %V", s->addr_text);
    len -= p - buf;
    buf = p;

    return p;
}


static void
ngx_rtmp_close_connection(ngx_connection_t *c)
{
    ngx_pool_t                         *pool;
    ngx_rtmp_session_t                 *s;
    ngx_rtmp_core_srv_conf_t           *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "close connection");

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    s = c->data;

    if (s->signature == NGX_RTMP_MODULE) {
        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

        while (s->out_pos != s->out_last) {
            ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos++]);
            s->out_pos %= s->out_queue;
        }

        if (s->out_pool) {
            ngx_destroy_pool(s->out_pool);
        }
    }

    pool = c->pool;
    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}


static void
ngx_rtmp_close_session_handler(ngx_event_t *e)
{
    ngx_rtmp_session_t                 *s;
    ngx_connection_t                   *c;
    ngx_rtmp_core_app_conf_t           *cacf;

    s = e->data;
    c = s->connection;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "close session");

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

    if (s->in_streams_pool) {
        ngx_destroy_pool(s->in_streams_pool);
    }

    if (cacf->lingering_close == NGX_RTMP_LINGERING_ALWAYS
        || (cacf->lingering_close == NGX_RTMP_LINGERING_ON
            && (s->lingering_close || s->connection->read->ready)))
    {
        ngx_rtmp_set_lingering_close(s);
        return;
    }

    ngx_rtmp_close_connection(c);
}


void
ngx_rtmp_finalize_session(ngx_rtmp_session_t *s)
{
    ngx_event_t        *e;
    ngx_connection_t   *c;

    c = s->connection;
    if (c->destroyed) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "finalize session");

    c->destroyed = 1;
    e = &s->close;
    e->data = s;
    e->handler = ngx_rtmp_close_session_handler;
    e->log = c->log;

    ngx_post_event(e, &ngx_posted_events);
}

static void
ngx_rtmp_process_unix_socket(ngx_rtmp_connection_t *rconn)
{
    ngx_uint_t                 i;
    ngx_rtmp_port_t           *port;
    struct sockaddr_in        *sin;
    ngx_rtmp_in_addr_t        *addr;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    ngx_rtmp_in6_addr_t       *addr6;
#endif
    ngx_listening_t           *ls;

    ls = ngx_cycle->listening.elts;
    for (i = 0; i < ngx_cycle->listening.nelts; ++i, ++ls) {
        if (ls->handler == ngx_rtmp_init_connection) {
            break;
        }
    }

    port = ls->servers;

    if (port->naddrs > 1) {
        switch (ls->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) ls->sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            rconn->addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) ls->sockaddr;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            rconn->addr_conf = &addr[i].conf;
        }
    } else {
        switch (ls->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            rconn->addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            rconn->addr_conf = &addr[0].conf;
        }
    }
}


static void
ngx_rtmp_set_lingering_close(ngx_rtmp_session_t *s)
{
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_rtmp_core_app_conf_t  *cacf;

    c = s->connection;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

    rev = c->read;
    rev->handler = ngx_rtmp_lingering_close_handler;

    s->lingering_time = ngx_time() + (time_t) (cacf->lingering_time / 1000);
    ngx_add_timer(rev, cacf->lingering_timeout);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_rtmp_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = ngx_rtmp_empty_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_rtmp_close_connection(c);
            return;
        }
    }

    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_connection_error(c, ngx_socket_errno,
                             ngx_shutdown_socket_n " failed");
        ngx_rtmp_close_connection(c);
        return;
    }

    if (rev->ready) {
        ngx_rtmp_lingering_close_handler(rev);
    }
}


static void
ngx_rtmp_lingering_close_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_msec_t                 timer;
    ngx_connection_t          *c;
    ngx_rtmp_session_t        *s;
    ngx_rtmp_core_app_conf_t  *cacf;
    u_char                     buffer[NGX_RTMP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                   "rtmp lingering close handler");

    if (rev->timedout) {
        ngx_rtmp_close_connection(c);
        return;
    }

    timer = (ngx_msec_t) s->lingering_time - (ngx_msec_t) ngx_time();
    if ((ngx_msec_int_t) timer <= 0) {
        ngx_rtmp_close_connection(c);
        return;
    }

    do {
        n = c->recv(c, buffer, NGX_RTMP_LINGERING_BUFFER_SIZE);

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0, "lingering read: %z", n);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_close_connection(c);
            return;
        }

    } while (rev->ready);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_rtmp_close_connection(c);
        return;
    }

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

    timer *= 1000;

    if (timer > cacf->lingering_timeout) {
        timer = cacf->lingering_timeout;
    }

    ngx_add_timer(rev, timer);
}

static void
ngx_rtmp_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, wev->log, 0, "rtmp empty handler");

    return;
}

