
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Winshining 
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_relay_module.h"


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_delete_stream_pt    next_delete_stream;


static ngx_int_t ngx_rtmp_auto_push_init_process(ngx_cycle_t *cycle);
static void ngx_rtmp_auto_push_exit_process(ngx_cycle_t *cycle);
static void * ngx_rtmp_auto_push_create_conf(ngx_cycle_t *cf);
static char * ngx_rtmp_auto_push_init_conf(ngx_cycle_t *cycle, void *conf);
#if (NGX_HAVE_UNIX_DOMAIN)
static ngx_int_t ngx_rtmp_auto_push_publish(ngx_rtmp_session_t *s,
       ngx_rtmp_publish_t *v);
static ngx_int_t ngx_rtmp_auto_push_delete_stream(ngx_rtmp_session_t *s,
       ngx_rtmp_delete_stream_t *v);
#endif


typedef struct ngx_rtmp_auto_push_ctx_s ngx_rtmp_auto_push_ctx_t;

struct ngx_rtmp_auto_push_ctx_s {
    ngx_int_t                      *slots; /* NGX_MAX_PROCESSES */
    u_char                          name[NGX_RTMP_MAX_NAME];
    u_char                          args[NGX_RTMP_MAX_ARGS];
    ngx_event_t                     push_evt;
};


typedef struct {
    ngx_flag_t                      auto_push;
    ngx_str_t                       socket_dir;
    ngx_msec_t                      push_reconnect;
} ngx_rtmp_auto_push_conf_t;


static ngx_command_t  ngx_rtmp_auto_push_commands[] = {

    { ngx_string("rtmp_auto_push"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_rtmp_auto_push_conf_t, auto_push),
      NULL },

    { ngx_string("rtmp_auto_push_reconnect"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_rtmp_auto_push_conf_t, push_reconnect),
      NULL },

    { ngx_string("rtmp_socket_dir"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_rtmp_auto_push_conf_t, socket_dir),
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_rtmp_auto_push_module_ctx = {
    ngx_string("rtmp_auto_push"),
    ngx_rtmp_auto_push_create_conf,         /* create conf */
    ngx_rtmp_auto_push_init_conf            /* init conf */
};


ngx_module_t  ngx_rtmp_auto_push_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_auto_push_module_ctx,         /* module context */
    ngx_rtmp_auto_push_commands,            /* module directives */
    NGX_CORE_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_rtmp_auto_push_init_process,        /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_rtmp_auto_push_exit_process,        /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_rtmp_module_t  ngx_rtmp_auto_push_index_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_auto_push_index_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_auto_push_index_module_ctx,   /* module context */
    NULL,                                   /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


#define NGX_RTMP_AUTO_PUSH_SOCKNAME         "nginx-http-flv"


static ngx_int_t
ngx_rtmp_auto_push_init_process(ngx_cycle_t *cycle)
{
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_rtmp_auto_push_conf_t   *apcf;
    ngx_listening_t             *ls, *lss;
    struct sockaddr_un          *saun;
#if (nginx_version >= 1009011)
    ngx_event_t                 *rev;
    ngx_connection_t            *c;
    ngx_module_t               **modules;
    ngx_int_t                    i, auto_push_index, event_core_index;
#endif
    int                          reuseaddr;
    ngx_socket_t                 s;
    size_t                       n;
    ngx_file_info_t              fi;
    ngx_pid_t                    pid;

    if (ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    apcf = (ngx_rtmp_auto_push_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                    ngx_rtmp_auto_push_module);
    if (apcf->auto_push == 0) {
        return NGX_OK;
    }

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_auto_push_publish;

    next_delete_stream = ngx_rtmp_delete_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_auto_push_delete_stream;

    reuseaddr = 1;
    s = (ngx_socket_t) -1;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, cycle->log, 0,
            "auto_push: creating sockets");

    /*TODO: clone all RTMP listenings? */
    ls = cycle->listening.elts;
    lss = NULL;
    for (n = 0; n < cycle->listening.nelts; ++n, ++ls) {
        if (ls->handler == ngx_rtmp_init_connection) {
            lss = ls;
            break;
        }
    }

    if (lss == NULL) {
        return NGX_OK;
    }

    ls = ngx_array_push(&cycle->listening);
    if (ls == NULL) {
        return NGX_ERROR;
    }

    *ls = *lss;

    /* Disable unix socket client address extraction
     * from accept call
     * Nginx generates bad addr_text with this enabled */
    ls->addr_ntop = 0;

    ls->socklen = sizeof(struct sockaddr_un);
    saun = ngx_pcalloc(cycle->pool, ls->socklen);
    ls->sockaddr = (struct sockaddr *) saun;
    if (ls->sockaddr == NULL) {
        return NGX_ERROR;
    }
    saun->sun_family = AF_UNIX;
    pid = ngx_getpid();
    *ngx_snprintf((u_char *) saun->sun_path, sizeof(saun->sun_path),
                  "%V/" NGX_RTMP_AUTO_PUSH_SOCKNAME ".%P",
                  &apcf->socket_dir, pid)
        = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, cycle->log, 0,
                   "auto_push: create socket '%s'",
                   saun->sun_path);

    if (ngx_file_info(saun->sun_path, &fi) != ENOENT) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, cycle->log, 0,
                       "auto_push: delete existing socket '%s'",
                       saun->sun_path);
        ngx_delete_file(saun->sun_path);
    }

    ls->addr_text.data = (u_char *) saun->sun_path;
    ls->addr_text.len = ngx_strlen(saun->sun_path);

    s = ngx_socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      ngx_socket_n " %s failed", saun->sun_path);
        return NGX_ERROR;
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                   (const void *) &reuseaddr, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                "setsockopt(SO_REUSEADDR) %s failed", saun->sun_path);
        goto sock_error;
    }

    if (!(ngx_event_flags & NGX_USE_AIO_EVENT)) {
        if (ngx_nonblocking(s) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                          ngx_nonblocking_n " %s failed", saun->sun_path);
            return NGX_ERROR;
        }
    }

    if (bind(s, (struct sockaddr *) saun, sizeof(*saun)) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      ngx_nonblocking_n " %s bind failed", saun->sun_path);
        goto sock_error;
    }

    if (listen(s, NGX_LISTEN_BACKLOG) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "listen() to %s, backlog %d failed",
                      saun->sun_path, NGX_LISTEN_BACKLOG);
        goto sock_error;
    }

    ls->fd = s;
    ls->listen = 1;

    /* Socket option `SO_REUSEPORT` has been supported since nginx-1.9.1,
     * if option `reuseport` is added for the directive `listen`, listening 
     * structure of unix domain socket in the non-first process will not be 
     * initialized, in fact `reuseport` is useless for a unix domain socket 
     * on which there is only a process listening */ 

#if (NGX_HAVE_REUSEPORT)
    ls->reuseport = 0;
#endif

    /* for dynamic module */
#if (nginx_version >= 1009011)
    auto_push_index = -1;
    event_core_index = -1;

    modules = cycle->modules;

    for (i = 0; modules[i]; ++i) {
        if (ngx_strcmp(modules[i]->name, "ngx_event_core_module") == 0) {
            event_core_index = i;
        }

        if (ngx_strcmp(modules[i]->name, "ngx_rtmp_auto_push_module") == 0) {
            auto_push_index = i;
        }

        if (auto_push_index != -1 && event_core_index != -1) {
            break;
        }
    }

    if (auto_push_index > event_core_index) {
        c = ngx_get_connection(ls->fd, cycle->log);
        if (c == NULL) {
            goto sock_error;
        }

        rev = c->read;

#if (nginx_version >= 1009013)
        c->type = ls->type;
#endif
        c->log = &ls->log;

        c->listening = ls;
        ls->connection = c;

        rev->log = c->log;
        rev->accept = 1;

#if (NGX_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls->deferred_accept;
#endif

#if (nginx_version >= 1009013)
        rev->handler = (c->type == SOCK_STREAM) ? ngx_event_accept
                                                : ngx_event_recvmsg;
#else
        rev->handler = ngx_event_accept;
#endif

        if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
#endif

    return NGX_OK;

sock_error:
    if (s != (ngx_socket_t) -1 && ngx_close_socket(s) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                ngx_close_socket_n " %s failed", saun->sun_path);
    }
    ngx_delete_file(saun->sun_path);

    return NGX_ERROR;

#else  /* NGX_HAVE_UNIX_DOMAIN */

    return NGX_OK;

#endif /* NGX_HAVE_UNIX_DOMAIN */
}


static void
ngx_rtmp_auto_push_exit_process(ngx_cycle_t *cycle)
{
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_rtmp_auto_push_conf_t  *apcf;
    u_char                      path[NGX_MAX_PATH];

    ngx_listening_t             *ls;
    ngx_connection_t            *c;
    size_t                       n;
    ngx_pid_t                    pid;

    apcf = (ngx_rtmp_auto_push_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                    ngx_rtmp_auto_push_module);
    if (apcf->auto_push == 0) {
        return;
    }

    ls = cycle->listening.elts;

    for (n = 0; n < cycle->listening.nelts; ++n, ++ls) {
        if ((ls->handler == ngx_rtmp_init_connection) &&
            (ls->sockaddr && ls->sockaddr->sa_family == AF_UNIX))
        {
            c = ls->connection;

            if (c) {
                if (c->read->active) {
                    if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {

                        /*
                         * delete the old accept events that were bound to
                         * the old cycle read events array
                         */

                        ngx_del_event(c->read,
                                      NGX_READ_EVENT, NGX_CLOSE_EVENT);

                        ngx_free_connection(c);

                        c->fd = (ngx_socket_t) -1;
                    }
                }
            }

            if (ngx_close_socket(ls->fd) == -1) {
                ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_socket_errno,
                              ngx_close_socket_n "%V failed",
                              &ls->addr_text);
            }

            ls->fd = (ngx_socket_t) -1;

            break;
        }
    }

    pid = ngx_getpid();
    *ngx_snprintf(path, sizeof(path),
                  "%V/" NGX_RTMP_AUTO_PUSH_SOCKNAME ".%P",
                  &apcf->socket_dir, pid)
         = 0;

    ngx_delete_file(path);

#endif
}


static void *
ngx_rtmp_auto_push_create_conf(ngx_cycle_t *cycle)
{
    ngx_rtmp_auto_push_conf_t       *apcf;

    apcf = ngx_pcalloc(cycle->pool, sizeof(ngx_rtmp_auto_push_conf_t));
    if (apcf == NULL) {
        return NULL;
    }

    apcf->auto_push = NGX_CONF_UNSET;
    apcf->push_reconnect = NGX_CONF_UNSET_MSEC;

    return apcf;
}


static char *
ngx_rtmp_auto_push_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_rtmp_auto_push_conf_t      *apcf = conf;

    ngx_conf_init_value(apcf->auto_push, 0);
    ngx_conf_init_msec_value(apcf->push_reconnect, 100);

    if (apcf->socket_dir.len == 0) {
        ngx_str_set(&apcf->socket_dir, "/tmp");
    }

    return NGX_CONF_OK;
}


#if (NGX_HAVE_UNIX_DOMAIN)
static void
ngx_rtmp_auto_push_reconnect(ngx_event_t *ev)
{
    ngx_rtmp_session_t             *s = ev->data;

    ngx_rtmp_auto_push_conf_t      *apcf;
    ngx_rtmp_auto_push_ctx_t       *ctx;
    ngx_int_t                      *slot;
    ngx_int_t                       n;
    ngx_rtmp_relay_target_t         at;
    u_char                          path[sizeof("unix:") + NGX_MAX_PATH];
    u_char                          flash_ver[sizeof("APSH ,") +
                                              NGX_INT_T_LEN * 2];
    u_char                          play_path[NGX_RTMP_MAX_NAME];
    ngx_str_t                       name;
    u_char                         *p;
    ngx_str_t                      *u;
    ngx_pid_t                       pid;
    ngx_int_t                       npushed;
    ngx_core_conf_t                *ccf;
    ngx_file_info_t                 fi;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "auto_push: reconnect");

    apcf = (ngx_rtmp_auto_push_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                    ngx_rtmp_auto_push_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auto_push_index_module);
    if (ctx == NULL) {
        return;
    }

    name.data = ctx->name;
    name.len = ngx_strlen(name.data);

    ngx_memzero(&at, sizeof(at));
    ngx_str_set(&at.page_url, "nginx-auto-push");
    at.tag = &ngx_rtmp_auto_push_module;

    if (s->app.len) {
        at.app.data = s->app.data;
        at.app.len = s->app.len;
    }

    if (ctx->args[0]) {
        at.play_path.data = play_path;
        at.play_path.len = ngx_snprintf(play_path, sizeof(play_path),
                                        "%s?%s", ctx->name, ctx->args) -
                           play_path;
    }

    slot = ctx->slots;
    npushed = 0;

    for (n = 0; n < NGX_MAX_PROCESSES; ++n, ++slot) {
        if (n == ngx_process_slot) {
            continue;
        }

        pid = ngx_processes[n].pid;
        if (pid == 0 || pid == NGX_INVALID_PID) {
            continue;
        }

        if (*slot) {
            npushed++;
            continue;
        }

        at.data = &ngx_processes[n];

        ngx_memzero(&at.url, sizeof(at.url));
        u = &at.url.url;
        p = ngx_snprintf(path, sizeof(path) - 1,
                         "unix:%V/" NGX_RTMP_AUTO_PUSH_SOCKNAME ".%P",
                         &apcf->socket_dir, pid);
        *p = 0;

        if (ngx_file_info(path + sizeof("unix:") - 1, &fi) != NGX_OK) {
            ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "auto_push: " ngx_file_info_n " failed: "
                           "slot=%i pid=%P socket='%s'" "url='%V' name='%s'",
                           n, pid, path, u, ctx->name);
            continue;
        }

        u->data = path;
        u->len = p - path;
        if (ngx_parse_url(s->connection->pool, &at.url) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "auto_push: auto-push parse_url failed "
                          "url='%V' name='%s'",
                          u, ctx->name);
            continue;
        }

        p = ngx_snprintf(flash_ver, sizeof(flash_ver) - 1, "APSH %i,%i",
                         (ngx_int_t) ngx_process_slot, (ngx_int_t) ngx_pid);
        at.flash_ver.data = flash_ver;
        at.flash_ver.len = p - flash_ver;

        ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "auto_push: connect slot=%i pid=%P socket='%s' name='%s'",
                       n, pid, path, ctx->name);

        if (ngx_rtmp_relay_push(s, &name, &at) == NGX_OK) {
            *slot = 1;
            npushed++;
            continue;
        }

        ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                      "auto_push: connect failed: slot=%i pid=%P socket='%s'"
                      "url='%V' name='%s'",
                      n, pid, path, u, ctx->name);
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "auto_push: pushed=%i total=%i failed=%i",
                   npushed, ccf->worker_processes,
                   ccf->worker_processes - 1 - npushed);

    if (ccf->worker_processes == npushed + 1) {
        return;
    }

    /* several workers failed */

    slot = ctx->slots;

    for (n = 0; n < NGX_MAX_PROCESSES; ++n, ++slot) {
        pid = ngx_processes[n].pid;

        if (n == ngx_process_slot || *slot == 1 ||
            pid == 0 || pid == NGX_INVALID_PID)
        {
            continue;
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "auto_push: connect failed: slot=%i pid=%P name='%s'",
                      n, pid, ctx->name);
    }

    if (!ctx->push_evt.timer_set) {
        ngx_add_timer(&ctx->push_evt, apcf->push_reconnect);
    }
}


static ngx_int_t
ngx_rtmp_auto_push_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_auto_push_conf_t      *apcf;
    ngx_rtmp_auto_push_ctx_t       *ctx;

    if (s->auto_pushed || (s->relay && !s->static_relay)) {
        goto next;
    }

    apcf = (ngx_rtmp_auto_push_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                    ngx_rtmp_auto_push_module);
    if (apcf->auto_push == 0) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auto_push_index_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool,
                         sizeof(ngx_rtmp_auto_push_ctx_t));
        if (ctx == NULL) {
            goto next;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_auto_push_index_module);

    }
    ngx_memzero(ctx, sizeof(*ctx));

    ctx->push_evt.data = s;
    ctx->push_evt.log = s->connection->log;
    ctx->push_evt.handler = ngx_rtmp_auto_push_reconnect;

    ctx->slots = ngx_pcalloc(s->connection->pool,
                             sizeof(ngx_int_t) * NGX_MAX_PROCESSES);
    if (ctx->slots == NULL) {
        goto next;
    }

    ngx_memcpy(ctx->name, v->name, sizeof(ctx->name));
    ngx_memcpy(ctx->args, v->args, sizeof(ctx->args));

    ngx_rtmp_auto_push_reconnect(&ctx->push_evt);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_auto_push_delete_stream(ngx_rtmp_session_t *s,
    ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_auto_push_conf_t      *apcf;
    ngx_rtmp_auto_push_ctx_t       *ctx, *pctx;
    ngx_rtmp_relay_ctx_t           *rctx;
    ngx_int_t                       slot;

    apcf = (ngx_rtmp_auto_push_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                    ngx_rtmp_auto_push_module);
    if (apcf->auto_push == 0) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auto_push_index_module);
    if (ctx) {
        if (ctx->push_evt.timer_set) {
            ngx_del_timer(&ctx->push_evt);
        }
        goto next;
    }

    /* skip non-relays & publishers */
    rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (rctx == NULL ||
        rctx->tag != &ngx_rtmp_auto_push_module ||
        rctx->publish == NULL)
    {
        goto next;
    }

    slot = (ngx_process_t *) rctx->data - &ngx_processes[0];

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "auto_push: disconnect slot=%i app='%V' name='%V'",
                   slot, &rctx->app, &rctx->name);

    pctx = ngx_rtmp_get_module_ctx(rctx->publish->session,
                                   ngx_rtmp_auto_push_index_module);
    if (pctx == NULL) {
        goto next;
    }

    pctx->slots[slot] = 0;

    /* push reconnect */
    if (!pctx->push_evt.timer_set) {
        ngx_add_timer(&pctx->push_evt, apcf->push_reconnect);
    }

next:
    return next_delete_stream(s, v);
}
#endif /* NGX_HAVE_UNIX_DOMAIN */
