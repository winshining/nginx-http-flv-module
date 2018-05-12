
/*
 * Copyright (C) Gnolizuh
 * Copyright (C) Winshining
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_flv_live_module.h"
#include "ngx_rtmp_gop_cache_module.h"


static ngx_rtmp_publish_pt       next_publish;
static ngx_rtmp_play_pt          next_play;
static ngx_rtmp_close_stream_pt  next_close_stream;


static ngx_rtmp_gop_frame_t *ngx_rtmp_gop_cache_alloc_frame(
    ngx_rtmp_session_t *s);
static ngx_rtmp_gop_frame_t *ngx_rtmp_gop_cache_free_frame(
    ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame);
static ngx_int_t ngx_rtmp_gop_cache_link_frame(ngx_rtmp_session_t *s,
    ngx_rtmp_gop_frame_t *frame);
static ngx_int_t ngx_rtmp_gop_cache_alloc_cache(ngx_rtmp_session_t *s);
static ngx_rtmp_gop_cache_t *ngx_rtmp_gop_cache_free_cache(
    ngx_rtmp_session_t *s, ngx_rtmp_gop_cache_t *cache);
static void ngx_rtmp_gop_cache_cleanup(ngx_rtmp_session_t *s);
static void ngx_rtmp_gop_cache_update(ngx_rtmp_session_t *s);
static void ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio,
    ngx_rtmp_header_t *ch, ngx_chain_t *frame);
static void ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *s);
static void ngx_rtmp_gop_cache_init_handler(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_gop_cache_av(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_gop_cache_publish(ngx_rtmp_session_t *s,
    ngx_rtmp_publish_t *v);
static ngx_int_t ngx_rtmp_gop_cache_play(ngx_rtmp_session_t *s,
    ngx_rtmp_play_t *v);
static ngx_int_t ngx_rtmp_gop_cache_close_stream(ngx_rtmp_session_t *s,
    ngx_rtmp_close_stream_t *v);


static ngx_chain_t *ngx_rtmp_gop_cache_append_shared_bufs(
    ngx_rtmp_gop_cache_ctx_t *ctx, ngx_chain_t *head, ngx_chain_t *in);
static ngx_chain_t *ngx_rtmp_gop_cache_alloc_shared_buf(
    ngx_rtmp_gop_cache_ctx_t *ctx);
static void ngx_rtmp_gop_cache_free_shared_chain(ngx_rtmp_gop_cache_ctx_t *ctx,
    ngx_chain_t *in);

static ngx_chain_t *ngx_hfl_gop_cache_meta_message(ngx_rtmp_session_t *s,
    ngx_chain_t *in);
static ngx_chain_t *ngx_hfl_gop_cache_append_message(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in);
static ngx_chain_t *ngx_hfl_gop_cache_append_shared_bufs(
    ngx_rtmp_gop_cache_ctx_t *ctx, ngx_rtmp_header_t *h, ngx_chain_t *in,
    ngx_flag_t chunked);
static void ngx_hfl_gop_cache_free_message(ngx_rtmp_session_t *s,
    ngx_chain_t *in);


static ngx_chain_t *ngx_rl_gop_cache_meta_message(ngx_rtmp_session_t *s,
    ngx_chain_t *in);
static ngx_chain_t *ngx_rl_gop_cache_append_message(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in);
static void ngx_rl_gop_cache_free_message(ngx_rtmp_session_t *s,
    ngx_chain_t *in);


static ngx_int_t ngx_rtmp_gop_cache_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_gop_cache_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_gop_cache_merge_app_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_rtmp_gop_cache_proc_handler_t  ngx_rl_gop_cache_proc_handler = {
    ngx_rtmp_live_send_message,
    ngx_rl_gop_cache_meta_message,
    ngx_rl_gop_cache_append_message,
    ngx_rl_gop_cache_free_message
};

static ngx_rtmp_gop_cache_proc_handler_t  ngx_hfl_gop_cache_proc_handler = {
    ngx_http_flv_live_send_message,
    ngx_hfl_gop_cache_meta_message,
    ngx_hfl_gop_cache_append_message,
    ngx_hfl_gop_cache_free_message
};

ngx_rtmp_gop_cache_proc_handler_t  *ngx_rtmp_gop_cache_proc_handlers[] = {
     &ngx_rl_gop_cache_proc_handler,
     &ngx_hfl_gop_cache_proc_handler
};

extern ngx_module_t                 ngx_http_flv_live_module;


static ngx_command_t ngx_rtmp_gop_cache_commands[] = {
    { ngx_string("gop_cache"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_cache),
      NULL },

    { ngx_string("gop_max_frame_count"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_max_frame_count),
      NULL },

    { ngx_string("gop_max_video_count"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_max_video_count),
      NULL },

    { ngx_string("gop_max_audio_count"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_max_audio_count),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t ngx_rtmp_gop_cache_module_ctx = {
    NULL,
    ngx_rtmp_gop_cache_postconfiguration, /* postconfiguration */
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_rtmp_gop_cache_create_app_conf,   /* create application configuration */
    ngx_rtmp_gop_cache_merge_app_conf     /* merge application configuration */
};


ngx_module_t ngx_rtmp_gop_cache_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_gop_cache_module_ctx,
    ngx_rtmp_gop_cache_commands,
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


static void *
ngx_rtmp_gop_cache_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_gop_cache_app_conf_t *gacf;

    gacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_gop_cache_app_conf_t));
    if (gacf == NULL) {
        return NULL;
    }

    gacf->gop_cache = NGX_CONF_UNSET;
    gacf->gop_cache_count = NGX_CONF_UNSET_SIZE;
    gacf->gop_max_frame_count = NGX_CONF_UNSET_SIZE;
    gacf->gop_max_audio_count = NGX_CONF_UNSET_SIZE;
    gacf->gop_max_video_count = NGX_CONF_UNSET_SIZE;

    return (void *) gacf;
}


static char *
ngx_rtmp_gop_cache_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_gop_cache_app_conf_t        *prev = parent;
    ngx_rtmp_gop_cache_app_conf_t        *conf = child;

    ngx_conf_merge_value(conf->gop_cache, prev->gop_cache, 0);
    ngx_conf_merge_size_value(conf->gop_cache_count, prev->gop_cache_count, 2);
    ngx_conf_merge_size_value(conf->gop_max_frame_count,
            prev->gop_max_frame_count, 2048);
    ngx_conf_merge_size_value(conf->gop_max_audio_count,
            prev->gop_max_audio_count, 1024);
    ngx_conf_merge_size_value(conf->gop_max_video_count,
            prev->gop_max_video_count, 1024);
    
    return NGX_CONF_OK;
}


static ngx_rtmp_gop_frame_t *
ngx_rtmp_gop_cache_alloc_frame(ngx_rtmp_session_t *s)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_frame_t           *frame;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->free_frame) {
        frame = ctx->free_frame;
        ctx->free_frame = frame->next;

        return frame;
    }

    frame = ngx_pcalloc(ctx->pool, sizeof(ngx_rtmp_gop_frame_t));

    return frame;
}


static ngx_rtmp_gop_frame_t *
ngx_rtmp_gop_cache_free_frame(ngx_rtmp_session_t *s,
    ngx_rtmp_gop_frame_t *frame)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    if (frame->frame) {
        ngx_rtmp_gop_cache_free_shared_chain(ctx, frame->frame);
        frame->frame = NULL;
    }

    if (frame->h.type == NGX_RTMP_MSG_VIDEO) {
        ctx->video_frame_in_all--;
    } else if (frame->h.type == NGX_RTMP_MSG_AUDIO) {
        ctx->audio_frame_in_all--;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "gop free frame: type='%s' video_frame_in_cache='%uD' "
           "audio_frame_in_cache='%uD'",
           frame->h.type == NGX_RTMP_MSG_VIDEO ? "video" : "audio",
           ctx->video_frame_in_all, ctx->audio_frame_in_all);

    return frame->next;
}


static ngx_int_t
ngx_rtmp_gop_cache_link_frame(ngx_rtmp_session_t *s,
    ngx_rtmp_gop_frame_t *frame)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache;
    ngx_rtmp_gop_frame_t          **iter;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    cache = ctx->cache_tail;
    if (cache == NULL) {
        return NGX_ERROR;
    }

    if(cache->frame_head == NULL) {
        cache->frame_head = cache->frame_tail = frame;
    } else {
        iter = &cache->frame_tail->next;
        *iter = frame;
        cache->frame_tail = frame;
    }

    if (frame->h.type == NGX_RTMP_MSG_VIDEO) {
        ctx->video_frame_in_all++;
        cache->video_frame_in_this++;
    } else if(frame->h.type == NGX_RTMP_MSG_AUDIO) {
        ctx->audio_frame_in_all++;
        cache->audio_frame_in_this++;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "gop link frame: type='%s' "
            "ctx->video_frame_in_all='%uD' "
            "ctx->audio_frame_in_all='%uD' "
            "cache->video_frame_in_this='%uD' "
            "cache->audio_frame_in_this='%uD'",
            frame->h.type == NGX_RTMP_MSG_VIDEO ? "video" : "audio",
            ctx->video_frame_in_all, ctx->audio_frame_in_all,
            cache->video_frame_in_this, cache->audio_frame_in_this);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_gop_cache_alloc_cache(ngx_rtmp_session_t *s)
{
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache, **iter;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->free_cache) {
        cache = ctx->free_cache;
        ctx->free_cache = cache->next;

        ngx_memzero(cache, sizeof(ngx_rtmp_gop_cache_t));
    } else {
        cache = ngx_pcalloc(ctx->pool, sizeof(ngx_rtmp_gop_cache_t));
        if (cache == NULL) {
            return NGX_ERROR;
        }
    }

    // save video seq header.
    if (codec_ctx->avc_header && ctx->video_seq_header == NULL) {
        ctx->video_seq_header = codec_ctx->avc_header;
    }

    // save audio seq header.
    if (codec_ctx->aac_header && ctx->audio_seq_header == NULL) {
        ctx->audio_seq_header = codec_ctx->aac_header;
    }

    // save metadata.
    if (codec_ctx->meta && ctx->meta == NULL) {
        ctx->meta_version = codec_ctx->meta_version;
        ctx->meta = codec_ctx->meta;
    }

    if (ctx->cache_head == NULL) {
        ctx->cache_tail = ctx->cache_head = cache;
    } else {
        iter = &ctx->cache_tail->next;
        *iter = cache;
        ctx->cache_tail = cache;
    }

    ctx->gop_cache_count++;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "gop alloc cache: gop_cache_count='%uD'", ctx->gop_cache_count);

    return NGX_OK;
}


static ngx_rtmp_gop_cache_t *
ngx_rtmp_gop_cache_free_cache(ngx_rtmp_session_t *s,
    ngx_rtmp_gop_cache_t *cache)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_frame_t           *frame;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    for (frame = cache->frame_head; frame; frame = frame->next) {
        ngx_rtmp_gop_cache_free_frame(s, frame);
    }

    cache->video_frame_in_this = 0;
    cache->audio_frame_in_this = 0;

    // recycle mem of gop frame
    cache->frame_head->next = ctx->free_frame;
    ctx->free_frame = cache->frame_head;

    ctx->gop_cache_count--;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "gop free cache: gop_cache_count='%uD'", ctx->gop_cache_count);

    return cache->next;
}


static void
ngx_rtmp_gop_cache_cleanup(ngx_rtmp_session_t *s)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }

    for (cache = ctx->cache_head; cache; cache = cache->next) {
        ngx_rtmp_gop_cache_free_cache(s, cache);
    }

    if (ctx->pool) {
        ngx_destroy_pool(ctx->pool);
        ctx->pool = NULL;
    }

    ctx->video_seq_header = NULL;
    ctx->audio_seq_header = NULL;
    ctx->meta = NULL;

    ctx->cache_tail = ctx->cache_head = NULL;
    ctx->gop_cache_count = 0;
    ctx->free_cache = NULL;
    ctx->free_frame = NULL;
    ctx->video_frame_in_all = 0;
    ctx->audio_frame_in_all = 0;
}


static void
ngx_rtmp_gop_cache_update(ngx_rtmp_session_t *s)
{
    ngx_rtmp_gop_cache_app_conf_t        *gacf;
    ngx_rtmp_gop_cache_ctx_t             *ctx;
    ngx_rtmp_gop_cache_t                 *next;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }

    while (ctx->gop_cache_count > gacf->gop_cache_count) {
        if (ctx->cache_head) {
            /* remove the 1st gop */
            next = ngx_rtmp_gop_cache_free_cache(s, ctx->cache_head);

            ctx->cache_head->next = ctx->free_cache;
            ctx->free_cache = ctx->cache_head;

            ctx->cache_head = next;
        }
    }
}


static void
ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio,
    ngx_rtmp_header_t *ch, ngx_chain_t *frame)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_gop_frame_t           *gf;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return;
    }

    if (ch->type == NGX_RTMP_MSG_VIDEO) {
        // drop video when not H.264
        if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "drop video non-H.264 encode type timestamp='%uD'",
                    ch->timestamp);

            return;
        }

        // drop non-IDR
        if (prio != NGX_RTMP_VIDEO_KEY_FRAME && ctx->cache_head == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "drop video non-keyframe timestamp='%uD'",
                    ch->timestamp);

            return;
        }
    }

    // pure audio
    if (ctx->video_frame_in_all == 0 && ch->type == NGX_RTMP_MSG_AUDIO) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "drop audio frame timestamp='%uD'",
                    ch->timestamp);

        return;
    }

    if (ch->type == NGX_RTMP_MSG_VIDEO && prio == NGX_RTMP_VIDEO_KEY_FRAME) {
        if (ngx_rtmp_gop_cache_alloc_cache(s) != NGX_OK) {
            return;
        }
    }

    gf = ngx_rtmp_gop_cache_alloc_frame(s);
    if (gf == NULL) {
        return;
    }

    gf->h = *ch;
    gf->prio = prio;
    gf->next = NULL;
    gf->frame = ngx_rtmp_gop_cache_append_shared_bufs(ctx, NULL, frame);

    if (ngx_rtmp_gop_cache_link_frame(s, gf) != NGX_OK) {
        ngx_rtmp_gop_cache_free_shared_chain(ctx, gf->frame);
        return;
    }

    if (ctx->video_frame_in_all > gacf->gop_max_video_count ||
        ctx->audio_frame_in_all > gacf->gop_max_audio_count ||
        (ctx->video_frame_in_all + ctx->audio_frame_in_all)
        > gacf->gop_max_frame_count)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
               "gop cache: video_frame_in_cache='%uD' "
               "audio_frame_in_cache='%uD' max_video_count='%uD' "
               "max_audio_count='%uD' gop_max_frame_count='%uD'",
               ctx->video_frame_in_all, ctx->audio_frame_in_all,
               gacf->gop_max_video_count, gacf->gop_max_audio_count,
               gacf->gop_max_frame_count);

        ngx_rtmp_gop_cache_cleanup(s);
        return;
    }

    ngx_rtmp_gop_cache_update(s);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "gop cache: cache packet type='%s' timestamp='%uD'",
           gf->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
           gf->h.timestamp);
}


static void
ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *s)
{
    ngx_rtmp_session_t                 *rs;
    ngx_chain_t                        *pkt, *apkt, *meta, *header;
    ngx_rtmp_live_ctx_t                *ctx, *pub_ctx;
    ngx_http_flv_live_ctx_t            *hflctx;
    ngx_rtmp_gop_cache_ctx_t           *gctx;
    ngx_rtmp_live_app_conf_t           *lacf;
    ngx_rtmp_gop_cache_t               *cache;
    ngx_rtmp_gop_frame_t               *gf;
    ngx_rtmp_header_t                   ch, lh;
    ngx_uint_t                          meta_version;
    uint32_t                            delta;
    ngx_int_t                           csidx;
    ngx_rtmp_live_chunk_stream_t       *cs;
    ngx_rtmp_gop_cache_proc_handler_t  *handler;
    ngx_http_request_t                 *r;

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return;
    }

    /* pub_ctx saved the publisher info */
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL ||
        ctx->stream->pub_ctx == NULL || !ctx->stream->publishing) {
        return;
    }

    pkt = NULL;
    apkt = NULL;
    header = NULL;
    meta = NULL;
    meta_version = 0;

    pub_ctx = ctx->stream->pub_ctx;
    rs = pub_ctx->session;
    s->publisher = rs;
    handler = ngx_rtmp_gop_cache_proc_handlers[ctx->protocol];

    gctx = ngx_rtmp_get_module_ctx(rs, ngx_rtmp_gop_cache_module);
    if (gctx == NULL) {
        return;
    }

    for (cache = gctx->cache_head; cache; cache = cache->next) {
        if (ctx->protocol == NGX_RTMP_PROTOCOL_HTTP) {
            r = s->data;
            if (r == NULL || (r->connection && r->connection->destroyed)) {
                return;
            }

            hflctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
            if (!hflctx->header_sent) {
                hflctx->header_sent = 1;
                ngx_http_flv_live_send_header(s);
            }
        }

        if (meta == NULL && meta_version != gctx->meta_version) {
            meta = handler->meta_message_pt(s, gctx->meta);
            if (meta == NULL) {
                return;
            }
        }

        if (meta) {
            meta_version = gctx->meta_version;
        }

        /* send metadata */
        if (meta && meta_version != ctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "gop cache send: meta");

            ngx_rtmp_gop_cache_init_handler(s);

            if (handler->send_message_pt(s, meta, 0) == NGX_ERROR) {
                ngx_rtmp_finalize_session(s);
                return;
            }

            ctx->meta_version = meta_version;
            handler->free_message_pt(s, meta);
        }

        for (gf = cache->frame_head; gf; gf = gf->next) {
            csidx = !(lacf->interleave || gf->h.type == NGX_RTMP_MSG_VIDEO);

            cs = &ctx->cs[csidx];

            lh = ch = gf->h;

            if (cs->active) {
                lh.timestamp = cs->timestamp;
            }

            delta = ch.timestamp - lh.timestamp;

            if (!cs->active) {
                switch (gf->h.type) {
                    case NGX_RTMP_MSG_VIDEO:
                        header = gctx->video_seq_header;
                        break;
                    default:
                        header = gctx->audio_seq_header;
                }

                if (header) {
                    apkt = handler->append_message_pt(s, &lh, NULL, header);
                    if (apkt == NULL) {
                        return;
                    }

                    ngx_rtmp_gop_cache_init_handler(s);
                }

                if (apkt && handler->send_message_pt(s, apkt, 0) != NGX_ERROR)
                {
                    cs->timestamp = lh.timestamp;
                    cs->active = 1;
                    s->current_time = cs->timestamp;
                }
            }

            pkt = handler->append_message_pt(s, &ch, &lh, gf->frame);
            if (pkt == NULL) {
                return;
            }

            ngx_rtmp_gop_cache_init_handler(s);

            if (handler->send_message_pt(s, pkt, gf->prio) == NGX_ERROR)
            {
                ++pub_ctx->ndropped;

                cs->dropped += delta;

                ngx_rtmp_finalize_session(s);
                return;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "gop cache send: tag type='%s' prio='%d' ctimestamp='%uD' "
                    "ltimestamp='%uD'",
                    gf->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
                    gf->prio, ch.timestamp, lh.timestamp);

            cs->timestamp += delta;
            s->current_time = cs->timestamp;

            if (pkt) {
                handler->free_message_pt(s, pkt);
                pkt = NULL;
            }

            if (apkt) {
                handler->free_message_pt(s, apkt);
                apkt = NULL;
            }
        }
    }
}


static void
ngx_rtmp_gop_cache_init_handler(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    s->gop_cache.out[s->out_last].set = 1;
    s->gop_cache.count++;

    if (ctx->protocol == NGX_RTMP_PROTOCOL_RTMP) {
        s->gop_cache.out[s->out_last].free = ngx_rl_gop_cache_free_message;
    } else {
        s->gop_cache.out[s->out_last].free = ngx_hfl_gop_cache_free_message;
    }
}


static ngx_int_t
ngx_rtmp_gop_cache_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_header_t               ch;
    ngx_uint_t                      prio;
    ngx_uint_t                      csidx;
    ngx_rtmp_live_chunk_stream_t   *cs;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        return NGX_OK;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
        return NGX_OK;
    }

    if (in == NULL || in->buf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (ctx->publishing == 0) {
        return NGX_OK;
    }

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
           ngx_rtmp_get_video_frame_type(in) : 0);

    csidx = !(lacf->interleave || h->type == NGX_RTMP_MSG_VIDEO);

    cs = &ctx->cs[csidx];

    ngx_memzero(&ch, sizeof(ch));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;

    ngx_rtmp_gop_cache_frame(s, prio, &ch, in);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_gop_cache_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "gop cache publish: name='%s' type='%s'",
                  v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool,
                sizeof(ngx_rtmp_gop_cache_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_gop_cache_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    if (ctx->pool == NULL) {
        ctx->pool = ngx_create_pool(NGX_GOP_CACHE_POOL_CREATE_SIZE,
                                    s->connection->log);

        if (ctx->pool == NULL) {
            return NGX_ERROR;
        }
    }

    ctx->chunk_size = cscf->chunk_size;

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_gop_cache_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
#ifdef NGX_DEBUG
    ngx_msec_t                      start, end;
#endif

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool,
                         sizeof(ngx_rtmp_gop_cache_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_gop_cache_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

    if (ctx->pool == NULL) {
        ctx->pool = ngx_create_pool(NGX_GOP_CACHE_POOL_CREATE_SIZE,
                                    s->connection->log);
        if (ctx->pool == NULL) {
            return NGX_ERROR;
        }
    }

    ctx->chunk_size = cscf->chunk_size;

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "gop cache play: name='%s' start='%i' duration='%i' reset='%d'",
            v->name, (ngx_int_t) v->start,
            (ngx_int_t) v->duration, (ngx_uint_t) v->reset);

#ifdef NGX_DEBUG
    start = ngx_current_msec;
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "gop cache send: start_time='%uD'", start);
#endif

    ngx_rtmp_gop_cache_send(s);

#ifdef NGX_DEBUG
    end = ngx_current_msec;
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "gop cache send: end_time='%uD'", end);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "gop cache send: delta_time='%uD'", end - start);
#endif

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_gop_cache_close_stream(ngx_rtmp_session_t *s,
    ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_gop_cache_ctx_t       *gctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->publishing == 0) {
        gctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
        if (gctx && gctx->pool) {
            ngx_destroy_pool(gctx->pool);
            gctx->pool = NULL;
        }

        goto next;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL || !lacf->live) {
        goto next;
    }

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    ngx_rtmp_gop_cache_cleanup(s);

next:
    return next_close_stream(s, v);
}


static ngx_chain_t *
ngx_rtmp_gop_cache_append_shared_bufs(ngx_rtmp_gop_cache_ctx_t *ctx,
    ngx_chain_t *head, ngx_chain_t *in)
{
    ngx_chain_t                    *l, **ll;
    u_char                         *p;
    size_t                          size;

    ll = &head;
    p = in->buf->pos;
    l = head;

    if (l) {
        for(; l->next; l = l->next);
        ll = &l->next;
    }

    for ( ;; ) {

        if (l == NULL || l->buf->last == l->buf->end) {
            l = ngx_rtmp_gop_cache_alloc_shared_buf(ctx);
            if (l == NULL || l->buf == NULL) {
                break;
            }

            *ll = l;
            ll = &l->next;
        }

        while (l->buf->end - l->buf->last >= in->buf->last - p) {
            l->buf->last = ngx_cpymem(l->buf->last, p,
                                      in->buf->last - p);
            in = in->next;
            if (in == NULL) {
                goto done;
            }
            p = in->buf->pos;
        }

        size = l->buf->end - l->buf->last;
        l->buf->last = ngx_cpymem(l->buf->last, p, size);
        p += size;
    }

done:
    *ll = NULL;

    return head;
}


static ngx_chain_t *
ngx_rtmp_gop_cache_alloc_shared_buf(ngx_rtmp_gop_cache_ctx_t *ctx)
{
    u_char                     *p;
    ngx_chain_t                *out;
    ngx_buf_t                  *b;
    size_t                      size;

    if (ctx->free) {
        out = ctx->free;
        ctx->free = out->next;

    } else {

        size = ctx->chunk_size + NGX_RTMP_MAX_CHUNK_HEADER;

        p = ngx_pcalloc(ctx->pool, NGX_RTMP_REFCOUNT_BYTES
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
    b->pos = b->last = b->start + NGX_RTMP_MAX_CHUNK_HEADER;
    b->memory = 1;

    /* buffer has refcount =1 when created! */
    ngx_rtmp_ref_set(out, 1);

    return out;
}


static void
ngx_rtmp_gop_cache_free_shared_chain(ngx_rtmp_gop_cache_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_chain_t        *cl;
    
    if (ngx_rtmp_ref_put(in)) {
        return;
    }
    
    for (cl = in; ; cl = cl->next) {
        if (cl->next == NULL) {
            cl->next = ctx->free;
            ctx->free = in;
            return;
        }
    }
}


static ngx_chain_t *
ngx_hfl_gop_cache_meta_message(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_gop_cache_ctx_t        *ctx;
    ngx_http_request_t              *r;
    ngx_rtmp_header_t                ch;
    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    r = s->data;
    if (r == NULL || (r->connection && r->connection->destroyed)) {
        ngx_rtmp_gop_cache_free_shared_chain(ctx, in);
        return NULL;
    }
    
    ch.timestamp = 0;
    ch.type = NGX_RTMP_MSG_AMF_META;
    
    return ngx_hfl_gop_cache_append_message(s, &ch, NULL, in);
}


static ngx_chain_t *
ngx_hfl_gop_cache_append_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_rtmp_header_t *lh, ngx_chain_t *in)
{
    ngx_rtmp_gop_cache_ctx_t        *ctx;
    ngx_http_request_t              *r;
    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }
    
    r = s->data;
    if (r == NULL || (r->connection && r->connection->destroyed)) {
        ngx_rtmp_gop_cache_free_shared_chain(ctx, in);
        return NULL;
    }
    
    return ngx_hfl_gop_cache_append_shared_bufs(ctx, h, in, r->chunked);
}


static ngx_chain_t *
ngx_hfl_gop_cache_append_shared_bufs(ngx_rtmp_gop_cache_ctx_t *ctx,
    ngx_rtmp_header_t *h, ngx_chain_t *in, ngx_flag_t chunked)
{
    ngx_chain_t        *tag, *ch, *ct, chunk, *iter, *last_in, **tail,
                        prev_tag_size;
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

    tag = ngx_rtmp_gop_cache_append_shared_bufs(ctx, NULL, in);
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

        ch = ngx_rtmp_gop_cache_append_shared_bufs(ctx, NULL, &chunk);
        if (ch == NULL) {
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

            ct = ngx_rtmp_gop_cache_append_shared_bufs(ctx, NULL, &chunk);
            if (ct == NULL) {
                return NULL;
            }

            tail = &last_in->next;
            *tail = ct;
        }

        ch->next = tag;

        return ch;
    }

    return tag;
}
    

static void
ngx_hfl_gop_cache_free_message(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_gop_cache_ctx_t  *ctx;
        
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }
        
    ngx_rtmp_gop_cache_free_shared_chain(ctx, in);
}


static ngx_chain_t *
ngx_rl_gop_cache_meta_message(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    return ngx_rtmp_gop_cache_append_shared_bufs(ctx, NULL, in);
}


static ngx_chain_t *
ngx_rl_gop_cache_append_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_rtmp_header_t *lh, ngx_chain_t *in)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_chain_t                    *pkt;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    pkt = ngx_rtmp_gop_cache_append_shared_bufs(ctx, NULL, in);
    if (pkt != NULL) {
        ngx_rtmp_prepare_message(s, h, lh, pkt);
    }

    return pkt;
}


static void
ngx_rl_gop_cache_free_message(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_gop_cache_ctx_t  *ctx;
        
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }
        
    ngx_rtmp_gop_cache_free_shared_chain(ctx, in);
}


void
ngx_rtmp_gop_cache_exec_handler(ngx_rtmp_session_t *s, size_t pos,
    ngx_chain_t *in)
{
    s->gop_cache.out[pos].set = 0;
    s->gop_cache.out[pos].free(s, in);
    s->gop_cache.count--;
}


static ngx_int_t
ngx_rtmp_gop_cache_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_gop_cache_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_gop_cache_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_gop_cache_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_gop_cache_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_gop_cache_close_stream;

    return NGX_OK;
}

