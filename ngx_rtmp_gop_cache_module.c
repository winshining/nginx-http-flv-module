
/*
 * Copyright (C) Gnolizuh
 * Copyright (C) Winshining
 */


#include "ngx_http_flv_live_module.h"
#include "ngx_rtmp_gop_cache_module.h"


static ngx_rtmp_publish_pt       next_publish;
static ngx_rtmp_play_pt          next_play;
static ngx_rtmp_close_stream_pt  next_close_stream;


static ngx_rtmp_gop_frame_t *ngx_rtmp_gop_alloc_frame(ngx_rtmp_session_t *s);
static ngx_rtmp_gop_frame_t *ngx_rtmp_gop_free_frame(ngx_rtmp_session_t *s,
        ngx_rtmp_gop_frame_t *frame);
static ngx_int_t ngx_rtmp_gop_link_frame(ngx_rtmp_session_t *s,
        ngx_rtmp_gop_frame_t *frame);
static ngx_int_t ngx_rtmp_gop_alloc_cache(ngx_rtmp_session_t *s);
static ngx_rtmp_gop_cache_t *ngx_rtmp_gop_free_cache(ngx_rtmp_session_t *s,
        ngx_rtmp_gop_cache_t *cache);
static void ngx_rtmp_gop_cleanup(ngx_rtmp_session_t *s);
static void ngx_rtmp_gop_cache_update(ngx_rtmp_session_t *s);
static void ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio,
        ngx_rtmp_header_t *ch, ngx_chain_t *frame);
static void ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_gop_cache_av(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_gop_cache_publish(ngx_rtmp_session_t *s,
        ngx_rtmp_publish_t *v);
static ngx_int_t ngx_rtmp_gop_cache_play(ngx_rtmp_session_t *s,
        ngx_rtmp_play_t *v);
static ngx_int_t ngx_rtmp_gop_cache_close_stream(ngx_rtmp_session_t *s,
        ngx_rtmp_close_stream_t *v);


static ngx_int_t ngx_rtmp_gop_cache_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_gop_cache_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_gop_cache_merge_app_conf(ngx_conf_t *cf,
        void *parent, void *child);


extern ngx_rtmp_live_process_handler_t  *ngx_rtmp_live_process_handlers
                                         [NGX_RTMP_PROTOCOL_HTTP + 1];
extern ngx_module_t                      ngx_http_flv_live_module;


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


void *
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

    return (void *)gacf;
}


char *
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


ngx_rtmp_gop_frame_t *
ngx_rtmp_gop_alloc_frame(ngx_rtmp_session_t *s)
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
    
    if (ctx->pool == NULL) {
        ctx->pool = ngx_create_pool(NGX_GOP_CACHE_POOL_CREATE_SIZE,
                s->connection->log);
    }

    frame = ngx_pcalloc(ctx->pool, sizeof(ngx_rtmp_gop_frame_t));

    return frame;
}


ngx_rtmp_gop_frame_t *
ngx_rtmp_gop_free_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NULL;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    if (frame->frame) {
        ngx_rtmp_free_shared_chain(cscf, frame->frame);
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


ngx_int_t
ngx_rtmp_gop_link_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_frame_t *frame)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache;

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
        cache->frame_tail->next = frame;
        cache->frame_tail = frame;
    }

    if (frame->h.type == NGX_RTMP_MSG_VIDEO) {
        ctx->video_frame_in_all++;
        cache->video_frame_in_this++;

        ctx->audio_after_last_video_count = 0;
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


ngx_int_t
ngx_rtmp_gop_alloc_cache(ngx_rtmp_session_t *s)
{
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NGX_ERROR;
    }

    if (ctx->free_cache != NULL) {
        cache = ctx->free_cache;
        ctx->free_cache = cache->next;

        ngx_memzero(cache, sizeof(ngx_rtmp_gop_cache_t));
    } else {
        if (ctx->pool == NULL) {
            ctx->pool = ngx_create_pool(NGX_GOP_CACHE_POOL_CREATE_SIZE,
                    s->connection->log);
        }

        cache = ngx_pcalloc(ctx->pool, sizeof(ngx_rtmp_gop_cache_t));
        if (cache == NULL) {
            return NGX_ERROR;
        }
    }

    // save video seq header.
    if (codec_ctx->avc_header) {
        cache->video_seq_header = ngx_rtmp_append_shared_bufs(
                cscf, NULL, codec_ctx->avc_header);
    }

    // save audio seq header.
    if (codec_ctx->aac_header) {
        cache->audio_seq_header = ngx_rtmp_append_shared_bufs(
                cscf, NULL, codec_ctx->aac_header);
    }

    // save metadata.
    if (codec_ctx->meta) {
        cache->meta_version = codec_ctx->meta_version;
        cache->meta = ngx_rtmp_append_shared_bufs(cscf, NULL, codec_ctx->meta);
    }

    if (ctx->cache_head == NULL) {
        ctx->cache_tail = ctx->cache_head = cache;
    } else {
        ctx->cache_tail->next = cache;
        ctx->cache_tail = cache;
    }

    ctx->gop_cache_count++;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "gop alloc cache: gop_cache_count='%uD'", ctx->gop_cache_count);

    return NGX_OK;
}


ngx_rtmp_gop_cache_t *
ngx_rtmp_gop_free_cache(ngx_rtmp_session_t *s, ngx_rtmp_gop_cache_t *cache)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_frame_t           *frame;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return NULL;
    }

    if (cache->video_seq_header) {
        ngx_rtmp_free_shared_chain(cscf, cache->video_seq_header);
        cache->video_seq_header = NULL;
    }

    if (cache->audio_seq_header) {
        ngx_rtmp_free_shared_chain(cscf, cache->audio_seq_header);
        cache->audio_seq_header = NULL;
    }

    if (cache->meta) {
        ngx_rtmp_free_shared_chain(cscf, cache->meta);
        cache->meta = NULL;
    }

    for (frame = cache->frame_head; frame; frame = frame->next) {
        ngx_rtmp_gop_free_frame(s, frame);
    }

    cache->video_frame_in_this = 0;
    cache->audio_frame_in_this = 0;

    // recycle mem of gop frame
    cache->frame_tail->next = ctx->free_frame;
    ctx->free_frame = cache->frame_head;

    ctx->gop_cache_count--;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "gop free cache: gop_cache_count='%uD'", ctx->gop_cache_count);

    return cache->next;
}


void
ngx_rtmp_gop_cleanup(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_gop_cache_t           *cache;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    for (cache = ctx->cache_head; cache; cache = cache->next) {
        ngx_rtmp_gop_free_cache(s, cache);
    }

    if (ctx->pool != NULL) {
        ngx_destroy_pool(ctx->pool);
        ctx->pool = NULL;
    }

    ctx->cache_tail = ctx->cache_head = NULL;
    ctx->gop_cache_count = 0;
    ctx->free_cache = NULL;
    ctx->free_frame = NULL;
    ctx->video_frame_in_all = 0;
    ctx->audio_frame_in_all = 0;
    ctx->audio_after_last_video_count = 0;
}


void
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
            next = ngx_rtmp_gop_free_cache(s, ctx->cache_head);

            ctx->cache_head->next = ctx->free_cache;
            ctx->free_cache = ctx->cache_head;

            ctx->cache_head = next;
        } else {
            ngx_rtmp_gop_cleanup(s);
        }
    }
}


void
ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_uint_t prio,
        ngx_rtmp_header_t *ch, ngx_chain_t *frame)
{
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_core_app_conf_t       *cacf;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_gop_frame_t           *gop_frame;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    if (cacf == NULL) {
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

    if (ch->type == NGX_RTMP_MSG_AUDIO) {
        ctx->audio_after_last_video_count++;
    }

    if (ctx->audio_after_last_video_count > cacf->pure_audio_threshold) {
        ngx_rtmp_gop_cleanup(s);
        return;
    }

    if (ch->type == NGX_RTMP_MSG_VIDEO && prio == NGX_RTMP_VIDEO_KEY_FRAME) {
        if (ngx_rtmp_gop_alloc_cache(s) != NGX_OK) {
            return;
        }
    }

    gop_frame = ngx_rtmp_gop_alloc_frame(s);
    if (gop_frame == NULL) {
        return;
    }

    gop_frame->h = *ch;
    gop_frame->prio = prio;
    gop_frame->next = NULL;
    gop_frame->frame = ngx_rtmp_append_shared_bufs(cscf, NULL, frame);

    if (ngx_rtmp_gop_link_frame(s, gop_frame) != NGX_OK) {
        ngx_rtmp_free_shared_chain(cscf, gop_frame->frame);
        return;
    }

    if (ctx->video_frame_in_all > gacf->gop_max_video_count ||
        ctx->audio_frame_in_all > gacf->gop_max_audio_count ||
        (ctx->video_frame_in_all + ctx->audio_frame_in_all)
        > gacf->gop_max_frame_count)
    {
        ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
               "gop cache: video_frame_in_cache='%uD' "
               "audio_frame_in_cache='%uD' max_video_count='%uD' "
               "max_audio_count='%uD' gop_max_frame_count='%uD'",
               ctx->video_frame_in_all, ctx->audio_frame_in_all,
               gacf->gop_max_video_count, gacf->gop_max_audio_count,
               gacf->gop_max_frame_count);

        ngx_rtmp_gop_cleanup(s);
        return;
    }

    ngx_rtmp_gop_cache_update(s);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
           "gop cache: cache packet type='%s' timestamp='%uD'",
           gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
           gop_frame->h.timestamp);
}


void
ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *s)
{
    ngx_rtmp_session_t               *rs;
    ngx_chain_t                      *pkt, *apkt, *meta, *header;
    ngx_rtmp_live_ctx_t              *ctx, *pub_ctx;
    ngx_http_flv_live_ctx_t          *hflctx;
    ngx_rtmp_gop_cache_ctx_t         *gctx;
    ngx_rtmp_live_app_conf_t         *lacf;
    ngx_rtmp_gop_cache_t             *cache;
    ngx_rtmp_gop_frame_t             *gop_frame;
    ngx_rtmp_header_t                 ch, lh;
    ngx_uint_t                        meta_version;
    uint32_t                          delta;
    ngx_int_t                         csidx;
    ngx_rtmp_live_chunk_stream_t     *cs;
    ngx_rtmp_live_process_handler_t  *handler;
    ngx_http_request_t               *r;

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
    handler = ngx_rtmp_live_process_handlers[ctx->protocol];

    gctx = ngx_rtmp_get_module_ctx(rs, ngx_rtmp_gop_cache_module);
    if (gctx == NULL) {
        return;
    }

    for (cache = gctx->cache_head; cache; cache = cache->next) {
        if (ctx->protocol == NGX_RTMP_PROTOCOL_HTTP) {
            r = s->data;
            if (r == NULL || (r->connection && r->connection->destroyed)) {
                goto clear;
            }

            hflctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
            if (!hflctx->header_sent) {
                hflctx->header_sent = 1;
                ngx_http_flv_live_send_header(s);
            }
        }

        if (meta == NULL && meta_version != cache->meta_version) {
            meta = handler->meta_message_pt(s, cache->meta);
        }

        if (meta) {
            meta_version = cache->meta_version;
        }

        /* send metadata */
        if (meta && meta_version != ctx->meta_version) {
            ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "gop cache send: meta");

            if (handler->send_message_pt(s, meta, 0) == NGX_OK) {
                ctx->meta_version = meta_version;
            }
        }

        for (gop_frame = cache->frame_head;
             gop_frame;
             gop_frame = gop_frame->next)
        {
            csidx = !(lacf->interleave
                      || gop_frame->h.type == NGX_RTMP_MSG_VIDEO);

            cs = &ctx->cs[csidx];

            lh = ch = gop_frame->h;

            if (cs->active) {
                lh.timestamp = cs->timestamp;
            }

            delta = ch.timestamp - lh.timestamp;

            if (!cs->active) {
                switch (gop_frame->h.type) {
                    case NGX_RTMP_MSG_VIDEO:
                        header = cache->video_seq_header;
                        break;
                    default:
                        header = cache->audio_seq_header;
                }

                if (header) {
                    apkt = handler->append_message_pt(s, &lh, NULL, header);
                }

                if (apkt && handler->send_message_pt(s, apkt, 0) == NGX_OK) {
                    cs->timestamp = lh.timestamp;
                    cs->active = 1;
                    s->current_time = cs->timestamp;
                }
            }

            pkt = handler->append_message_pt(s, &ch, &lh, gop_frame->frame);
            if (handler->send_message_pt(s, pkt, gop_frame->prio) != NGX_OK) {
                ++pub_ctx->ndropped;

                cs->dropped += delta;

                goto clear;
            }

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                   "gop cache send: tag type='%s' prio='%d' ctimestamp='%uD' "
                   "ltimestamp='%uD'",
                   gop_frame->h.type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
                   gop_frame->prio,
                   ch.timestamp,
                   lh.timestamp);

            cs->timestamp += delta;
            s->current_time = cs->timestamp;
        }
    }

    return;

clear:

    if (meta) {
        handler->free_message_pt(s, meta);
    }

    if (pkt) {
        handler->free_message_pt(s, pkt);
    }

    if (apkt) {
        handler->free_message_pt(s, apkt);
    }
}


ngx_int_t
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


ngx_int_t ngx_rtmp_gop_cache_publish(ngx_rtmp_session_t *s,
        ngx_rtmp_publish_t *v)
{
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_gop_cache_ctx_t       *ctx;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "gop cache publish: name='%s' type='%s'",
                  v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_cache_module);
    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool,
                sizeof(ngx_rtmp_gop_cache_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_gop_cache_module);
    }

    ngx_memzero(ctx, sizeof(*ctx));

next:
    return next_publish(s, v);
}


ngx_int_t ngx_rtmp_gop_cache_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_msec_t                      start, end;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop cache play: name='%s' start='%i' duration='%i' reset='%d'",
            v->name, (ngx_int_t) v->start,
            (ngx_int_t) v->duration, (ngx_uint_t) v->reset);

    start = ngx_current_msec;
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop cache send: start_time='%uD'", start);

    ngx_rtmp_gop_cache_send(s);

    end = ngx_current_msec;
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop cache send: end_time='%uD'", end);

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop cache send: delta_time='%uD'", end - start);

next:
    return next_play(s, v);
}


ngx_int_t
ngx_rtmp_gop_cache_close_stream(ngx_rtmp_session_t *s,
        ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        goto next;
    }

    if (ctx->publishing == 0) {
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

    ngx_rtmp_gop_cleanup(s);

next:
    return next_close_stream(s, v);
}


ngx_int_t
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

