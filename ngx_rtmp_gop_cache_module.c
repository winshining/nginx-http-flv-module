
/*
 * Copyright (C) Winshining
 */


#include "ngx_http_flv_live_module.h"
#include "ngx_rtmp_gop_cache_module.h"


static ngx_rtmp_publish_pt       next_publish;


static void ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *s, ngx_uint_t prio,
        ngx_rtmp_header_t *ch, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_gop_cache_av(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_gop_cache_publish(ngx_rtmp_session_t *s,
        ngx_rtmp_publish_t *v);


static ngx_int_t ngx_rtmp_gop_cache_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_gop_cache_create_loc_conf(ngx_conf_t *cf);
static char *ngx_rtmp_gop_cache_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);


extern ngx_rtmp_process_handler_t *ngx_rtmp_process_handlers[2];
extern ngx_module_t                ngx_http_flv_live_module;


static ngx_command_t ngx_rtmp_gop_cache_commands[] = {
    { ngx_string("gop_cache"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_cache_app_conf_t, gop_cache),
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
    ngx_rtmp_gop_cache_create_loc_conf,   /* create location configuration */
    ngx_rtmp_gop_cache_merge_loc_conf     /* merge location configuration */
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
ngx_rtmp_gop_cache_create_loc_conf(ngx_conf_t *cf)
{
    ngx_rtmp_gop_cache_app_conf_t *gacf;

    gacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_gop_cache_app_conf_t));
    if (gacf == NULL) {
        return NULL;
    }

    gacf->gop_cache = NGX_CONF_UNSET;

    return (void *)gacf;
}


char *
ngx_rtmp_gop_cache_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_gop_cache_app_conf_t        *prev = parent;
    ngx_rtmp_gop_cache_app_conf_t        *conf = child;

    ngx_conf_merge_value(conf->gop_cache, prev->gop_cache, 1);
    
    return NGX_CONF_OK;
}


void
ngx_rtmp_gop_cache_send(ngx_rtmp_session_t *s, ngx_uint_t prio,
        ngx_rtmp_header_t *ch, ngx_chain_t *in)
{
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_gop_cache_ctx_t       *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_live_ctx_t            *live_ctx, *pctx;
    ngx_rtmp_process_handler_t     *handler;
    ngx_chain_t                    *pkt, *apkt, *meta, *header;
    ngx_rtmp_live_chunk_stream_t   *cs;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_cache_app_conf_t  *gacf;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_http_flv_live_ctx_t        *hflctx;
    ngx_http_request_t             *r;
    uint32_t                        delta;
    ngx_int_t                       csidx;
    ngx_rtmp_header_t               lh;
    ngx_uint_t                      meta_version;
    ngx_uint_t                     *status;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_cache_module);
    if (gacf == NULL || !gacf->gop_cache) {
        return;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        return;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    if (lacf == NULL) {
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

    live_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (live_ctx == NULL || live_ctx->stream == NULL
        || !live_ctx->stream->publishing)
    {
        return;
    }

    if (ch->type == NGX_RTMP_MSG_AUDIO) {
        // pure audio
        if (ctx->audio_after_last_video_count
                > NGX_PURE_AUDIO_ESTIMATE_MAX_COUNT)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                    "drop audio frame timestamp='%uD'",
                    ch->timestamp);

            return;
        }

        ctx->audio_after_last_video_count++;
    }

    if (ch->type == NGX_RTMP_MSG_VIDEO && prio == NGX_RTMP_VIDEO_KEY_FRAME) {
        ctx->audio_after_last_video_count = 0;
    }

    pkt = NULL;
    apkt = NULL;
    header = NULL;
    meta_version = 0;

    ss = live_ctx->session;

    /* broadcast to all subscribers */

    for (pctx = live_ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == live_ctx || live_ctx->paused) {
            continue;
        }

        status = &pctx->gop_cache.status;
        if (*status == NGX_RTMP_GOP_CACHE_DONE) {
            continue;
        }

        if (*status == NGX_RTMP_GOP_CACHE_INITIAL) {
            if (ch->type == NGX_RTMP_MSG_VIDEO
                && prio == NGX_RTMP_VIDEO_KEY_FRAME)
            {
                *status = NGX_RTMP_GOP_CACHE_PLAYING;

                ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                       "gop cache send: playing");
            } else {
               ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                       "gop cache send: between the two GOPs");

                continue;
            }
        } else if (*status == NGX_RTMP_GOP_CACHE_PLAYING) {
            if (ch->type == NGX_RTMP_MSG_VIDEO) {
                // drop video when not H.264
                if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) {
                    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                            "drop video non-H.264 frame timestamp='%uD'",
                            ch->timestamp);

                    continue;
                }
            }

            if (ch->type == NGX_RTMP_MSG_VIDEO
                && prio == NGX_RTMP_VIDEO_KEY_FRAME)
            {
                /* 1 GOP done */
                *status = NGX_RTMP_GOP_CACHE_DONE;

                if (pctx->gop_cache.video_seq_header) {
                    ngx_rtmp_free_shared_chain(cscf,
                            pctx->gop_cache.video_seq_header);
                    pctx->gop_cache.video_seq_header = NULL;
                }

                if (pctx->gop_cache.audio_seq_header) {
                    ngx_rtmp_free_shared_chain(cscf,
                            pctx->gop_cache.audio_seq_header);
                    pctx->gop_cache.audio_seq_header = NULL;
                }

                if (pctx->gop_cache.meta) {
                    ngx_rtmp_free_shared_chain(cscf,
                            pctx->gop_cache.meta);
                    pctx->gop_cache.meta = NULL;
                }

                if (pctx->gop_cache.flv_meta) {
                    ngx_rtmp_free_shared_chain(cscf,
                            pctx->gop_cache.flv_meta);
                    pctx->gop_cache.flv_meta = NULL;
                }

                if (pctx->gop_cache.flv_meta_chunked) {
                    ngx_rtmp_free_shared_chain(cscf,
                            pctx->gop_cache.flv_meta_chunked);
                    pctx->gop_cache.flv_meta_chunked = NULL;
                }

                ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                       "gop cache send: done");

                continue;
            }
        }

        // save video seq header.
        if (codec_ctx->avc_header && !pctx->gop_cache.video_seq_header) {
            pctx->gop_cache.video_seq_header =
                    ngx_rtmp_append_shared_bufs(cscf, NULL,
                            codec_ctx->avc_header);
        }

        // save audio seq header.
        if (codec_ctx->aac_header && !pctx->gop_cache.audio_seq_header) {
            pctx->gop_cache.audio_seq_header =
                    ngx_rtmp_append_shared_bufs(cscf, NULL,
                            codec_ctx->aac_header);
        }

        // save metadata.
        if (codec_ctx->meta && !pctx->gop_cache.meta) {
            pctx->gop_cache.meta = ngx_rtmp_append_shared_bufs(cscf,
                    NULL, codec_ctx->meta);
        }

        if (codec_ctx->flv_meta && !pctx->gop_cache.flv_meta) {
            pctx->gop_cache.flv_meta = ngx_rtmp_append_shared_bufs(cscf,
                    NULL, codec_ctx->flv_meta);
        }

        if (codec_ctx->flv_meta_chunked
            && !pctx->gop_cache.flv_meta_chunked)
        {
            pctx->gop_cache.flv_meta_chunked =
                    ngx_rtmp_append_shared_bufs(cscf, NULL,
                            codec_ctx->flv_meta_chunked);
        }

        csidx = !(lacf->interleave || ch->type == NGX_RTMP_MSG_VIDEO);

        ss = pctx->session;
        cs = &pctx->cs[csidx];

        handler = ngx_rtmp_process_handlers[pctx->protocol];

        if (pctx->protocol == NGX_RTMP_PROTOCOL_HTTP) {
            r = ss->data;
            if (r == NULL || (r->connection && r->connection->destroyed)) {
                continue;
            }

            hflctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
            if (hflctx->chunked) {
                meta = pctx->gop_cache.flv_meta_chunked;
            } else {
                meta = pctx->gop_cache.flv_meta;
            }
        } else {
            meta = pctx->gop_cache.meta;
        }

		if (codec_ctx->meta) {
            meta_version = codec_ctx->meta_version;
        }

        /* send metadata */
        if (meta && meta_version != pctx->meta_version) {
            ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                    "gop cache send: meta");

            if (handler->send_message_pt(ss, meta, 0) == NGX_OK) {
                pctx->meta_version = meta_version;
            }
        }

        lh = *ch;

        if (cs->active) {
            lh.timestamp = cs->timestamp;
        }

        delta = ch->timestamp - lh.timestamp;

        if (!cs->active) {
            switch (ch->type) {
                case NGX_RTMP_MSG_VIDEO:
                    header = pctx->gop_cache.video_seq_header;
                    break;
                case NGX_RTMP_MSG_AUDIO:
                    header = pctx->gop_cache.audio_seq_header;
                    break;
                default:
                    header = NULL;
            }

            if (header) {
                apkt = handler->append_message_pt(ss, &lh, NULL, header);
            }

            if (apkt && handler->send_message_pt(ss, apkt, 0) == NGX_OK) {
                cs->timestamp = lh.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;
            }

            if (apkt) {
                handler->free_message_pt(ss, apkt);
                apkt = NULL;
            }
        }

        pkt = handler->append_message_pt(ss, ch, &lh, in);
        if (handler->send_message_pt(ss, pkt, prio) != NGX_OK) {
            ++live_ctx->ndropped;

            cs->dropped += delta;

            handler->free_message_pt(ss, pkt);

            return;
        }

        if (pkt) {
            handler->free_message_pt(ss, pkt);
            pkt = NULL;
        }

        ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
               "gop cache send: tag type='%s' prio='%d' ltimestamp='%uD'",
               ch->type == NGX_RTMP_MSG_AUDIO ? "audio" : "video",
               prio, lh.timestamp);

        cs->timestamp += delta;
        ss->current_time = cs->timestamp;
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

    ngx_rtmp_gop_cache_send(s, prio, &ch, in);

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

    return NGX_OK;
}

