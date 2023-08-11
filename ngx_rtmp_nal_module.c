/*
 * @Author: likai
 * @Date: 2023-08-11 19:00:30
 * @Last Modified by: likai
 * @Last Modified time: 2023-08-11 20:11:36
 * @Description: "this module for handle h264 nal data"
 */

#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>

static void *ngx_rtmp_nal_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_nal_merge_app_conf(ngx_conf_t *cf, void *parent,
                                         void *child);
static ngx_int_t ngx_rtmp_nal_postconfiguration(ngx_conf_t *cf);

typedef struct {
    ngx_flag_t skip_filler_data;
} ngx_rtmp_nal_app_conf_t;

static ngx_command_t ngx_rtmp_nal_commands[] = {

    { ngx_string("skip_filler_data"),
      NGX_RTMP_MAIN_CONF | NGX_RTMP_SRV_CONF | NGX_RTMP_APP_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot, NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_nal_app_conf_t, skip_filler_data), NULL },

    ngx_null_command

};

static ngx_rtmp_module_t ngx_rtmp_nal_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_rtmp_nal_postconfiguration, /* postconfiguration */
    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */
    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */
    ngx_rtmp_nal_create_app_conf,   /* create app configuration */
    ngx_rtmp_nal_merge_app_conf     /* merge app configuration */
};

ngx_module_t ngx_rtmp_nal_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_nal_module_ctx,       /* module context */
    ngx_rtmp_nal_commands,          /* module directives */
    NGX_RTMP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_rtmp_handle_video(ngx_rtmp_session_t *s,
                                       ngx_rtmp_header_t *h, ngx_chain_t *in) {
    ngx_rtmp_codec_ctx_t *codec_ctx;
    ngx_rtmp_nal_app_conf_t *nacf;

    ngx_int_t nal_type, nsize, nal_size, i, least_size;
    ngx_int_t remain, nal_size_remain, remove_size;
    ngx_int_t parse_header;
    ngx_chain_t *inp;
    u_char av_type, *p;

    nal_size = 0;
    nsize = 0;
    nal_type = 0;
    av_type = 0;
    nal_size_remain = 0;
    remove_size = 0;
    remain = 0;
    parse_header = 1;

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_nal_module);
    if (nacf == NULL) {
        return NGX_ERROR;
    }

    if (!nacf->skip_filler_data) {
        return NGX_OK;
    }

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return NGX_ERROR;
    }

    if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "skip filler data"
                      "only support h264");
        return NGX_OK;
    }

    if (in->buf->last - in->buf->pos < 5) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                    "input buffer too short: %d", in->buf->last - in->buf->pos);
        return NGX_OK;
    }

    inp = in;
    p = inp->buf->pos;
    p++;
    av_type = *p;
    p += 4;
    least_size = codec_ctx->avc_nal_bytes + 1;

    while (av_type != 0) {
        if (parse_header == 1) {
            for (i = 0; i < ((ngx_int_t)codec_ctx->avc_nal_bytes - nal_size_remain);
                 i++) {
                nal_size = (nal_size << 8) | (*p++);
            }
            if (nal_size_remain != 0) {
                p += (codec_ctx->avc_nal_bytes - nal_size_remain);
            }

            if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
                nal_type = *p & 0x1f;
            } else {
                nal_type = (*p & 0x7e) >> 1;
            }

            if ((h->mlen - 5) == nal_size + codec_ctx->avc_nal_bytes) {
                break;
            }
            if ((h->mlen - 5) < nal_size + codec_ctx->avc_nal_bytes) {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "nal size:%d > rtmp message length", nal_size);
                break;
            }
            parse_header = 0;
            p -= (codec_ctx->avc_nal_bytes - nal_size_remain);
        }

        nsize += (inp->buf->last - p);
        remain = nsize - (nal_size + codec_ctx->avc_nal_bytes);

        if (remain > 0 && nal_type == 12 &&
                codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
            remove_size = (inp->buf->last - p - remain);
            inp->buf->last = ngx_movemem(p, inp->buf->last - remain, remain);

        } else if (remain <= 0 && nal_type == 12 &&
                       codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
            remove_size += (inp->buf->last - p);
            inp->buf->last = p;
        }

        if (remain >= least_size) {
            p = inp->buf->last - remain;
            nal_size_remain = 0;
            nal_size = 0;
            nsize = 0;
            nal_type = 0;
            parse_header = 1;
            continue;
        } else if (remain > 0 && remain < least_size) {
            nal_size_remain = remain;
            nal_size = 0;
            nsize = 0;
            nal_type = 0;
            p = inp->buf->last - remain;
            for (i = 0; i < nal_size_remain; i++) {
                nal_size = (nal_size << 8) | (*p++);
            }
            parse_header = 1;
        }

        if (inp->next) {
            inp = inp->next;
            p = inp->buf->pos;
        } else {
            break;
        }
  }

#if (NGX_DEBUG)
    if (remove_size > 0) {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                    "remove filler data size:%d", remove_size);
    }
#endif

    return NGX_OK;
}

static void *ngx_rtmp_nal_create_app_conf(ngx_conf_t *cf) {
    ngx_rtmp_nal_app_conf_t *nacf;

    nacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_nal_app_conf_t));
    if (nacf == NULL) {
        return NULL;
    }

    nacf->skip_filler_data = NGX_CONF_UNSET;
    return nacf;
}

static char *ngx_rtmp_nal_merge_app_conf(ngx_conf_t *cf, void *parent,
                                         void *child) {
    ngx_rtmp_nal_app_conf_t *prev = parent;
    ngx_rtmp_nal_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->skip_filler_data, prev->skip_filler_data, 0);
    return NGX_CONF_OK;
}

static ngx_int_t ngx_rtmp_nal_postconfiguration(ngx_conf_t *cf) {
    ngx_rtmp_core_main_conf_t *cmcf;
    ngx_rtmp_handler_pt *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_handle_video;

    return NGX_OK;
}