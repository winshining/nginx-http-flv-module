
/*
 * Copyright (C) Winshining
 */

#ifndef _NGX_RTMP_GOP_CACHE_H_INCLUDE_
#define _NGX_RTMP_GOP_CACHE_H_INCLUDE_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_codec_module.h"


#define NGX_GOP_CACHE_POOL_CREATE_SIZE          4096
#define NGX_PURE_AUDIO_ESTIMATE_MAX_COUNT       115 /* pure audio */


typedef struct ngx_rtmp_gop_frame_s ngx_rtmp_gop_frame_t;
typedef struct ngx_rtmp_gop_cache_s ngx_rtmp_gop_cache_t;


struct ngx_rtmp_gop_frame_s {
    ngx_rtmp_header_t     h;
    ngx_uint_t            prio;
    ngx_chain_t          *frame;
    ngx_rtmp_gop_frame_t *next;
};


struct ngx_rtmp_gop_cache_s {
    ngx_rtmp_gop_frame_t  *frame_head;
    ngx_rtmp_gop_frame_t  *frame_tail;
    ngx_rtmp_gop_cache_t  *next;
    ngx_chain_t           *video_seq_header;
    ngx_chain_t           *audio_seq_header;
    ngx_chain_t           *meta;
    ngx_chain_t           *flv_meta;
    ngx_chain_t           *flv_meta_chunked;
    ngx_uint_t             meta_version;
    ngx_int_t              video_frame_in_this;
    ngx_int_t              audio_frame_in_this;
};


typedef struct ngx_rtmp_gop_cache_loc_conf_s {
    ngx_flag_t       gop_cache;
    ngx_int_t        gop_cache_count;
    ngx_int_t        gop_max_frame_count;
    ngx_int_t        gop_max_video_count;
    ngx_int_t        gop_max_audio_count;
} ngx_rtmp_gop_cache_app_conf_t;


typedef struct ngx_rtmp_gop_cache_ctx_s {
    ngx_pool_t                 *pool;
    ngx_rtmp_gop_cache_t       *cache_head;
    ngx_rtmp_gop_cache_t       *cache_tail;
    ngx_rtmp_gop_cache_t       *free_cache;
    ngx_rtmp_gop_frame_t       *free_frame;
    ngx_int_t                  gop_cache_count;
    ngx_int_t                  video_frame_in_all;
    ngx_int_t                  audio_frame_in_all;
    ngx_int_t                  audio_after_last_video_count;
} ngx_rtmp_gop_cache_ctx_t;


#endif

