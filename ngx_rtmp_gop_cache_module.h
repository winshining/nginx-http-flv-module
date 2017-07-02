
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
#define NGX_PURE_AUDIO_ESTIMATE_MAX_COUNT       128 /* pure audio */


typedef struct ngx_rtmp_gop_cache_loc_conf_s {
    ngx_flag_t        gop_cache;
} ngx_rtmp_gop_cache_app_conf_t;


typedef struct ngx_rtmp_gop_cache_ctx_s {
    ngx_int_t        audio_after_last_video_count;
} ngx_rtmp_gop_cache_ctx_t;


#endif

