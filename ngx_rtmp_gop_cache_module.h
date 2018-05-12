
/*
 * Copyright (C) Gnolizuh
 * Copyright (C) Winshining
 */

#ifndef _NGX_RTMP_GOP_CACHE_H_INCLUDE_
#define _NGX_RTMP_GOP_CACHE_H_INCLUDE_


#define NGX_GOP_CACHE_POOL_CREATE_SIZE          4096


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
    ngx_int_t              video_frame_in_this;
    ngx_int_t              audio_frame_in_this;
};


typedef struct ngx_rtmp_gop_cache_app_conf_s {
    ngx_flag_t       gop_cache;
    size_t           gop_cache_count;
    size_t           gop_max_frame_count;
    size_t           gop_max_video_count;
    size_t           gop_max_audio_count;
} ngx_rtmp_gop_cache_app_conf_t;


typedef struct ngx_rtmp_gop_cache_ctx_s {
    ngx_pool_t                 *pool;
    ngx_rtmp_gop_cache_t       *cache_head;
    ngx_rtmp_gop_cache_t       *cache_tail;
    ngx_rtmp_gop_cache_t       *free_cache;
    ngx_rtmp_gop_frame_t       *free_frame;

    ngx_chain_t                *video_seq_header;
    ngx_chain_t                *audio_seq_header;
    ngx_chain_t                *meta;
    ngx_chain_t                *free;
    
    ngx_uint_t                  meta_version;
    ngx_int_t                   chunk_size;

    size_t                      gop_cache_count;
    size_t                      video_frame_in_all;
    size_t                      audio_frame_in_all;
} ngx_rtmp_gop_cache_ctx_t;


typedef struct {
    ngx_int_t (*send_message_pt)(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority);
    ngx_chain_t *(*meta_message_pt)(ngx_rtmp_session_t *s, ngx_chain_t *in);
    ngx_chain_t *(*append_message_pt)(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_rtmp_header_t *lh, ngx_chain_t *in);
    void (*free_message_pt)(ngx_rtmp_session_t *s, ngx_chain_t *in);
} ngx_rtmp_gop_cache_proc_handler_t;


void ngx_rtmp_gop_cache_exec_handler(ngx_rtmp_session_t *s, size_t pos,
    ngx_chain_t *in);


#endif

