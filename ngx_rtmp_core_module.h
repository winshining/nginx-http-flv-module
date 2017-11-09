
/*
 * Copyright (C) Winshining
 */


#ifndef _NGX_RTMP_CORE_H_INCLUDED_
#define _NGX_RTMP_CORE_H_INCLUDED_


typedef struct ngx_rtmp_phase_handler_s  ngx_rtmp_phase_handler_t;

typedef ngx_int_t (*ngx_rtmp_phase_handler_pt)(ngx_rtmp_session_t *s,
    ngx_rtmp_phase_handler_t *ph);

struct ngx_rtmp_phase_handler_s {
    ngx_rtmp_phase_handler_pt  checker;
    ngx_rtmp_handler_pt        handler;
    ngx_uint_t                 next;
};


typedef struct {
    ngx_rtmp_phase_handler_t  *handlers;
    ngx_uint_t                 server_rewrite_index;
    ngx_uint_t                 location_rewrite_index;
} ngx_rtmp_phase_engine_t;


typedef struct {
    ngx_array_t                handlers;
} ngx_rtmp_phase_t;


void ngx_rtmp_core_run_phases(ngx_rtmp_session_t *s);
ngx_int_t ngx_rtmp_core_rewrite_phase(ngx_rtmp_session_t *s,
    ngx_rtmp_phase_handler_t *ph);
ngx_int_t ngx_rtmp_core_find_config_phase(ngx_rtmp_session_t *s,
    ngx_rtmp_phase_handler_t *ph);
ngx_int_t ngx_rtmp_core_post_rewrite_phase(ngx_rtmp_session_t *s,
    ngx_rtmp_phase_handler_t *ph);


#define NGX_RTMP_LINGERING_OFF          0
#define NGX_RTMP_LINGERING_ON           1
#define NGX_RTMP_LINGERING_ALWAYS       2

#endif /* _NGX_RTMP_CORE_H_INCLUDED_ */
