
/*
 * Copyright (C) Winshining
 */


#ifndef _NGX_RTMP_EXEC_H_INCLUDED_
#define _NGX_RTMP_EXEC_H_INCLUDED_


enum {
    NGX_RTMP_EXEC_PUSH,
    NGX_RTMP_EXEC_PULL,

    NGX_RTMP_EXEC_PUBLISH,
    NGX_RTMP_EXEC_PUBLISH_DONE,
    NGX_RTMP_EXEC_PLAY,
    NGX_RTMP_EXEC_PLAY_DONE,
    NGX_RTMP_EXEC_RECORD_DONE,

    NGX_RTMP_EXEC_MAX,

    NGX_RTMP_EXEC_STATIC
};


typedef struct ngx_rtmp_exec_pull_ctx_s  ngx_rtmp_exec_pull_ctx_t;

struct ngx_rtmp_exec_pull_ctx_s {
    ngx_pool_t                         *pool;
    ngx_uint_t                          counter;
    ngx_str_t                           name;
    ngx_str_t                           app;
    ngx_array_t                         pull_exec;   /* ngx_rtmp_exec_t */
    ngx_rtmp_exec_pull_ctx_t           *next;
};


typedef struct {
    ngx_int_t                           active;
    ngx_array_t                         conf[NGX_RTMP_EXEC_MAX];
                                                     /* ngx_rtmp_exec_conf_t */
    ngx_flag_t                          respawn;
    ngx_flag_t                          options;
    ngx_uint_t                          nbuckets;
    ngx_rtmp_exec_pull_ctx_t          **pull;
} ngx_rtmp_exec_app_conf_t;


extern ngx_module_t ngx_rtmp_exec_module;


#endif
