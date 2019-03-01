
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Winshining
 */


#ifndef _NGX_RTMP_VARIABLES_H_INCLUDED_
#define _NGX_RTMP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_variable_value_t  ngx_rtmp_variable_value_t;

#define ngx_rtmp_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_rtmp_variable_s  ngx_rtmp_variable_t;

typedef void (*ngx_rtmp_set_variable_pt) (ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_rtmp_get_variable_pt) (ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);


#define NGX_RTMP_VAR_CHANGEABLE   1
#define NGX_RTMP_VAR_NOCACHEABLE  2
#define NGX_RTMP_VAR_INDEXED      4
#define NGX_RTMP_VAR_NOHASH       8
#define NGX_RTMP_VAR_WEAK         16
#define NGX_RTMP_VAR_PREFIX       32


struct ngx_rtmp_variable_s {
    ngx_str_t                     name;   /* must be first to build the hash */
    ngx_rtmp_set_variable_pt      set_handler;
    ngx_rtmp_get_variable_pt      get_handler;
    uintptr_t                     data;
    ngx_uint_t                    flags;
    ngx_uint_t                    index;
};


ngx_rtmp_variable_t *ngx_rtmp_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);
ngx_int_t ngx_rtmp_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_rtmp_variable_value_t *ngx_rtmp_get_indexed_variable(ngx_rtmp_session_t *s,
    ngx_uint_t index);
ngx_rtmp_variable_value_t *ngx_rtmp_get_flushed_variable(ngx_rtmp_session_t *s,
    ngx_uint_t index);

ngx_rtmp_variable_value_t *ngx_rtmp_get_variable(ngx_rtmp_session_t *s,
    ngx_str_t *name, ngx_uint_t key);


#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_rtmp_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;
    ngx_uint_t                    ncaptures;
    ngx_rtmp_regex_variable_t    *variables;
    ngx_uint_t                    nvariables;
    ngx_str_t                     name;
} ngx_rtmp_regex_t;


typedef struct {
    ngx_rtmp_regex_t             *regex;
    void                         *value;
} ngx_rtmp_map_regex_t;


ngx_rtmp_regex_t *ngx_rtmp_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
ngx_int_t ngx_rtmp_regex_exec(ngx_rtmp_session_t *s, ngx_rtmp_regex_t *re,
    ngx_str_t *str);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_rtmp_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_rtmp_map_t;


void *ngx_rtmp_map_find(ngx_rtmp_session_t *s, ngx_rtmp_map_t *map,
    ngx_str_t *match);


ngx_int_t ngx_rtmp_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_rtmp_variables_init_vars(ngx_conf_t *cf);


extern ngx_rtmp_variable_value_t  ngx_rtmp_variable_null_value;
extern ngx_rtmp_variable_value_t  ngx_rtmp_variable_true_value;


#endif /* _NGX_RTMP_VARIABLES_H_INCLUDED_ */
