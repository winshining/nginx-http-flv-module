
/*
 * Copyright (C) Winshining
 */


#ifndef _NGX_RTMP_HLS_MODULE_H_
#define _NGX_RTMP_HLS_MODULE_H_


ngx_int_t ngx_rtmp_hls_copy(ngx_rtmp_session_t *s, void *dst, u_char **src,
        size_t n, ngx_chain_t **in);


#endif /* _NGX_RTMP_HLS_MODULE_H_ */
