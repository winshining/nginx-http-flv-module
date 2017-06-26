
/*
 * Copyright (C) Winshining
 */

#ifndef _NGX_RTMP_AUTO_PUSH_H_INCLUDED_

typedef struct {
    ngx_flag_t                      auto_push;
    ngx_str_t                       socket_dir;
    ngx_msec_t                      push_reconnect;
    ngx_rtmp_addr_conf_t           *addr_conf;
} ngx_rtmp_auto_push_conf_t;

#endif

