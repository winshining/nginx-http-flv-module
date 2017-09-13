
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc. 
 * Copyright (C) Winshining 
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


#define NGX_RTMP_PARSE_INVALID_REQUEST    11


static uint32_t  usual[] = {
    0xffffdbfe, /* 1111 1111 1111 1111  1101 1011 1111 1110 */

                /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */

                /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
#if (NGX_WIN32)
    0xefffffff, /* 1110 1111 1111 1111  1111 1111 1111 1111 */
#else
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
#endif

                /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
};


ngx_int_t
ngx_rtmp_parse_request_line(ngx_rtmp_session_t *s, ngx_buf_t *b)
{
    u_char  c, ch, *p;
    enum {
        sw_start = 0,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host_start,
        sw_host,
        sw_host_end,
        sw_host_ip_literal,
        sw_port,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_uri
    } state;

    state = sw_start;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case sw_start:

            s->schema_start = p;
            state = sw_schema;

            /* fall through */

        case sw_schema:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            switch (ch) {
            case ':':
                s->schema_end = p;
                state = sw_schema_slash;
                break;
            default:
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash:
            switch (ch) {
            case '/':
                state = sw_schema_slash_slash;
                break;
            default:
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash_slash:
            switch (ch) {
            case '/':
                state = sw_host_start;
                break;
            default:
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_host_start:

            s->host_start = p;

            if (ch == '[') {
                state = sw_host_ip_literal;
                break;
            }

            state = sw_host;

            /* fall through */

        case sw_host:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                break;
            }

            /* fall through */

        case sw_host_end:

            s->host_end = p;

            switch (ch) {
            case ':':
                s->port_start = p + 1;
                state = sw_port;
                break;
            case '/':
                s->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            default:
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_host_ip_literal:

            if (ch >= '0' && ch <= '9') {
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            switch (ch) {
            case ':':
                break;
            case ']':
                state = sw_host_end;
                break;
            case '-':
            case '.':
            case '_':
            case '~':
                /* unreserved */
                break;
            case '!':
            case '$':
            case '&':
            case '\'':
            case '(':
            case ')':
            case '*':
            case '+':
            case ',':
            case ';':
            case '=':
                /* sub-delims */
                break;
            default:
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_port:
            if (ch >= '0' && ch <= '9') {
                break;
            }

            switch (ch) {
            case '/':
                s->port_end = p;
                s->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            default:
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            }
            break;

        /* check "/.", "//", "%", and "\" (Win32) in URI */
        case sw_after_slash_in_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_check_uri;
                break;
            }

            switch (ch) {
            case '.':
                s->complex_uri = 1;
                state = sw_uri;
                break;
            case '%':
                s->quoted_uri = 1;
                state = sw_uri;
                break;
            case '/':
                s->complex_uri = 1;
                state = sw_uri;
                break;
#if (NGX_WIN32)
            case '\\':
                s->complex_uri = 1;
                state = sw_uri;
                break;
#endif
            case '?':
                s->args_start = p + 1;
                state = sw_uri;
                break;
            case '#':
                s->complex_uri = 1;
                state = sw_uri;
                break;
            case '+':
                s->plus_in_uri = 1;
                break;
            case '\0':
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            default:
                state = sw_check_uri;
                break;
            }
            break;

        /* check "/", "%" and "\" (Win32) in URI */
        case sw_check_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case '/':
                state = sw_after_slash_in_uri;
                break;
            case '.':
                break;
#if (NGX_WIN32)
            case '\\':
                s->complex_uri = 1;
                state = sw_after_slash_in_uri;
                break;
#endif
            case '%':
                s->quoted_uri = 1;
                state = sw_uri;
                break;
            case '?':
                s->args_start = p + 1;
                state = sw_uri;
                break;
            case '#':
                s->complex_uri = 1;
                state = sw_uri;
                break;
            case '+':
                s->plus_in_uri = 1;
                break;
            case '\0':
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            }
            break;

        /* URI */
        case sw_uri:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                break;
            }

            switch (ch) {
            case '#':
                s->complex_uri = 1;
                break;
            case '\0':
                return NGX_RTMP_PARSE_INVALID_REQUEST;
            }
        }
    }

    /* end of request line */
    s->uri_end = p;

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_process_request_uri(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t  *cscf;

    if (s->args_start) {
        s->uri.len = s->args_start - 1 - s->uri_start;
    } else {
        s->uri.len = s->uri_end - s->uri_start;
    }

    if (s->complex_uri || s->quoted_uri) {

        s->uri.data = ngx_pnalloc(s->connection->pool, s->uri.len + 1);
        if (s->uri.data == NULL) {
            return NGX_ERROR;
        }

        cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

        if (ngx_rtmp_parse_complex_uri(s, cscf->merge_slashes) != NGX_OK) {
            s->uri.len = 0;

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "client sent invalid request");
            return NGX_ERROR;
        }

    } else {
        s->uri.data = s->uri_start;
    }

    s->unparsed_uri.len = s->uri_end - s->uri_start;
    s->unparsed_uri.data = s->uri_start;

    s->valid_unparsed_uri = s->space_in_uri ? 0 : 1;

    if (s->args_start && s->uri_end > s->args_start) {
        s->args.len = s->uri_end - s->args_start;
        s->args.data = s->args_start;
    }

#if (NGX_WIN32)
    {
    u_char  *p, *last;

    p = s->uri.data;
    last = s->uri.data + s->uri.len;

    while (p < last) {

        if (*p++ == ':') {

            /*
             * this check covers "::$data", "::$index_allocation" and
             * ":$i30:$index_allocation"
             */

            if (p < last && *p == '$') {
                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                              "client sent unsafe win32 URI");
                return NGX_ERROR;
            }
        }
    }

    p = s->uri.data + s->uri.len - 1;

    while (p > s->uri.data) {

        if (*p == ' ') {
            p--;
            continue;
        }

        if (*p == '.') {
            p--;
            continue;
        }

        break;
    }

    if (p != s->uri.data + s->uri.len - 1) {
        s->uri.len = p + 1 - s->uri.data;
    }

    }
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "rtmp uri: \"%V\"", &s->uri);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "rtmp args: \"%V\"", &s->args);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_parse_complex_uri(ngx_rtmp_session_t *s, ngx_uint_t merge_slashes)
{
    u_char  c, ch, decoded, *p, *u;
    enum {
        sw_usual = 0,
        sw_slash,
        sw_dot,
        sw_dot_dot,
        sw_quoted,
        sw_quoted_second
    } state, quoted_state;

#if (NGX_SUPPRESS_WARN)
    decoded = '\0';
    quoted_state = sw_usual;
#endif

    state = sw_usual;
    p = s->uri_start;
    u = s->uri.data;
    s->args_start = NULL;

    ch = *p++;

    while (p <= s->uri_end) {

        /*
         * we use "ch = *p++" inside the cycle, it is safe,
         * because after the URI there is a character: '\r'
         */

        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "s:%d in:'%Xd:%c'", state, ch, ch);

        switch (state) {

        case sw_usual:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch (ch) {
#if (NGX_WIN32)
            case '\\':
                if (u - 2 >= s->uri.data
                    && *(u - 1) == '.' && *(u - 2) != '.')
                {
                    u--;
                }

                if (p == s->uri_start + s->uri.len) {

                    /*
                     * we omit the last "\" to cause redirect because
                     * the browsers do not treat "\" as "/" in relative URL path
                     */

                    break;
                }

                state = sw_slash;
                *u++ = '/';
                break;
#endif
            case '/':
#if (NGX_WIN32)
                if (u - 2 >= s->uri.data
                    && *(u - 1) == '.' && *(u - 2) != '.')
                {
                    u--;
                }
#endif
                state = sw_slash;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                s->args_start = p;
                goto args;
            case '#':
                goto done;
            case '.':
                *u++ = ch;
                break;
            case '+':
                s->plus_in_uri = 1;
                /* fall through */
            default:
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_slash:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch (ch) {
#if (NGX_WIN32)
            case '\\':
                break;
#endif
            case '/':
                if (!merge_slashes) {
                    *u++ = ch;
                }
                break;
            case '.':
                state = sw_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                s->args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                s->plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_dot:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch (ch) {
#if (NGX_WIN32)
            case '\\':
#endif
            case '/':
                state = sw_slash;
                u--;
                break;
            case '.':
                state = sw_dot_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                s->args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                s->plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_dot_dot:

            if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
                state = sw_usual;
                *u++ = ch;
                ch = *p++;
                break;
            }

            switch (ch) {
#if (NGX_WIN32)
            case '\\':
#endif
            case '/':
                state = sw_slash;
                u -= 5;
                for ( ;; ) {
                    if (u < s->uri.data) {
                        return NGX_RTMP_PARSE_INVALID_REQUEST;
                    }
                    if (*u == '/') {
                        u++;
                        break;
                    }
                    u--;
                }
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                s->args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                s->plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }

            ch = *p++;
            break;

        case sw_quoted:
            s->quoted_uri = 1;

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            return NGX_RTMP_PARSE_INVALID_REQUEST;

        case sw_quoted_second:
            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + ch - '0');

                if (ch == '%' || ch == '#') {
                    state = sw_usual;
                    *u++ = ch;
                    ch = *p++;
                    break;

                } else if (ch == '\0') {
                    return NGX_RTMP_PARSE_INVALID_REQUEST;
                }

                state = quoted_state;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + c - 'a' + 10);

                if (ch == '?') {
                    state = sw_usual;
                    *u++ = ch;
                    ch = *p++;
                    break;

                } else if (ch == '+') {
                    s->plus_in_uri = 1;
                }

                state = quoted_state;
                break;
            }

            return NGX_RTMP_PARSE_INVALID_REQUEST;
        }
    }

done:

    s->uri.len = *u == CR ? (u - s->uri.data) : (u - s->uri.data + 1);

    return NGX_OK;

args:

    if (*s->uri_end == CR) {
        s->uri_end -= 1;
    }

    while (p < s->uri_end) {
        if (*p++ != '#') {
            continue;
        }

        s->args.len = p - 1 - s->args_start;
        s->args.data = s->args_start;
        s->args_start = NULL;

        break;
    }

    s->uri.len = u - s->uri.data;

    return NGX_OK;
}

