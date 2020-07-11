
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) plainheart
 * Copyright (C) Winshining
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_version.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_play_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_record_module.h"


static ngx_int_t ngx_rtmp_stat_init_process(ngx_cycle_t *cycle);
static char *ngx_rtmp_stat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_rtmp_stat_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_stat_create_loc_conf(ngx_conf_t *cf);
static char * ngx_rtmp_stat_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);


static time_t                       start_time;


#define NGX_RTMP_STAT_ALL           0xff
#define NGX_RTMP_STAT_GLOBAL        0x01
#define NGX_RTMP_STAT_LIVE          0x02
#define NGX_RTMP_STAT_CLIENTS       0x04
#define NGX_RTMP_STAT_PLAY          0x08
#define NGX_RTMP_STAT_RECORD        0x10

#define NGX_RTMP_STAT_FORMAT_XML    0x01
#define NGX_RTMP_STAT_FORMAT_JSON   0x02


/*
 * global: stat-{bufs-{total,free,used}, total bytes in/out, bw in/out} - cscf
*/


typedef struct {
    ngx_uint_t                      stat;
    ngx_str_t                       stylesheet;
    ngx_uint_t                      format;
} ngx_rtmp_stat_loc_conf_t;


static ngx_conf_bitmask_t           ngx_rtmp_stat_masks[] = {
    { ngx_string("all"),            NGX_RTMP_STAT_ALL           },
    { ngx_string("global"),         NGX_RTMP_STAT_GLOBAL        },
    { ngx_string("live"),           NGX_RTMP_STAT_LIVE          },
    { ngx_string("clients"),        NGX_RTMP_STAT_CLIENTS       },
    { ngx_string("record"),         NGX_RTMP_STAT_RECORD        },
    { ngx_null_string,              0 }
};


static ngx_conf_bitmask_t           ngx_rtmp_stat_format_masks[] = {
    { ngx_string("xml"),            NGX_RTMP_STAT_FORMAT_XML       },
    { ngx_string("json"),           NGX_RTMP_STAT_FORMAT_JSON      },
    { ngx_null_string,              0 }
};


static ngx_command_t  ngx_rtmp_stat_commands[] = {

    { ngx_string("rtmp_stat"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_rtmp_stat,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_rtmp_stat_loc_conf_t, stat),
        ngx_rtmp_stat_masks },

    { ngx_string("rtmp_stat_stylesheet"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_rtmp_stat_loc_conf_t, stylesheet),
        NULL },
        
    { ngx_string("rtmp_stat_format"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_rtmp_stat,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_rtmp_stat_loc_conf_t, format),
        ngx_rtmp_stat_format_masks },

    ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_stat_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_rtmp_stat_postconfiguration,    /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_stat_create_loc_conf,      /* create location configuration */
    ngx_rtmp_stat_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_rtmp_stat_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_stat_module_ctx,          /* module context */
    ngx_rtmp_stat_commands,             /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    ngx_rtmp_stat_init_process,         /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


#define NGX_RTMP_STAT_BUFSIZE           256


static ngx_int_t
ngx_rtmp_stat_init_process(ngx_cycle_t *cycle)
{
    /*
     * HTTP process initializer is called
     * after event module initializer
     * so we can run posted events here
     */

    ngx_event_process_posted(cycle, &ngx_rtmp_init_queue);

    return NGX_OK;
}


/* ngx_escape_html does not escape characters out of ASCII range
 * which are bad for xslt */

static void *
ngx_rtmp_stat_escape(ngx_http_request_t *r, void *data, size_t len)
{
    u_char *p, *np;
    void   *new_data;
    size_t  n;

    p = data;

    for (n = 0; n < len; ++n, ++p) {
        if (*p < 0x20 || *p >= 0x7f) {
            break;
        }
    }

    if (n == len) {
        return data;
    }

    new_data = ngx_palloc(r->pool, len);
    if (new_data == NULL) {
        return NULL;
    }

    p  = data;
    np = new_data;

    for (n = 0; n < len; ++n, ++p, ++np) {
        *np = (*p < 0x20 || *p >= 0x7f) ? (u_char) ' ' : *p;
    }

    return new_data;
}


#if (NGX_WIN32)
/*
 * Fix broken MSVC memcpy optimization for 4-byte data
 * when this function is inlined
 */
__declspec(noinline)
#endif


static void
ngx_rtmp_stat_output(ngx_http_request_t *r, ngx_chain_t ***lll,
        void *data, size_t len, ngx_uint_t escape)
{
    ngx_chain_t        *cl;
    ngx_buf_t          *b;
    size_t              real_len;

    if (len == 0) {
        return;
    }

    if (escape) {
        data = ngx_rtmp_stat_escape(r, data, len);
        if (data == NULL) {
            return;
        }
    }

    real_len = escape
        ? len + ngx_escape_html(NULL, data, len)
        : len;

    cl = **lll;
    if (cl && cl->buf->last + real_len > cl->buf->end) {
        *lll = &cl->next;
    }

    if (**lll == NULL) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return;
        }
        b = ngx_create_temp_buf(r->pool,
                ngx_max(NGX_RTMP_STAT_BUFSIZE, real_len));
        if (b == NULL || b->pos == NULL) {
            return;
        }
        cl->next = NULL;
        cl->buf = b;
        **lll = cl;
    }

    b = (**lll)->buf;

    if (escape) {
        b->last = (u_char *)ngx_escape_html(b->last, data, len);
    } else {
        b->last = ngx_cpymem(b->last, data, len);
    }
}


/* These shortcuts assume 2 variables exist in current context:
 *   ngx_http_request_t    *r
 *   ngx_chain_t         ***lll */

/* plain data */
#define NGX_RTMP_STAT(data, len)    ngx_rtmp_stat_output(r, lll, data, len, 0)

/* escaped data */
#define NGX_RTMP_STAT_E(data, len)  ngx_rtmp_stat_output(r, lll, data, len, 1)

/* literal */
#define NGX_RTMP_STAT_L(s)          NGX_RTMP_STAT((s), sizeof(s) - 1)

/* ngx_str_t */
#define NGX_RTMP_STAT_S(s)          NGX_RTMP_STAT((s)->data, (s)->len)

/* escaped ngx_str_t */
#define NGX_RTMP_STAT_ES(s)         NGX_RTMP_STAT_E((s)->data, (s)->len)

/* C string */
#define NGX_RTMP_STAT_CS(s)         NGX_RTMP_STAT((s), ngx_strlen(s))

/* escaped C string */
#define NGX_RTMP_STAT_ECS(s)        NGX_RTMP_STAT_E((s), ngx_strlen(s))


#define NGX_RTMP_STAT_BW            0x01
#define NGX_RTMP_STAT_BYTES         0x02
#define NGX_RTMP_STAT_BW_BYTES      0x03


static void
ngx_rtmp_stat_bw(ngx_http_request_t *r, ngx_chain_t ***lll,
                 ngx_rtmp_bandwidth_t *bw, char *name,
                 ngx_uint_t flags)
{
    u_char                          buf[NGX_INT64_LEN + 9];
    ngx_rtmp_stat_loc_conf_t       *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    ngx_rtmp_update_bandwidth(bw, 0);

    if (flags & NGX_RTMP_STAT_BW) {
        if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
            NGX_RTMP_STAT_L("<bw_");
            NGX_RTMP_STAT_CS(name);
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), ">%uL</bw_",
                                            bw->bandwidth * 8)
                               - buf);
            NGX_RTMP_STAT_CS(name);
            NGX_RTMP_STAT_L(">\r\n");
        } else {
            NGX_RTMP_STAT_L("\"bw_");
            NGX_RTMP_STAT_CS(name);
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "\":%uL,",
                                            bw->bandwidth * 8)
                               - buf);
        }
    }

    if (flags & NGX_RTMP_STAT_BYTES) {
        if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
            NGX_RTMP_STAT_L("<bytes_");
            NGX_RTMP_STAT_CS(name);
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), ">%uL</bytes_",
                                            bw->bytes)
                               - buf);
            NGX_RTMP_STAT_CS(name);
            NGX_RTMP_STAT_L(">\r\n");
        } else {
            NGX_RTMP_STAT_L("\"bytes_");
            NGX_RTMP_STAT_CS(name);
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "\":%uL,",
                                            bw->bytes)
                               - buf);
        }
    }
}


#ifdef NGX_RTMP_POOL_DEBUG
static void
ngx_rtmp_stat_get_pool_size(ngx_pool_t *pool, ngx_uint_t *nlarge,
        ngx_uint_t *size)
{
    ngx_pool_large_t       *l;
    ngx_pool_t             *p, *n;

    *nlarge = 0;
    for (l = pool->large; l; l = l->next) {
        ++*nlarge;
    }

    *size = 0;
    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        *size += (p->d.last - (u_char *)p);
        if (n == NULL) {
            break;
        }
    }
}


static void
ngx_rtmp_stat_dump_pool(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_pool_t *pool)
{
    ngx_uint_t                      nlarge, size;
    u_char                          buf[NGX_INT_T_LEN];
    ngx_rtmp_stat_loc_conf_t       *slcf;

    size = 0;
    nlarge = 0;
    ngx_rtmp_stat_get_pool_size(pool, &nlarge, &size);

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);
    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<pool><nlarge>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui", nlarge) - buf);
        NGX_RTMP_STAT_L("</nlarge><size>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui", size) - buf);
        NGX_RTMP_STAT_L("</size></pool>\r\n");
    } else {
        NGX_RTMP_STAT_L("\"pool\":{\"nlarge\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui", nlarge) - buf);
        NGX_RTMP_STAT_L(",\"size\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui", size) - buf);
        NGX_RTMP_STAT_L("}");
    }
}
#endif


static void
ngx_rtmp_stat_client(ngx_http_request_t *r, ngx_chain_t ***lll,
    ngx_rtmp_session_t *s)
{
    u_char                          buf[NGX_INT_T_LEN];
    ngx_rtmp_stat_loc_conf_t       *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

#ifdef NGX_RTMP_POOL_DEBUG
    ngx_rtmp_stat_dump_pool(r, lll, s->connection->pool);
    if (slcf->format & NGX_RTMP_STAT_FORMAT_JSON) {
        NGX_RTMP_STAT_L(",");
    }
#endif

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<id>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui",
                      (ngx_uint_t) s->connection->number) - buf);
        NGX_RTMP_STAT_L("</id>\r\n");

        NGX_RTMP_STAT_L("<address>");
        NGX_RTMP_STAT_ES(&s->connection->addr_text);
        NGX_RTMP_STAT_L("</address>\r\n");

        NGX_RTMP_STAT_L("<time>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%i",
                      (ngx_int_t) (ngx_current_msec - s->epoch)) - buf);
        NGX_RTMP_STAT_L("</time>\r\n");

        if (s->flashver.len) {
            NGX_RTMP_STAT_L("<flashver>");
            NGX_RTMP_STAT_ES(&s->flashver);
            NGX_RTMP_STAT_L("</flashver>\r\n");
        }

        if (s->page_url.len) {
            NGX_RTMP_STAT_L("<pageurl>");
            NGX_RTMP_STAT_ES(&s->page_url);
            NGX_RTMP_STAT_L("</pageurl>\r\n");
        }

        if (s->swf_url.len) {
            NGX_RTMP_STAT_L("<swfurl>");
            NGX_RTMP_STAT_ES(&s->swf_url);
            NGX_RTMP_STAT_L("</swfurl>\r\n");
        }
    } else {
        NGX_RTMP_STAT_L("\"id\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%ui",
                      (ngx_uint_t) s->connection->number) - buf);

        NGX_RTMP_STAT_L(",\"address\":\"");
        NGX_RTMP_STAT_ES(&s->connection->addr_text);

        NGX_RTMP_STAT_L("\",\"time\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%i",
                      (ngx_int_t) (ngx_current_msec - s->epoch)) - buf);
        NGX_RTMP_STAT_L(",");

        if (s->flashver.len) {
            NGX_RTMP_STAT_L("\"flashver\":\"");
            NGX_RTMP_STAT_ES(&s->flashver);
            NGX_RTMP_STAT_L("\",");
        }

        if (s->page_url.len) {
            NGX_RTMP_STAT_L("\"pageurl\":\"");
            NGX_RTMP_STAT_ES(&s->page_url);
            NGX_RTMP_STAT_L("\",");
        }

        if (s->swf_url.len) {
            NGX_RTMP_STAT_L("\"swfurl\":\"");
            NGX_RTMP_STAT_ES(&s->swf_url);
            NGX_RTMP_STAT_L("\",");
        }
    }
}


static char *
ngx_rtmp_stat_get_aac_profile(ngx_uint_t p, ngx_uint_t sbr, ngx_uint_t ps) {
    switch (p) {
        case 1:
            return "Main";
        case 2:
            if (ps) {
                return "HEv2";
            }
            if (sbr) {
                return "HE";
            }
            return "LC";
        case 3:
            return "SSR";
        case 4:
            return "LTP";
        case 5:
            return "SBR";
        default:
            return "";
    }
}


static char *
ngx_rtmp_stat_get_avc_profile(ngx_uint_t p) {
    switch (p) {
        case 66:
            return "Baseline";
        case 77:
            return "Main";
        case 100:
            return "High";
        default:
            return "";
    }
}


static void
ngx_rtmp_stat_live_records(ngx_http_request_t *r, ngx_chain_t ***lll,
    ngx_rtmp_session_t *s)
{
    ngx_uint_t                      i;
    u_char                          buf[NGX_INT_T_LEN];
    ngx_str_t                       filename;
    ngx_file_info_t                 filebuf;
    ngx_rtmp_record_ctx_t          *rctx;
    ngx_rtmp_record_rec_ctx_t      *rrctx;
    ngx_rtmp_stat_loc_conf_t       *slcf;

    rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_record_module);
    if(rctx == NULL) {
        return;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);
    rrctx = rctx->rec.elts;

    for(i = 0; i < rctx->rec.nelts; ++i, ++rrctx) {
        if (rrctx->file.fd == NGX_INVALID_FILE) {
            continue;
        }

        if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
            NGX_RTMP_STAT_L("<record>");

            if(rrctx->conf) {
                NGX_RTMP_STAT_L("<recorder>");
                NGX_RTMP_STAT_S(&rrctx->conf->id);
                NGX_RTMP_STAT_L("</recorder>\r\n");
            }

            NGX_RTMP_STAT_L("<epoch>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                        "%ui", rrctx->epoch) - buf);
            NGX_RTMP_STAT_L("</epoch>\r\n");
            NGX_RTMP_STAT_L("<time_shift>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                        "%ui", rrctx->time_shift) - buf);
            NGX_RTMP_STAT_L("</time_shift>\r\n");

            NGX_RTMP_STAT_L("<recording/>\r\n");
            NGX_RTMP_STAT_L("<file>");
            ngx_rtmp_record_get_path(s, rrctx, &filename);
            NGX_RTMP_STAT_S(&filename);
            NGX_RTMP_STAT_L("</file>\r\n");
            NGX_RTMP_STAT_L("<time>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                    "%ui", ngx_cached_time->sec - rrctx->timestamp) - buf);
            NGX_RTMP_STAT_L("</time>\r\n");
            NGX_RTMP_STAT_L("<size>");
            ngx_file_info((const char *)filename.data, &filebuf);
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                        "%ui", ngx_file_size(&filebuf)) - buf);
            NGX_RTMP_STAT_L("</size>\r\n");
            NGX_RTMP_STAT_L("<nframes>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                        "%ui", rrctx->nframes) - buf);
            NGX_RTMP_STAT_L("</nframes>\r\n");

            NGX_RTMP_STAT_L("</record>\r\n");
        } else {
            NGX_RTMP_STAT_L("{");

            if(rrctx->conf) {
                NGX_RTMP_STAT_L("\"recorder\":\"");
                NGX_RTMP_STAT_S(&rrctx->conf->id);
                NGX_RTMP_STAT_L("\"");
            } else {
                NGX_RTMP_STAT_L("\"recorder\":\"\"");
            }

            NGX_RTMP_STAT_L(",\"epoch\":");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                        "%ui", rrctx->epoch) - buf);
            NGX_RTMP_STAT_L(",\"time_shift\":");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                        "%ui", rrctx->time_shift) - buf);

            NGX_RTMP_STAT_L(",\"recording\":true");
            NGX_RTMP_STAT_L(",\"file\":\"");
            ngx_rtmp_record_get_path(s, rrctx, &filename);
            NGX_RTMP_STAT_S(&filename);
            NGX_RTMP_STAT_L("\",\"time\":");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                    "%ui", ngx_cached_time->sec - rrctx->timestamp) - buf);
            NGX_RTMP_STAT_L(",\"size\":");
            ngx_file_info((const char *)filename.data, &filebuf);
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                        "%ui", ngx_file_size(&filebuf)) - buf);
            NGX_RTMP_STAT_L(",\"nframes\":");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                        "%ui", rrctx->nframes) - buf);

            NGX_RTMP_STAT_L("}");
        }
    }
}


static void
ngx_rtmp_stat_live(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_live_app_conf_t *lacf)
{
    ngx_rtmp_live_stream_t         *stream;
    ngx_rtmp_codec_ctx_t           *codec;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_session_t             *s;
    ngx_int_t                       n;
    ngx_uint_t                      nclients, total_nclients;
    ngx_uint_t                      f;
    ngx_flag_t                      prev;
    u_char                          buf[NGX_INT64_LEN + 4];
    u_char                          bbuf[NGX_INT32_LEN];
    ngx_rtmp_stat_loc_conf_t       *slcf;
    u_char                         *cname;

    if (!lacf->live) {
        return;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<live>\r\n");
    } else {
        NGX_RTMP_STAT_L(",\"live\":{");
        NGX_RTMP_STAT_L("\"streams\":[");
    }

    total_nclients = 0;
    prev = 0;
    for (n = 0; n < lacf->nbuckets; ++n) {
        for (stream = lacf->streams[n]; stream; stream = stream->next) {
            if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                NGX_RTMP_STAT_L("<stream>\r\n");
            } else {
                if (prev) {
                    NGX_RTMP_STAT_L(",");
                }

                prev = 1;
                NGX_RTMP_STAT_L("{");
            }

            if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                NGX_RTMP_STAT_L("<name>");
                NGX_RTMP_STAT_ECS(stream->name);
                NGX_RTMP_STAT_L("</name>\r\n");

                NGX_RTMP_STAT_L("<time>");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%i",
                              (ngx_int_t) (ngx_current_msec - stream->epoch))
                              - buf);
                NGX_RTMP_STAT_L("</time>\r\n");
            } else {
                NGX_RTMP_STAT_L("\"name\":\"");
                NGX_RTMP_STAT_ECS(stream->name);
                NGX_RTMP_STAT_L("\",");

                NGX_RTMP_STAT_L("\"time\":");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), "%i",
                              (ngx_int_t) (ngx_current_msec - stream->epoch))
                              - buf);
                NGX_RTMP_STAT_L(",");
            }

            ngx_rtmp_stat_bw(r, lll, &stream->bw_in, "in",
                             NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_bw(r, lll, &stream->bw_out, "out",
                             NGX_RTMP_STAT_BW_BYTES);
            ngx_rtmp_stat_bw(r, lll, &stream->bw_in_audio, "audio",
                             NGX_RTMP_STAT_BW);
            ngx_rtmp_stat_bw(r, lll, &stream->bw_in_video, "video",
                             NGX_RTMP_STAT_BW);

            nclients = 0;
            codec = NULL;

            if (slcf->stat & NGX_RTMP_STAT_CLIENTS &&
                slcf->format & NGX_RTMP_STAT_FORMAT_JSON)
            {
                NGX_RTMP_STAT_L("\"clients\":[");
            }

            for (ctx = stream->ctx; ctx; ctx = ctx->next, ++nclients) {
                s = ctx->session;
                if (slcf->stat & NGX_RTMP_STAT_CLIENTS) {

                    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                        NGX_RTMP_STAT_L("<client>\r\n");
                    } else {
                        NGX_RTMP_STAT_L("{");
                    }

                    ngx_rtmp_stat_client(r, lll, s);

                    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                        NGX_RTMP_STAT_L("<dropped>");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", ctx->ndropped) - buf);
                        NGX_RTMP_STAT_L("</dropped>\r\n");

                        NGX_RTMP_STAT_L("<avsync>");
                        if (!lacf->interleave) {
                            NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                          "%D", ctx->cs[1].timestamp -
                                          ctx->cs[0].timestamp) - bbuf);
                        }
                        NGX_RTMP_STAT_L("</avsync>\r\n");

                        NGX_RTMP_STAT_L("<timestamp>");
                        NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                      "%D", s->current_time) - bbuf);
                        NGX_RTMP_STAT_L("</timestamp>\r\n");

                        if (ctx->publishing) {
                            NGX_RTMP_STAT_L("<publishing/>\r\n");
                        }

                        if (ctx->active) {
                            NGX_RTMP_STAT_L("<active/>\r\n");
                        }
                    } else {
                        NGX_RTMP_STAT_L("\"dropped\":");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", ctx->ndropped) - buf);

                        NGX_RTMP_STAT_L(",\"avsync\":");
                        if (!lacf->interleave) {
                            NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                          "%D", ctx->cs[1].timestamp -
                                          ctx->cs[0].timestamp) - bbuf);
                        }

                        NGX_RTMP_STAT_L(",\"timestamp\":");
                        NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                      "%D", s->current_time) - bbuf);

                        NGX_RTMP_STAT_L(",\"publishing\":");
                        if (ctx->publishing) {
                            NGX_RTMP_STAT_L("true");
                        } else {
                            NGX_RTMP_STAT_L("false");
                        }

                        NGX_RTMP_STAT_L(",\"active\":");
                        if (ctx->active) {
                            NGX_RTMP_STAT_L("true");
                        } else {
                            NGX_RTMP_STAT_L("false");
                        }
                    }

                    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                       NGX_RTMP_STAT_L("</client>\r\n");
                    } else {
                        NGX_RTMP_STAT_L("}");
                        if (ctx->next) {
                            NGX_RTMP_STAT_L(",");
                        }
                    }
                }
                if (ctx->publishing) {
                    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
                }
            }
            total_nclients += nclients;

            if (slcf->stat & NGX_RTMP_STAT_CLIENTS &&
                slcf->format & NGX_RTMP_STAT_FORMAT_JSON)
            {
                NGX_RTMP_STAT_L("],");
            }

            if(slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                NGX_RTMP_STAT_L("<records>\r\n");
            } else {
                NGX_RTMP_STAT_L("\"records\":[");
            }

            for (ctx = stream->ctx; ctx; ctx = ctx->next) {
                /* valid for only publishers */
                if (ctx->publishing) {
                    s = ctx->session;

                    if (slcf->stat & NGX_RTMP_STAT_RECORD) {
                        ngx_rtmp_stat_live_records(r, lll, s);
                    }

                    break;
                }
            }

            if(slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                NGX_RTMP_STAT_L("</records>\r\n");
            } else {
                if (codec == NULL) {
                    NGX_RTMP_STAT_L("],");
                } else {
                    NGX_RTMP_STAT_L("]");
                }
            }

            if (codec) {
                if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                    NGX_RTMP_STAT_L("<meta>\r\n");

                    NGX_RTMP_STAT_L("<video>\r\n");
                    NGX_RTMP_STAT_L("<width>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", codec->width) - buf);
                    NGX_RTMP_STAT_L("</width>\r\n<height>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", codec->height) - buf);
                    NGX_RTMP_STAT_L("</height>\r\n<frame_rate>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%.3f", codec->frame_rate) - buf);
                    NGX_RTMP_STAT_L("</frame_rate>\r\n");

                    cname = ngx_rtmp_get_video_codec_name(codec->video_codec_id);
                    if (*cname) {
                        NGX_RTMP_STAT_L("<codec>");
                        NGX_RTMP_STAT_ECS(cname);
                        NGX_RTMP_STAT_L("</codec>\r\n");
                    }
                    if (codec->avc_profile) {
                        NGX_RTMP_STAT_L("<profile>");
                        NGX_RTMP_STAT_CS(
                            ngx_rtmp_stat_get_avc_profile(codec->avc_profile));
                        NGX_RTMP_STAT_L("</profile>\r\n");
                    }
                    if (codec->avc_compat) {
                        NGX_RTMP_STAT_L("<compat>");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", codec->avc_compat) - buf);
                        NGX_RTMP_STAT_L("</compat>\r\n");
                    }
                    if (codec->avc_level) {
                        NGX_RTMP_STAT_L("<level>");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%.1f", codec->avc_level / 10.) - buf);
                        NGX_RTMP_STAT_L("</level>\r\n");
                    }
                    NGX_RTMP_STAT_L("</video>\r\n");

                    NGX_RTMP_STAT_L("<audio>\r\n");
                    cname = ngx_rtmp_get_audio_codec_name(codec->audio_codec_id);
                    if (*cname) {
                        NGX_RTMP_STAT_L("<codec>");
                        NGX_RTMP_STAT_ECS(cname);
                        NGX_RTMP_STAT_L("</codec>\r\n");
                    }
                    if (codec->aac_profile) {
                        NGX_RTMP_STAT_L("<profile>");
                        NGX_RTMP_STAT_CS(
                            ngx_rtmp_stat_get_aac_profile(codec->aac_profile,
                                                          codec->aac_sbr,
                                                          codec->aac_ps));
                        NGX_RTMP_STAT_L("</profile>\r\n");
                    }
                    if (codec->aac_chan_conf) {
                        NGX_RTMP_STAT_L("<channels>");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", codec->aac_chan_conf) - buf);
                        NGX_RTMP_STAT_L("</channels>\r\n");
                    } else if (codec->audio_channels) {
                        NGX_RTMP_STAT_L("<channels>");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", codec->audio_channels) - buf);
                        NGX_RTMP_STAT_L("</channels>\r\n");
                    }
                    if (codec->sample_rate) {
                        NGX_RTMP_STAT_L("<sample_rate>");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", codec->sample_rate) - buf);
                        NGX_RTMP_STAT_L("</sample_rate>\r\n");
                    }
                    NGX_RTMP_STAT_L("</audio>\r\n");

                    NGX_RTMP_STAT_L("</meta>\r\n");
                } else {
                    NGX_RTMP_STAT_L(",\"meta\":{");

                    NGX_RTMP_STAT_L("\"video\":{");
                    NGX_RTMP_STAT_L("\"width\":");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", codec->width) - buf);
                    NGX_RTMP_STAT_L(",\"height\":");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%ui", codec->height) - buf);
                    NGX_RTMP_STAT_L(",\"frame_rate\":");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                  "%.3f", codec->frame_rate) - buf);

                    cname = ngx_rtmp_get_video_codec_name(codec->video_codec_id);
                    if (*cname) {
                        NGX_RTMP_STAT_L(",\"codec\":\"");
                        NGX_RTMP_STAT_ECS(cname);
                        NGX_RTMP_STAT_L("\"");
                    }
                    if (codec->avc_profile) {
                        NGX_RTMP_STAT_L(",\"profile\":\"");
                        NGX_RTMP_STAT_CS(ngx_rtmp_stat_get_avc_profile(
                                         codec->avc_profile));
                        NGX_RTMP_STAT_L("\"");
                    }
                    if (codec->avc_compat) {
                        NGX_RTMP_STAT_L(",\"compat\":");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", codec->avc_compat) - buf);
                    }
                    if (codec->avc_level) {
                        NGX_RTMP_STAT_L(",\"level\":");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%.1f", codec->avc_level / 10.) - buf);
                    }

                    NGX_RTMP_STAT_L("},\"audio\":{");
                    cname = ngx_rtmp_get_audio_codec_name(codec->audio_codec_id);
                    f = 0;
                    if (*cname) {
                        f = 1;
                        NGX_RTMP_STAT_L("\"codec\":\"");
                        NGX_RTMP_STAT_ECS(cname);
                    }
                    if (codec->aac_profile) {
                        if (f == 1) NGX_RTMP_STAT_L("\",");
                        f = 2;
                        NGX_RTMP_STAT_L("\"profile\":\"");
                        NGX_RTMP_STAT_CS(
                            ngx_rtmp_stat_get_aac_profile(codec->aac_profile,
                                                          codec->aac_sbr,
                                                          codec->aac_ps));
                    }
                    if (codec->aac_chan_conf) {
                        if (f >= 1) NGX_RTMP_STAT_L("\",");
                        f = 3;
                        NGX_RTMP_STAT_L("\"channels\":");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", codec->aac_chan_conf) - buf);
                    } else if (codec->audio_channels) {
                        if (f >= 1) NGX_RTMP_STAT_L("\",");
                        f = 3;
                        NGX_RTMP_STAT_L("\"channels\":");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", codec->audio_channels) - buf);
                    }
                    if (codec->sample_rate) {
                        if (f == 1 || f == 2) {
                            NGX_RTMP_STAT_L("\",");
                        } else if (f == 3) {
                            NGX_RTMP_STAT_L(",");
                        }
                        f = 4;
                        NGX_RTMP_STAT_L("\"sample_rate\":");
                        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                                      "%ui", codec->sample_rate) - buf);
                    }
                    if (f == 1 || f == 2) {
                        NGX_RTMP_STAT_L("\"");
                    }
                    NGX_RTMP_STAT_L("}}");
                }
            }

            if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                NGX_RTMP_STAT_L("<nclients>");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", nclients) - buf);
                NGX_RTMP_STAT_L("</nclients>\r\n");

                if (stream->publishing) {
                    NGX_RTMP_STAT_L("<publishing/>\r\n");
                }

                if (stream->active) {
                    NGX_RTMP_STAT_L("<active/>\r\n");
                }

                NGX_RTMP_STAT_L("</stream>\r\n");
            } else {
                if (codec) {
                    NGX_RTMP_STAT_L(",");
                }
                NGX_RTMP_STAT_L("\"nclients\":");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", nclients) - buf);

                NGX_RTMP_STAT_L(",\"publishing\":");
                if (stream->publishing) {
                    NGX_RTMP_STAT_L("true");
                } else {
                    NGX_RTMP_STAT_L("false");
                }

                NGX_RTMP_STAT_L(",\"active\":");
                if (stream->active) {
                    NGX_RTMP_STAT_L("true");
                } else {
                    NGX_RTMP_STAT_L("false");
                }

                NGX_RTMP_STAT_L("}");
            }
        }
    }

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<nclients>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", total_nclients) - buf);
        NGX_RTMP_STAT_L("</nclients>\r\n");
        NGX_RTMP_STAT_L("</live>\r\n");
    } else {
        NGX_RTMP_STAT_L("],\"nclients\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", total_nclients) - buf);
        NGX_RTMP_STAT_L("}");
    }
}


static void
ngx_rtmp_stat_play(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_play_app_conf_t *pacf)
{
    ngx_rtmp_play_ctx_t            *ctx, *sctx;
    ngx_rtmp_session_t             *s;
    ngx_uint_t                      n, nclients, total_nclients;
    ngx_flag_t                      prev;
    u_char                          buf[NGX_INT_T_LEN];
    u_char                          bbuf[NGX_INT32_LEN];
    ngx_rtmp_stat_loc_conf_t       *slcf;

    if (pacf->entries.nelts == 0) {
        return;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);
    
    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<play>\r\n");
    } else {
        NGX_RTMP_STAT_L(",\"play\":{");
        NGX_RTMP_STAT_L("\"streams\":[");
    }

    total_nclients = 0;
    prev = 0;
    for (n = 0; n < pacf->nbuckets; ++n) {
        for (ctx = pacf->ctx[n]; ctx; ) {
            if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                NGX_RTMP_STAT_L("<stream>\r\n");
                NGX_RTMP_STAT_L("<name>");
                NGX_RTMP_STAT_ECS(ctx->name);
                NGX_RTMP_STAT_L("</name>\r\n");
            } else {
                if (prev) {
                    NGX_RTMP_STAT_L(",");
                }

                prev = 1;
                NGX_RTMP_STAT_L("{\"name\":\"");
                NGX_RTMP_STAT_ECS(ctx->name);
                NGX_RTMP_STAT_L("\",\"clients\":[");
            }

            nclients = 0;
            sctx = ctx;
            for (; ctx; ctx = ctx->next) {
                if (ngx_strcmp(ctx->name, sctx->name)) {
                    break;
                }

                nclients++;

                s = ctx->session;
                if (slcf->stat & NGX_RTMP_STAT_CLIENTS) {
                    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                        NGX_RTMP_STAT_L("<client>\r\n");

                        ngx_rtmp_stat_client(r, lll, s);

                        NGX_RTMP_STAT_L("<timestamp>");
                        NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                      "%D", s->current_time) - bbuf);
                        NGX_RTMP_STAT_L("</timestamp>\r\n");

                        NGX_RTMP_STAT_L("</client>\r\n");
                    } else {
                        NGX_RTMP_STAT_L("{");

                        ngx_rtmp_stat_client(r, lll, s);

                        NGX_RTMP_STAT_L("\"timestamp\":");
                        NGX_RTMP_STAT(bbuf, ngx_snprintf(bbuf, sizeof(bbuf),
                                      "%D", s->current_time) - bbuf);

                        NGX_RTMP_STAT_L("}");
                    }
                }
            }
            total_nclients += nclients;
            if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
                NGX_RTMP_STAT_L("<active/>");
                NGX_RTMP_STAT_L("<nclients>");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", nclients) - buf);
                NGX_RTMP_STAT_L("</nclients>\r\n");

                NGX_RTMP_STAT_L("</stream>\r\n");             
            } else {
                NGX_RTMP_STAT_L("],");
                NGX_RTMP_STAT_L("\"active\":true,");
                NGX_RTMP_STAT_L("\"nclients\":");
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", nclients) - buf);
                NGX_RTMP_STAT_L("}");
            }
        }
    }

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<nclients>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", total_nclients) - buf);
        NGX_RTMP_STAT_L("</nclients>\r\n");
        NGX_RTMP_STAT_L("</play>\r\n");
    } else {
        NGX_RTMP_STAT_L("],\"nclients\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", total_nclients) - buf);
        NGX_RTMP_STAT_L("}");
    }
}


static void
ngx_rtmp_stat_application_recorders(ngx_http_request_t *r, ngx_chain_t ***lll,
    ngx_rtmp_core_app_conf_t *cacf)
{
    size_t                       n, len;
    u_char                       flag[NGX_RTMP_MAX_URL];
    u_char                       buf[NGX_INT_T_LEN];
    ngx_rtmp_record_app_conf_t  *racf, *lracf, **rracf;
    ngx_rtmp_stat_loc_conf_t    *slcf;

    racf = cacf->app_conf[ngx_rtmp_record_module.ctx_index];
    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    if(slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<recorders>\r\n");
        NGX_RTMP_STAT_L("<count>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", racf->rec.nelts) - buf);
        NGX_RTMP_STAT_L("</count>\r\n");
    } else {
        NGX_RTMP_STAT_L(",\"recorder\":{");
        NGX_RTMP_STAT_L("\"count\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", racf->rec.nelts) - buf);
        NGX_RTMP_STAT_L(",\"list\":[");           
    }

    rracf = racf->rec.elts;
    for(n = 0; n < racf->rec.nelts; ++n, ++rracf) {
        lracf = *rracf;

        if(n > 0 && n < racf->rec.nelts - 1) {
            NGX_RTMP_STAT_L(",");
        }

        if(slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
            NGX_RTMP_STAT_L("<recorder>\r\n");

            NGX_RTMP_STAT_L("<id>");
            NGX_RTMP_STAT_S(&lracf->id);
            NGX_RTMP_STAT_L("</id>\r\n");

            NGX_RTMP_STAT_L("<flags>");

            if(lracf->flags & NGX_RTMP_RECORD_OFF) {
                NGX_RTMP_STAT_L("<off/>");
            }

            if(lracf->flags & NGX_RTMP_RECORD_VIDEO) {
                NGX_RTMP_STAT_L("<video/>");
            }

            if(lracf->flags & NGX_RTMP_RECORD_AUDIO) {
                NGX_RTMP_STAT_L("<audio/>");
            }

            if(lracf->flags & NGX_RTMP_RECORD_KEYFRAMES) {
                NGX_RTMP_STAT_L("<keyframes/>");
            }

            if(lracf->flags & NGX_RTMP_RECORD_MANUAL) {
                NGX_RTMP_STAT_L("<manual/>");
            }

            NGX_RTMP_STAT_L("</flags>\r\n");

            if(lracf->unique) {
                NGX_RTMP_STAT_L("<unique/>\r\n");
            }

            if(lracf->append) {
                NGX_RTMP_STAT_L("<append/>\r\n");
            }

            if(lracf->lock_file) {
                NGX_RTMP_STAT_L("<lock_file/>\r\n");
            }

            if(lracf->notify) {
                NGX_RTMP_STAT_L("<notify/>\r\n");
            }

            NGX_RTMP_STAT_L("<path>");
            NGX_RTMP_STAT_S(&lracf->path);
            NGX_RTMP_STAT_L("</path>\r\n");

            NGX_RTMP_STAT_L("<max_size>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", (ngx_uint_t)lracf->max_size) - buf);
            NGX_RTMP_STAT_L("</max_size>\r\n");

            NGX_RTMP_STAT_L("<max_frames>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", (ngx_uint_t)lracf->max_frames) - buf);
            NGX_RTMP_STAT_L("</max_frames>\r\n");

            NGX_RTMP_STAT_L("<interval>");

            if (lracf->interval == NGX_CONF_UNSET_MSEC) {
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%d", -1) - buf);
            } else {
                NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                              "%ui", lracf->interval) - buf);
            }

            NGX_RTMP_STAT_L("</interval>\r\n");

            NGX_RTMP_STAT_L("<suffix>");
            NGX_RTMP_STAT_S(&lracf->suffix);
            NGX_RTMP_STAT_L("</suffix>\r\n");

            NGX_RTMP_STAT_L("</recorder>\r\n");
        } else {
            NGX_RTMP_STAT_L("{\"id\":\"");
            NGX_RTMP_STAT_S(&lracf->id);
            NGX_RTMP_STAT_L("\",\"flags\":[");

            ngx_memzero(flag, sizeof(flag));

            if(lracf->flags & NGX_RTMP_RECORD_OFF) {
                *ngx_snprintf(flag + ngx_strlen(flag),
                              NGX_RTMP_MAX_URL - ngx_strlen(flag),
                              "%s", "\"off\"") = 0;
            }

            if(lracf->flags & NGX_RTMP_RECORD_VIDEO) {
                len = ngx_strlen(flag);
                if (len && len < NGX_RTMP_MAX_URL && flag[len - 1] != ',') {
                    flag[len++] = ',';
                }

                if (NGX_RTMP_MAX_URL - len > sizeof("\"video\"")) {
                    *ngx_snprintf(flag + ngx_strlen(flag),
                                  NGX_RTMP_MAX_URL - len,
                                  "%s", "\"video\"") = 0;
                } else {
                    flag[len - 1] = 0;
                }
            }

            if(lracf->flags & NGX_RTMP_RECORD_AUDIO) {
                len = ngx_strlen(flag);
                if (len && len < NGX_RTMP_MAX_URL && flag[len - 1] != ',') {
                    flag[len++] = ',';
                }

                if (NGX_RTMP_MAX_URL - len > sizeof("\"audio\"")) {
                    *ngx_snprintf(flag + ngx_strlen(flag),
                                  NGX_RTMP_MAX_URL - len,
                                  "%s", "\"audio\"") = 0;
                } else {
                    flag[len - 1] = 0;
                }
            }

            if(lracf->flags & NGX_RTMP_RECORD_KEYFRAMES) {
                len = ngx_strlen(flag);
                if (len && len < NGX_RTMP_MAX_URL && flag[len - 1] != ',') {
                    flag[len++] = ',';
                }

                if (NGX_RTMP_MAX_URL - len > sizeof("\"keyframes\"")) {
                    *ngx_snprintf(flag + ngx_strlen(flag),
                                  NGX_RTMP_MAX_URL - len,
                                  "%s", "\"keyframes\"") = 0;
                } else {
                    flag[len - 1] = 0;
                }
            }

            if(lracf->flags & NGX_RTMP_RECORD_MANUAL) {
                len = ngx_strlen(flag);
                if (len && len < NGX_RTMP_MAX_URL && flag[len - 1] != ',') {
                    flag[len++] = ',';
                }

                if (NGX_RTMP_MAX_URL - len > sizeof("\"manual\"")) {
                    *ngx_snprintf(flag + ngx_strlen(flag),
                                  NGX_RTMP_MAX_URL - len,
                                  "%s", "\"manual\"") = 0;
                } else {
                    flag[len - 1] = 0;
                }
            }

            NGX_RTMP_STAT_CS(flag);

            NGX_RTMP_STAT_L("]");

            if(lracf->unique) {
                NGX_RTMP_STAT_L(",\"unique\":true");
            } else {
                NGX_RTMP_STAT_L(",\"unique\":false");
            }

            if(lracf->append) {
                NGX_RTMP_STAT_L(",\"append\":true");
            } else {
                NGX_RTMP_STAT_L(",\"append\":false");
            }

            if(lracf->lock_file) {
                NGX_RTMP_STAT_L(",\"lock_file\":true");
            } else {
                NGX_RTMP_STAT_L(",\"lock_file\":false");
            }

            if(lracf->notify) {
                NGX_RTMP_STAT_L(",\"notify\":true");
            } else {
                NGX_RTMP_STAT_L(",\"notify\":false");
            }

            NGX_RTMP_STAT_L(",\"path\":\"");
            NGX_RTMP_STAT_S(&lracf->path);

            NGX_RTMP_STAT_L("\",\"max_size\":");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", (ngx_uint_t)lracf->max_size) - buf);

            NGX_RTMP_STAT_L(",\"max_frames\":");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", (ngx_uint_t)lracf->max_frames) - buf);

            NGX_RTMP_STAT_L(",\"interval\":");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                          "%ui", lracf->interval) - buf);

            NGX_RTMP_STAT_L(",\"suffix\":\"");
            NGX_RTMP_STAT_S(&lracf->suffix);
            NGX_RTMP_STAT_L("\"}");
        }
    }

    if(slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("</recorders>\r\n");
    } else {
        NGX_RTMP_STAT_L("]}");
    }
}


static void
ngx_rtmp_stat_application(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_core_srv_conf_t *cscf, ngx_rtmp_core_app_conf_t *cacf)
{
    ngx_rtmp_stat_loc_conf_t       *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<application>\r\n");
        NGX_RTMP_STAT_L("<name>");
        NGX_RTMP_STAT_ES(&cacf->name);
        NGX_RTMP_STAT_L("</name>\r\n");
    } else {
        NGX_RTMP_STAT_L("{");
        NGX_RTMP_STAT_L("\"name\":\"");
        NGX_RTMP_STAT_ES(&cacf->name);
        NGX_RTMP_STAT_L("\"");
    }

    if (slcf->stat & NGX_RTMP_STAT_LIVE) {
        ngx_rtmp_stat_live(r, lll,
                cacf->app_conf[ngx_rtmp_live_module.ctx_index]);
    }

    if (slcf->stat & NGX_RTMP_STAT_PLAY) {
        ngx_rtmp_stat_play(r, lll,
                cacf->app_conf[ngx_rtmp_play_module.ctx_index]);
    }

    if (slcf->stat & NGX_RTMP_STAT_RECORD) {
        ngx_rtmp_stat_application_recorders(r, lll, cacf);
    }

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("</application>\r\n");
    } else {
        NGX_RTMP_STAT_L("}");
    }
}


static void
ngx_rtmp_stat_server(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_core_srv_conf_t *cscf)
{
    u_char                          buf[NGX_INT_T_LEN];
    size_t                          n;
    ngx_rtmp_core_app_conf_t      **cacf;
    ngx_rtmp_stat_loc_conf_t       *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<server>\r\n");
        NGX_RTMP_STAT_L("<port>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", cscf->port) - buf);
        NGX_RTMP_STAT_L("</port>\r\n");
        NGX_RTMP_STAT_L("<server_index>");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", cscf->index) - buf);
        NGX_RTMP_STAT_L("</server_index>\r\n");
    } else {
        NGX_RTMP_STAT_L("{");
        NGX_RTMP_STAT_L("\"port\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", cscf->port) - buf);
        NGX_RTMP_STAT_L(",");
        NGX_RTMP_STAT_L("\"server_index\":");
        NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf),
                      "%ui", cscf->index) - buf);
        NGX_RTMP_STAT_L(",");
    }

#ifdef NGX_RTMP_POOL_DEBUG
    ngx_rtmp_stat_dump_pool(r, lll, cscf->pool);
    if (slcf->format & NGX_RTMP_STAT_FORMAT_JSON) {
        NGX_RTMP_STAT_L(",");
    }
#endif

    if (slcf->format & NGX_RTMP_STAT_FORMAT_JSON) {
        NGX_RTMP_STAT_L("\"applications\":[");
    }

    cacf = cscf->applications.elts;
    for (n = 0; n < cscf->applications.nelts; ++n, ++cacf) {
        ngx_rtmp_stat_application(r, lll, cscf, *cacf);

        if (slcf->format & NGX_RTMP_STAT_FORMAT_JSON &&
            n < cscf->applications.nelts - 1)
        {
            NGX_RTMP_STAT_L(",");
        }
    }

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("</server>\r\n");
    } else {
        NGX_RTMP_STAT_L("]}");
    }
}


static ngx_int_t
ngx_rtmp_stat_handler(ngx_http_request_t *r)
{
    ngx_rtmp_stat_loc_conf_t       *slcf;
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_core_srv_conf_t      **cscf;
    ngx_chain_t                    *cl, *l, **ll, ***lll;
    size_t                          n;
    off_t                           len;
    static u_char                   tbuf[NGX_TIME_T_LEN];
    static u_char                   nbuf[NGX_INT_T_LEN];

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);
    if (slcf->stat == 0) {
        return NGX_DECLINED;
    }

    if (slcf->format == 0) {
        slcf->format = NGX_RTMP_STAT_FORMAT_XML;
    }

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL) {
        goto error;
    }

    cl = NULL;
    ll = &cl;
    lll = &ll;

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n");
        if (slcf->stylesheet.len) {
            NGX_RTMP_STAT_L("<?xml-stylesheet type=\"text/xsl\" href=\"");
            NGX_RTMP_STAT_ES(&slcf->stylesheet);
            NGX_RTMP_STAT_L("\" ?>\r\n");
        }

        NGX_RTMP_STAT_L("<http-flv>\r\n");

    #ifdef NGINX_VERSION
        NGX_RTMP_STAT_L("<nginx_version>" NGINX_VERSION "</nginx_version>\r\n");
    #endif

    #ifdef NGINX_RTMP_VERSION
        NGX_RTMP_STAT_L("<nginx_http_flv_version>"
                        NGINX_RTMP_VERSION
                        "</nginx_http_flv_version>\r\n");
    #endif

    #ifdef NGX_COMPILER
        NGX_RTMP_STAT_L("<compiler>" NGX_COMPILER "</compiler>\r\n");
    #endif
        NGX_RTMP_STAT_L("<built>" __DATE__ " " __TIME__ "</built>\r\n");

        NGX_RTMP_STAT_L("<pid>");
        NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                      "%ui", (ngx_uint_t) ngx_getpid()) - nbuf);
        NGX_RTMP_STAT_L("</pid>\r\n");

        NGX_RTMP_STAT_L("<uptime>");
        NGX_RTMP_STAT(tbuf, ngx_snprintf(tbuf, sizeof(tbuf),
                      "%T", ngx_cached_time->sec - start_time) - tbuf);
        NGX_RTMP_STAT_L("</uptime>\r\n");

        NGX_RTMP_STAT_L("<naccepted>");
        NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                      "%ui", ngx_rtmp_naccepted) - nbuf);
        NGX_RTMP_STAT_L("</naccepted>\r\n");
    } else {
        NGX_RTMP_STAT_L("{\"http-flv\":{");

    #ifdef NGINX_VERSION
        NGX_RTMP_STAT_L("\"nginx_version\":\"" NGINX_VERSION "\",");
    #endif

    #ifdef NGINX_RTMP_VERSION
        NGX_RTMP_STAT_L("\"nginx_http_flv_version\":\""
                        NGINX_RTMP_VERSION
                        "\",");
    #endif

    #ifdef NGX_COMPILER
        NGX_RTMP_STAT_L("\"compiler\":\"" NGX_COMPILER "\",");
    #endif
        NGX_RTMP_STAT_L("\"built\":\"" __DATE__ " " __TIME__ "\",");

        NGX_RTMP_STAT_L("\"pid\":");
        NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                      "%ui", (ngx_uint_t) ngx_getpid()) - nbuf);
        NGX_RTMP_STAT_L(",");

        NGX_RTMP_STAT_L("\"uptime\":");
        NGX_RTMP_STAT(tbuf, ngx_snprintf(tbuf, sizeof(tbuf),
                      "%T", ngx_cached_time->sec - start_time) - tbuf);
        NGX_RTMP_STAT_L(",");

        NGX_RTMP_STAT_L("\"naccepted\":");
        NGX_RTMP_STAT(nbuf, ngx_snprintf(nbuf, sizeof(nbuf),
                      "%ui", ngx_rtmp_naccepted) - nbuf);
        NGX_RTMP_STAT_L(",");
    }

    ngx_rtmp_stat_bw(r, lll, &ngx_rtmp_bw_in, "in", NGX_RTMP_STAT_BW_BYTES);
    ngx_rtmp_stat_bw(r, lll, &ngx_rtmp_bw_out, "out", NGX_RTMP_STAT_BW_BYTES);
    
    if (slcf->format & NGX_RTMP_STAT_FORMAT_JSON) {
        NGX_RTMP_STAT_L("\"servers\":[");
    }

    cscf = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; ++n, ++cscf) {
        ngx_rtmp_stat_server(r, lll, *cscf);
        if (n < cmcf->servers.nelts - 1 &&
            slcf->format & NGX_RTMP_STAT_FORMAT_JSON)
        {
            NGX_RTMP_STAT_L(",");
        }
    }

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        NGX_RTMP_STAT_L("</http-flv>\r\n");
    } else {
        NGX_RTMP_STAT_L("]}}");
    }

    len = 0;
    for (l = cl; l; l = l->next) {
        len += (l->buf->last - l->buf->pos);
    }

    if (slcf->format & NGX_RTMP_STAT_FORMAT_XML) {
        ngx_str_set(&r->headers_out.content_type, "text/xml");
    } else {
        ngx_str_set(&r->headers_out.content_type, "application/json");
    }
    r->headers_out.content_length_n = len;
    r->headers_out.status = NGX_HTTP_OK;
    ngx_http_send_header(r);
    (*ll)->buf->last_buf = 1;
    return ngx_http_output_filter(r, cl);

error:
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
}


static void *
ngx_rtmp_stat_create_loc_conf(ngx_conf_t *cf)
{
    ngx_rtmp_stat_loc_conf_t       *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_stat_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->stat = 0;

    return conf;
}


static char *
ngx_rtmp_stat_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_stat_loc_conf_t       *prev = parent;
    ngx_rtmp_stat_loc_conf_t       *conf = child;

    ngx_conf_merge_bitmask_value(conf->stat, prev->stat, 0);
    ngx_conf_merge_str_value(conf->stylesheet, prev->stylesheet, "");

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_stat(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_rtmp_stat_handler;

    return ngx_conf_set_bitmask_slot(cf, cmd, conf);
}


static ngx_int_t
ngx_rtmp_stat_postconfiguration(ngx_conf_t *cf)
{
    start_time = ngx_cached_time->sec;

    return NGX_OK;
}
