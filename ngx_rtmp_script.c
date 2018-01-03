
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Winshining
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"


static ngx_int_t ngx_rtmp_script_init_arrays(ngx_rtmp_script_compile_t *sc);
static ngx_int_t ngx_rtmp_script_done(ngx_rtmp_script_compile_t *sc);
static ngx_int_t ngx_rtmp_script_add_copy_code(ngx_rtmp_script_compile_t *sc,
    ngx_str_t *value, ngx_uint_t last);
static ngx_int_t ngx_rtmp_script_add_var_code(ngx_rtmp_script_compile_t *sc,
    ngx_str_t *name);
static ngx_int_t ngx_rtmp_script_add_args_code(ngx_rtmp_script_compile_t *sc);
#if (NGX_PCRE)
static ngx_int_t ngx_rtmp_script_add_capture_code(ngx_rtmp_script_compile_t *sc,
    ngx_uint_t n);
#endif
static ngx_int_t
    ngx_rtmp_script_add_full_name_code(ngx_rtmp_script_compile_t *sc);
static size_t ngx_rtmp_script_full_name_len_code(ngx_rtmp_script_engine_t *e);
static void ngx_rtmp_script_full_name_code(ngx_rtmp_script_engine_t *e);


#define ngx_rtmp_script_exit  (u_char *) &ngx_rtmp_script_exit_code

static uintptr_t ngx_rtmp_script_exit_code = (uintptr_t) NULL;


void
ngx_rtmp_script_flush_complex_value(ngx_rtmp_session_t *s,
    ngx_rtmp_complex_value_t *val)
{
    ngx_uint_t *index;

    index = val->flushes;

    if (index) {
        while (*index != (ngx_uint_t) -1) {

            if (s->variables[*index].no_cacheable) {
                s->variables[*index].valid = 0;
                s->variables[*index].not_found = 0;
            }

            index++;
        }
    }
}


ngx_int_t
ngx_rtmp_complex_value(ngx_rtmp_session_t *s, ngx_rtmp_complex_value_t *val,
    ngx_str_t *value)
{
    size_t                        len;
    ngx_rtmp_script_code_pt       code;
    ngx_rtmp_script_len_code_pt   lcode;
    ngx_rtmp_script_engine_t      e;

    if (val->lengths == NULL) {
        *value = val->value;
        return NGX_OK;
    }

    ngx_rtmp_script_flush_complex_value(s, val);

    ngx_memzero(&e, sizeof(ngx_rtmp_script_engine_t));

    e.ip = val->lengths;
    e.request = s;
    e.flushed = 1;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(ngx_rtmp_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = ngx_pnalloc(s->connection->pool, len);
    if (value->data == NULL) {
        return NGX_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;
    e.buf = *value;

    while (*(uintptr_t *) e.ip) {
        code = *(ngx_rtmp_script_code_pt *) e.ip;
        code((ngx_rtmp_script_engine_t *) &e);
    }

    *value = e.buf;

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_compile_complex_value(ngx_rtmp_compile_complex_value_t *ccv)
{
    ngx_str_t                  *v;
    ngx_uint_t                  i, n, nv, nc;
    ngx_array_t                 flushes, lengths, values, *pf, *pl, *pv;
    ngx_rtmp_script_compile_t   sc;

    v = ccv->value;

    nv = 0;
    nc = 0;

    for (i = 0; i < v->len; i++) {
        if (v->data[i] == '$') {
            if (v->data[i + 1] >= '1' && v->data[i + 1] <= '9') {
                nc++;

            } else {
                nv++;
            }
        }
    }

    if ((v->len == 0 || v->data[0] != '$')
        && (ccv->conf_prefix || ccv->root_prefix))
    {
        if (ngx_conf_full_name(ccv->cf->cycle, v, ccv->conf_prefix) != NGX_OK) {
            return NGX_ERROR;
        }

        ccv->conf_prefix = 0;
        ccv->root_prefix = 0;
    }

    ccv->complex_value->value = *v;
    ccv->complex_value->flushes = NULL;
    ccv->complex_value->lengths = NULL;
    ccv->complex_value->values = NULL;

    if (nv == 0 && nc == 0) {
        return NGX_OK;
    }

    n = nv + 1;

    if (ngx_array_init(&flushes, ccv->cf->pool, n, sizeof(ngx_uint_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    n = nv * (2 * sizeof(ngx_rtmp_script_copy_code_t)
                  + sizeof(ngx_rtmp_script_var_code_t))
        + sizeof(uintptr_t);

    if (ngx_array_init(&lengths, ccv->cf->pool, n, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    n = (nv * (2 * sizeof(ngx_rtmp_script_copy_code_t)
                   + sizeof(ngx_rtmp_script_var_code_t))
                + sizeof(uintptr_t)
                + v->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    if (ngx_array_init(&values, ccv->cf->pool, n, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    pf = &flushes;
    pl = &lengths;
    pv = &values;

    ngx_memzero(&sc, sizeof(ngx_rtmp_script_compile_t));

    sc.cf = ccv->cf;
    sc.source = v;
    sc.flushes = &pf;
    sc.lengths = &pl;
    sc.values = &pv;
    sc.complete_lengths = 1;
    sc.complete_values = 1;
    sc.zero = ccv->zero;
    sc.conf_prefix = ccv->conf_prefix;
    sc.root_prefix = ccv->root_prefix;

    if (ngx_rtmp_script_compile(&sc) != NGX_OK) {
        return NGX_ERROR;
    }

    if (flushes.nelts) {
        ccv->complex_value->flushes = flushes.elts;
        ccv->complex_value->flushes[flushes.nelts] = (ngx_uint_t) -1;
    }

    ccv->complex_value->lengths = lengths.elts;
    ccv->complex_value->values = values.elts;

    return NGX_OK;
}


char *
ngx_rtmp_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t                          *value;
    ngx_rtmp_complex_value_t          **cv;
    ngx_rtmp_compile_complex_value_t    ccv;

    cv = (ngx_rtmp_complex_value_t **) (p + cmd->offset);

    if (*cv != NULL) {
        return "duplicate";
    }

    *cv = ngx_palloc(cf->pool, sizeof(ngx_rtmp_complex_value_t));
    if (*cv == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_rtmp_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (ngx_rtmp_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_rtmp_test_predicates(ngx_rtmp_session_t *s, ngx_array_t *predicates)
{
    ngx_str_t                  val;
    ngx_uint_t                 i;
    ngx_rtmp_complex_value_t  *cv;

    if (predicates == NULL) {
        return NGX_OK;
    }

    cv = predicates->elts;

    for (i = 0; i < predicates->nelts; i++) {
        if (ngx_rtmp_complex_value(s, &cv[i], &val) != NGX_OK) {
            return NGX_ERROR;
        }

        if (val.len && (val.len != 1 || val.data[0] != '0')) {
            return NGX_DECLINED;
        }
    }

    return NGX_OK;
}


char *
ngx_rtmp_set_predicate_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t                          *value;
    ngx_uint_t                          i;
    ngx_array_t                       **a;
    ngx_rtmp_complex_value_t           *cv;
    ngx_rtmp_compile_complex_value_t    ccv;

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a == NGX_CONF_UNSET_PTR) {
        *a = ngx_array_create(cf->pool, 1, sizeof(ngx_rtmp_complex_value_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        cv = ngx_array_push(*a);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_rtmp_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (ngx_rtmp_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


ngx_uint_t
ngx_rtmp_script_variables_count(ngx_str_t *value)
{
    ngx_uint_t  i, n;

    for (n = 0, i = 0; i < value->len; i++) {
        if (value->data[i] == '$') {
            n++;
        }
    }

    return n;
}


ngx_int_t
ngx_rtmp_script_compile(ngx_rtmp_script_compile_t *sc)
{
    u_char       ch;
    ngx_str_t    name;
    ngx_uint_t   i, bracket;

    if (ngx_rtmp_script_init_arrays(sc) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < sc->source->len; /* void */ ) {

        name.len = 0;

        if (sc->source->data[i] == '$') {

            if (++i == sc->source->len) {
                goto invalid_variable;
            }

            if (sc->source->data[i] >= '1' && sc->source->data[i] <= '9') {
#if (NGX_PCRE)
                ngx_uint_t  n;

                n = sc->source->data[i] - '0';

                if (sc->captures_mask & ((ngx_uint_t) 1 << n)) {
                    sc->dup_capture = 1;
                }

                sc->captures_mask |= (ngx_uint_t) 1 << n;

                if (ngx_rtmp_script_add_capture_code(sc, n) != NGX_OK) {
                    return NGX_ERROR;
                }

                i++;

                continue;
#else
                ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0,
                                   "using variable \"$%c\" requires "
                                   "PCRE library", sc->source->data[i]);
                return NGX_ERROR;
#endif
            }

            if (sc->source->data[i] == '{') {
                bracket = 1;

                if (++i == sc->source->len) {
                    goto invalid_variable;
                }

                name.data = &sc->source->data[i];

            } else {
                bracket = 0;
                name.data = &sc->source->data[i];
            }

            for ( /* void */ ; i < sc->source->len; i++, name.len++) {
                ch = sc->source->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0,
                                   "the closing bracket in \"%V\" "
                                   "variable is missing", &name);
                return NGX_ERROR;
            }

            if (name.len == 0) {
                goto invalid_variable;
            }

            sc->variables++;

            if (ngx_rtmp_script_add_var_code(sc, &name) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        if (sc->source->data[i] == '?' && sc->compile_args) {
            sc->args = 1;
            sc->compile_args = 0;

            if (ngx_rtmp_script_add_args_code(sc) != NGX_OK) {
                return NGX_ERROR;
            }

            i++;

            continue;
        }

        name.data = &sc->source->data[i];

        while (i < sc->source->len) {

            if (sc->source->data[i] == '$') {
                break;
            }

            if (sc->source->data[i] == '?') {

                sc->args = 1;

                if (sc->compile_args) {
                    break;
                }
            }

            i++;
            name.len++;
        }

        sc->size += name.len;

        if (ngx_rtmp_script_add_copy_code(sc, &name, (i == sc->source->len))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return ngx_rtmp_script_done(sc);

invalid_variable:

    ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return NGX_ERROR;
}


u_char *
ngx_rtmp_script_run(ngx_rtmp_session_t *s, ngx_str_t *value,
    void *code_lengths, size_t len, void *code_values)
{
    ngx_uint_t                    i;
    ngx_rtmp_script_code_pt       code;
    ngx_rtmp_script_len_code_pt   lcode;
    ngx_rtmp_script_engine_t      e;
    ngx_rtmp_core_main_conf_t    *cmcf;

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (s->variables[i].no_cacheable) {
            s->variables[i].valid = 0;
            s->variables[i].not_found = 0;
        }
    }

    ngx_memzero(&e, sizeof(ngx_rtmp_script_engine_t));

    e.ip = code_lengths;
    e.request = s;
    e.flushed = 1;

    while (*(uintptr_t *) e.ip) {
        lcode = *(ngx_rtmp_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    value->len = len;
    value->data = ngx_pnalloc(s->connection->pool, len);
    if (value->data == NULL) {
        return NULL;
    }

    e.ip = code_values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(ngx_rtmp_script_code_pt *) e.ip;
        code((ngx_rtmp_script_engine_t *) &e);
    }

    return e.pos;
}


void
ngx_rtmp_script_flush_no_cacheable_variables(ngx_rtmp_session_t *s,
    ngx_array_t *indices)
{
    ngx_uint_t  n, *index;

    if (indices) {
        index = indices->elts;
        for (n = 0; n < indices->nelts; n++) {
            if (s->variables[index[n]].no_cacheable) {
                s->variables[index[n]].valid = 0;
                s->variables[index[n]].not_found = 0;
            }
        }
    }
}


static ngx_int_t
ngx_rtmp_script_init_arrays(ngx_rtmp_script_compile_t *sc)
{
    ngx_uint_t   n;

    if (sc->flushes && *sc->flushes == NULL) {
        n = sc->variables ? sc->variables : 1;
        *sc->flushes = ngx_array_create(sc->cf->pool, n, sizeof(ngx_uint_t));
        if (*sc->flushes == NULL) {
            return NGX_ERROR;
        }
    }

    if (*sc->lengths == NULL) {
        n = sc->variables * (2 * sizeof(ngx_rtmp_script_copy_code_t)
                             + sizeof(ngx_rtmp_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = ngx_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return NGX_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(ngx_rtmp_script_copy_code_t)
                              + sizeof(ngx_rtmp_script_var_code_t))
                + sizeof(uintptr_t)
                + sc->source->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

        *sc->values = ngx_array_create(sc->cf->pool, n, 1);
        if (*sc->values == NULL) {
            return NGX_ERROR;
        }
    }

    sc->variables = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_script_done(ngx_rtmp_script_compile_t *sc)
{
    ngx_str_t    zero;
    uintptr_t   *code;

    if (sc->zero) {

        zero.len = 1;
        zero.data = (u_char *) "\0";

        if (ngx_rtmp_script_add_copy_code(sc, &zero, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (sc->conf_prefix || sc->root_prefix) {
        if (ngx_rtmp_script_add_full_name_code(sc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (sc->complete_lengths) {
        code = ngx_rtmp_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = ngx_rtmp_script_add_code(*sc->values, sizeof(uintptr_t),
                                        &sc->main);
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return NGX_OK;
}


void *
ngx_rtmp_script_start_code(ngx_pool_t *pool, ngx_array_t **codes, size_t size)
{
    if (*codes == NULL) {
        *codes = ngx_array_create(pool, 256, 1);
        if (*codes == NULL) {
            return NULL;
        }
    }

    return ngx_array_push_n(*codes, size);
}


void *
ngx_rtmp_script_add_code(ngx_array_t *codes, size_t size, void *code)
{
    u_char  *elts, **p;
    void    *new;

    elts = codes->elts;

    new = ngx_array_push_n(codes, size);
    if (new == NULL) {
        return NULL;
    }

    if (code) {
        if (elts != codes->elts) {
            p = code;
            *p += (u_char *) codes->elts - elts;
        }
    }

    return new;
}


static ngx_int_t
ngx_rtmp_script_add_copy_code(ngx_rtmp_script_compile_t *sc, ngx_str_t *value,
    ngx_uint_t last)
{
    u_char                       *p;
    size_t                        size, len, zero;
    ngx_rtmp_script_copy_code_t  *code;

    zero = (sc->zero && last);
    len = value->len + zero;

    code = ngx_rtmp_script_add_code(*sc->lengths,
                                    sizeof(ngx_rtmp_script_copy_code_t), NULL);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_rtmp_script_code_pt) ngx_rtmp_script_copy_len_code;
    code->len = len;

    size = (sizeof(ngx_rtmp_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    code = ngx_rtmp_script_add_code(*sc->values, size, &sc->main);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = ngx_rtmp_script_copy_code;
    code->len = len;

    p = ngx_cpymem((u_char *) code + sizeof(ngx_rtmp_script_copy_code_t),
                   value->data, value->len);

    if (zero) {
        *p = '\0';
        sc->zero = 0;
    }

    return NGX_OK;
}


size_t
ngx_rtmp_script_copy_len_code(ngx_rtmp_script_engine_t *e)
{
    ngx_rtmp_script_copy_code_t  *code;

    code = (ngx_rtmp_script_copy_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_copy_code_t);

    return code->len;
}


void
ngx_rtmp_script_copy_code(ngx_rtmp_script_engine_t *e)
{
    u_char                       *p;
    ngx_rtmp_script_copy_code_t  *code;

    code = (ngx_rtmp_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = ngx_copy(p, e->ip + sizeof(ngx_rtmp_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(ngx_rtmp_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script copy: \"%*s\"", e->pos - p, p);
}


static ngx_int_t
ngx_rtmp_script_add_var_code(ngx_rtmp_script_compile_t *sc, ngx_str_t *name)
{
    ngx_int_t                    index, *p;
    ngx_rtmp_script_var_code_t  *code;

    index = ngx_rtmp_get_variable_index(sc->cf, name);

    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (sc->flushes) {
        p = ngx_array_push(*sc->flushes);
        if (p == NULL) {
            return NGX_ERROR;
        }

        *p = index;
    }

    code = ngx_rtmp_script_add_code(*sc->lengths,
                                    sizeof(ngx_rtmp_script_var_code_t), NULL);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_rtmp_script_code_pt) ngx_rtmp_script_copy_var_len_code;
    code->index = (uintptr_t) index;

    code = ngx_rtmp_script_add_code(*sc->values,
                                    sizeof(ngx_rtmp_script_var_code_t),
                                    &sc->main);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = ngx_rtmp_script_copy_var_code;
    code->index = (uintptr_t) index;

    return NGX_OK;
}


size_t
ngx_rtmp_script_copy_var_len_code(ngx_rtmp_script_engine_t *e)
{
    ngx_rtmp_variable_value_t   *value;
    ngx_rtmp_script_var_code_t  *code;

    code = (ngx_rtmp_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_var_code_t);

    if (e->flushed) {
        value = ngx_rtmp_get_indexed_variable(e->request, code->index);

    } else {
        value = ngx_rtmp_get_flushed_variable(e->request, code->index);
    }

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


void
ngx_rtmp_script_copy_var_code(ngx_rtmp_script_engine_t *e)
{
    u_char                      *p;
    ngx_rtmp_variable_value_t   *value;
    ngx_rtmp_script_var_code_t  *code;

    code = (ngx_rtmp_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_var_code_t);

    if (!e->skip) {

        if (e->flushed) {
            value = ngx_rtmp_get_indexed_variable(e->request, code->index);

        } else {
            value = ngx_rtmp_get_flushed_variable(e->request, code->index);
        }

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = ngx_copy(p, value->data, value->len);

            ngx_log_debug2(NGX_LOG_DEBUG_RTMP,
                           e->request->connection->log, 0,
                           "rtmp script var: \"%*s\"", e->pos - p, p);
        }
    }
}


static ngx_int_t
ngx_rtmp_script_add_args_code(ngx_rtmp_script_compile_t *sc)
{
    uintptr_t   *code;

    code = ngx_rtmp_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) ngx_rtmp_script_mark_args_code;

    code = ngx_rtmp_script_add_code(*sc->values, sizeof(uintptr_t), &sc->main);
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) ngx_rtmp_script_start_args_code;

    return NGX_OK;
}


size_t
ngx_rtmp_script_mark_args_code(ngx_rtmp_script_engine_t *e)
{
    e->is_args = 1;
    e->ip += sizeof(uintptr_t);

    return 1;
}


void
ngx_rtmp_script_start_args_code(ngx_rtmp_script_engine_t *e)
{
    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script args");

    e->is_args = 1;
    e->args = e->pos;
    e->ip += sizeof(uintptr_t);
}


#if (NGX_PCRE)

static ngx_int_t
ngx_rtmp_script_add_capture_code(ngx_rtmp_script_compile_t *sc, ngx_uint_t n)
{
    ngx_rtmp_script_copy_capture_code_t  *code;

    code = ngx_rtmp_script_add_code(*sc->lengths,
                                    sizeof(ngx_rtmp_script_copy_capture_code_t),
                                    NULL);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_rtmp_script_code_pt)
                      ngx_rtmp_script_copy_capture_len_code;
    code->n = 2 * n;


    code = ngx_rtmp_script_add_code(*sc->values,
                                    sizeof(ngx_rtmp_script_copy_capture_code_t),
                                    &sc->main);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = ngx_rtmp_script_copy_capture_code;
    code->n = 2 * n;

    if (sc->ncaptures < n) {
        sc->ncaptures = n;
    }

    return NGX_OK;
}


size_t
ngx_rtmp_script_copy_capture_len_code(ngx_rtmp_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p;
    ngx_uint_t                            n;
    ngx_rtmp_session_t                   *s;
    ngx_rtmp_script_copy_capture_code_t  *code;

    s = e->request;

    code = (ngx_rtmp_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_copy_capture_code_t);

    n = code->n;

    if (n < s->ncaptures) {

        cap = s->captures;

        if ((e->is_args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            p = s->captures_data;

            return cap[n + 1] - cap[n]
                   + 2 * ngx_escape_uri(NULL, &p[cap[n]], cap[n + 1] - cap[n],
                                        NGX_ESCAPE_ARGS);
        } else {
            return cap[n + 1] - cap[n];
        }
    }

    return 0;
}


void
ngx_rtmp_script_copy_capture_code(ngx_rtmp_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p, *pos;
    ngx_uint_t                            n;
    ngx_rtmp_session_t                   *s;
    ngx_rtmp_script_copy_capture_code_t  *code;

    s = e->request;

    code = (ngx_rtmp_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_copy_capture_code_t);

    n = code->n;

    pos = e->pos;

    if (n < s->ncaptures) {

        cap = s->captures;
        p = s->captures_data;

        if ((e->is_args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            e->pos = (u_char *) ngx_escape_uri(pos, &p[cap[n]],
                                               cap[n + 1] - cap[n],
                                               NGX_ESCAPE_ARGS);
        } else {
            e->pos = ngx_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script capture: \"%*s\"", e->pos - pos, pos);
}

#endif


static ngx_int_t
ngx_rtmp_script_add_full_name_code(ngx_rtmp_script_compile_t *sc)
{
    ngx_rtmp_script_full_name_code_t  *code;

    code = ngx_rtmp_script_add_code(*sc->lengths,
                                    sizeof(ngx_rtmp_script_full_name_code_t),
                                    NULL);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_rtmp_script_code_pt) ngx_rtmp_script_full_name_len_code;
    code->conf_prefix = sc->conf_prefix;

    code = ngx_rtmp_script_add_code(*sc->values,
                                    sizeof(ngx_rtmp_script_full_name_code_t),
                                    &sc->main);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = ngx_rtmp_script_full_name_code;
    code->conf_prefix = sc->conf_prefix;

    return NGX_OK;
}


static size_t
ngx_rtmp_script_full_name_len_code(ngx_rtmp_script_engine_t *e)
{
    ngx_rtmp_script_full_name_code_t  *code;

    code = (ngx_rtmp_script_full_name_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_full_name_code_t);

    return code->conf_prefix ? ngx_cycle->conf_prefix.len:
                               ngx_cycle->prefix.len;
}


static void
ngx_rtmp_script_full_name_code(ngx_rtmp_script_engine_t *e)
{
    ngx_rtmp_script_full_name_code_t  *code;

    ngx_str_t  value;

#if (nginx_version >= 1005003)
    ngx_str_t *prefix;
#endif

    code = (ngx_rtmp_script_full_name_code_t *) e->ip;

    value.data = e->buf.data;
    value.len = e->pos - e->buf.data;

#if (nginx_version >= 1005003)
    prefix = code->conf_prefix ? (ngx_str_t *) &ngx_cycle->conf_prefix:
                                 (ngx_str_t *) &ngx_cycle->prefix;

    if (ngx_get_full_name(e->request->connection->pool, prefix,
            &value) != NGX_OK)
#else
    if (ngx_conf_full_name((ngx_cycle_t *) ngx_cycle, &value,
            code->conf_prefix) != NGX_OK)
#endif
    {
        e->ip = ngx_rtmp_script_exit;
        e->status = NGX_RTMP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->buf = value;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script fullname: \"%V\"", &value);

    e->ip += sizeof(ngx_rtmp_script_full_name_code_t);
}


void
ngx_rtmp_script_complex_value_code(ngx_rtmp_script_engine_t *e)
{
    size_t                                 len;
    ngx_rtmp_script_engine_t               le;
    ngx_rtmp_script_len_code_pt            lcode;
    ngx_rtmp_script_complex_value_code_t  *code;

    code = (ngx_rtmp_script_complex_value_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_complex_value_code_t);

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script complex value");

    ngx_memzero(&le, sizeof(ngx_rtmp_script_engine_t));

    le.ip = code->lengths->elts;
    le.line = e->line;
    le.request = e->request;
    le.quote = e->quote;

    for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
        lcode = *(ngx_rtmp_script_len_code_pt *) le.ip;
    }

    e->buf.len = len;
    e->buf.data = ngx_pnalloc(e->request->connection->pool, len);
    if (e->buf.data == NULL) {
        e->ip = ngx_rtmp_script_exit;
        return;
    }

    e->pos = e->buf.data;

    e->sp->len = e->buf.len;
    e->sp->data = e->buf.data;
    e->sp++;
}


void
ngx_rtmp_script_value_code(ngx_rtmp_script_engine_t *e)
{
    ngx_rtmp_script_value_code_t  *code;

    code = (ngx_rtmp_script_value_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_value_code_t);

    e->sp->len = code->text_len;
    e->sp->data = (u_char *) code->text_data;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script value: \"%v\"", e->sp);

    e->sp++;
}


void
ngx_rtmp_script_set_var_code(ngx_rtmp_script_engine_t *e)
{
    ngx_rtmp_session_t          *s;
    ngx_rtmp_script_var_code_t  *code;

    code = (ngx_rtmp_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_var_code_t);

    s = e->request;

    e->sp--;

    s->variables[code->index].len = e->sp->len;
    s->variables[code->index].valid = 1;
    s->variables[code->index].no_cacheable = 0;
    s->variables[code->index].not_found = 0;
    s->variables[code->index].data = e->sp->data;

#if (NGX_DEBUG)
    {
    ngx_rtmp_variable_t        *v;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    v = cmcf->variables.elts;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script set $%V", &v[code->index].name);
    }
#endif
}


void
ngx_rtmp_script_var_set_handler_code(ngx_rtmp_script_engine_t *e)
{
    ngx_rtmp_script_var_handler_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script set var handler");

    code = (ngx_rtmp_script_var_handler_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_var_handler_code_t);

    e->sp--;

    code->handler(e->request, e->sp, code->data);
}


void
ngx_rtmp_script_var_code(ngx_rtmp_script_engine_t *e)
{
    ngx_rtmp_variable_value_t   *value;
    ngx_rtmp_script_var_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                   "rtmp script var");

    code = (ngx_rtmp_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_rtmp_script_var_code_t);

    value = ngx_rtmp_get_flushed_variable(e->request, code->index);

    if (value && !value->not_found) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, e->request->connection->log, 0,
                       "rtmp script var: \"%v\"", value);

        *e->sp = *value;
        e->sp++;

        return;
    }

    *e->sp = ngx_rtmp_variable_null_value;
    e->sp++;
}


void
ngx_rtmp_script_nop_code(ngx_rtmp_script_engine_t *e)
{
    e->ip += sizeof(uintptr_t);
}

