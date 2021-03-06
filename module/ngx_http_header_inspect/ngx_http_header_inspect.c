/*
 * ngx_http_header_inspect - Inspect HTTP headers
 *
 * Copyright (c) 2011, Andreas Jaggi <andreas.jaggi@waterwave.ch>
 * Copyright (c) 2021, Khalegh Salehi <khaleghsalehi@gmail.com>
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_array.h>
#include <ngx_regex.h>

#define MODULE_VERSION "0.3"

typedef struct {
    ngx_flag_t inspect;
    ngx_flag_t log;
    ngx_flag_t log_uninspected;
    ngx_flag_t block;
    ngx_uint_t range_max_byteranges;
    ngx_str_t token_name;
    ngx_str_t token_version_name;
    ngx_str_t regex_pattern;
    ngx_str_t token_version;
} ngx_header_inspect_loc_conf_t;


static ngx_int_t ngx_header_inspect_init(ngx_conf_t *cf);


static ngx_int_t ngx_header_inspect_process_request(ngx_http_request_t *r);

static void *ngx_header_inspect_create_conf(ngx_conf_t *cf);

static char *ngx_header_inspect_merge_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t ngx_header_inspect_commands[] = {
        {
                ngx_string("inspect_headers"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, inspect),
                NULL
        },
        {
                ngx_string("inspect_headers_log_violations"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, log),
                NULL
        },
        {
                ngx_string("inspect_headers_block_violations"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, block),
                NULL
        },
        {
                ngx_string("inspect_headers_log_uninspected"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, log_uninspected),
                NULL
        },
        {
                ngx_string("inspect_headers_range_max_byteranges"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_num_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, range_max_byteranges),
                NULL
        },
        {
                ngx_string("inspect_headers_token_name"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, token_name),
                NULL
        },
        {
                ngx_string("inspect_headers_regex_pattern"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, regex_pattern),
                NULL
        },
        {
                ngx_string("inspect_headers_version_name"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, token_version_name),
                NULL
        },
        {
                ngx_string("inspect_headers_version"),
                NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_header_inspect_loc_conf_t, token_version),
                NULL
        },
        ngx_null_command
};

static ngx_http_module_t ngx_header_inspect_module_ctx = {
        NULL,                             /* preconfiguration */
        ngx_header_inspect_init,          /* postconfiguration */

        NULL,                             /* create main configuration */
        NULL,                             /* init main configuration */

        NULL,                             /* create server configuration */
        NULL,                             /* merge server configuration */

        ngx_header_inspect_create_conf,   /* create location configuration */
        ngx_header_inspect_merge_conf,    /* merge location configuration */
};

ngx_module_t ngx_http_header_inspect_module = {
        NGX_MODULE_V1,
        &ngx_header_inspect_module_ctx, /* module context */
        ngx_header_inspect_commands,    /* module directives */
        NGX_HTTP_MODULE,                /* module type */
        NULL,                           /* init master */
        NULL,                           /* init module */
        NULL,                           /* init process */
        NULL,                           /* init thread */
        NULL,                           /* exit thread */
        NULL,                           /* exit process */
        NULL,                           /* exit master */
        NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_header_inspect_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_header_inspect_process_request;
    return NGX_OK;
}

static ngx_uint_t
check_token_pattern(ngx_header_inspect_loc_conf_t *conf, ngx_http_request_t *r, ngx_str_t *token_value) {


    ngx_regex_t *re;
    ngx_regex_compile_t rc;

    u_char err_str[NGX_MAX_CONF_ERRSTR];
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "header_inspect: incoming string %s via len %d",
                  token_value->data,
                  token_value->len);
    // get version number

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "header_inspect: token version  %d",
                  conf->token_version);
    // regex value
    ngx_str_t regex_pattern_value = ngx_string(conf->regex_pattern.data);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "header_inspect: regex token_value string ==>  %s",
                  regex_pattern_value.data);

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = regex_pattern_value;
    rc.pool = r->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = err_str;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "header_inspect: %V", &rc.err);
    }

    re = rc.regex;


    ngx_int_t n;
    int captures[(1 + rc.captures) * 3];

    n = ngx_regex_exec(re, token_value, captures, (1 + rc.captures) * 3);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "header_inspect: n  regex result  %d", n);
    if (n >= 0) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "header_inspect: token matched.");
        return 0;

    } else if (n == NGX_REGEX_NO_MATCHED) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                      "header_inspect:  header_inspect: token not matched.");
        return 1;
    } else {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      ngx_regex_exec_n
                              "header_inspect: Internal error,  matching failed: %i", n);
        return -1;
    }

}

static ngx_int_t ngx_header_inspect_process_request(ngx_http_request_t *r) {
    ngx_header_inspect_loc_conf_t *conf;
    ngx_uint_t i;
    ngx_uint_t token_status;
    ngx_uint_t version_status;
    token_status = 1; // false
    version_status = 1; // false
    conf = ngx_http_get_module_loc_conf(r, ngx_http_header_inspect_module);
    if (conf->inspect) {
        ngx_list_part_t *part1;
        ngx_table_elt_t *h1;
        part1 = &r->headers_in.headers.part;
        do {
            h1 = part1->elts;
            // iterate headers and find token name
            for (i = 0; i < part1->nelts; i++) {
                if (ngx_strcmp(conf->token_name.data, h1[i].key.data) == 0) {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                  "header_inspect: token found ->  %s len %d",
                                  h1[i].value.data, h1[i].value.len);
                    if (check_token_pattern(conf, r, &h1[i].value) == 0) {
                        version_status = 0;
                        break;
                    } else {
                        version_status = 1;
                    }
                }
            }
            // iterate headers and find token valid version
            for (i = 0; i < part1->nelts; i++) {
                if (ngx_strcmp(conf->token_version_name.data, h1[i].key.data) == 0) {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                  "header_inspect: token version [%s] found",
                                  h1[i].value.data);
                    if (ngx_atoi(h1[i].value.data, 8) >= ngx_atoi(conf->token_version.data, 8) ) {
                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                      "header_inspect: token version  mathced with valid number");
                        token_status = 0;
                        break;
                    } else {
                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                      "header_inspect: token version  found but not matched with valid number");
                        token_status = 1;
                        break;
                    }
                } else {
                    token_status = 1;
                }
            }
            part1 = part1->next;
        } while (part1 != NULL);
    }
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                  "header_inspect: status of token =>>  %d  version =>>  %d",
                  token_status, version_status);
    if ((token_status) == 0 && (version_status == 0))
        return NGX_DECLINED;
    else
        return NGX_HTTP_BAD_REQUEST;
}


static void *ngx_header_inspect_create_conf(ngx_conf_t *cf) {
    ngx_header_inspect_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_header_inspect_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->inspect = NGX_CONF_UNSET;
    conf->log = NGX_CONF_UNSET;
    conf->block = NGX_CONF_UNSET;
    conf->log_uninspected = NGX_CONF_UNSET;

    conf->range_max_byteranges = NGX_CONF_UNSET_UINT;
    conf->token_name.data = NULL;
    conf->regex_pattern.data = NULL;
    conf->token_version.data = NULL;
    conf->token_version_name.data = NULL;
    return conf;
}

static char *ngx_header_inspect_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_header_inspect_loc_conf_t *prev = parent;
    ngx_header_inspect_loc_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->inspect, prev->inspect, 0);
    ngx_conf_merge_off_value(conf->log, prev->log, 1);
    ngx_conf_merge_off_value(conf->block, prev->block, 0);
    ngx_conf_merge_off_value(conf->log_uninspected, prev->log_uninspected, 0);

    ngx_conf_merge_uint_value(conf->range_max_byteranges, prev->range_max_byteranges, 5);
    ngx_conf_merge_str_value(conf->token_name, prev->token_name, "");
    ngx_conf_merge_str_value(conf->token_version_name, prev->token_version_name, "");
    ngx_conf_merge_str_value(conf->regex_pattern, prev->regex_pattern, "");
    ngx_conf_merge_str_value(conf->token_version, prev->token_version, 0);
    return NGX_CONF_OK;
}
