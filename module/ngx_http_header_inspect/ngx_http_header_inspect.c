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



/*
 * Encryption
 */


#ifndef AES_H_
#define AES_H_

#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32

typedef struct _AES_DATA {
    unsigned char *key;
    unsigned char *iv;
} AES_DATA;

typedef struct Message_Struct {
    unsigned char *body;
    int *length;
    AES_DATA *aes_settings;

} Message;

Message *message_init(int);

int aes256_init(Message *);

Message *aes256_encrypt(Message *);

Message *aes256_decrypt(Message *);

void aes_cleanup(AES_DATA *);

void message_cleanup(Message *);


#endif

Message *message_init(int length) {
    Message *ret = malloc(sizeof(Message));
    ret->body = malloc(length);
    ret->length = malloc(sizeof(int));
    *ret->length = length;
    //used string terminator to allow string methods to work
    memset(ret->body, '\0', length);
    //initialize aes_data
    aes256_init(ret);
    return ret;
}

int aes256_init(Message *input) {
    AES_DATA *aes_info = malloc(sizeof(AES_DATA));
    aes_info->key = malloc(sizeof(char) * AES_KEY_SIZE);
    aes_info->iv = malloc(sizeof(char) * AES_KEY_SIZE);
    //point to new data
    input->aes_settings = aes_info;
    //set to zero
    memset(input->aes_settings->key, 0, AES_KEY_SIZE);
    memset(input->aes_settings->iv, 0, AES_KEY_SIZE);
    //get rand bytes


//    unsigned char aes_key[] = {0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
//                               0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
//                               0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
//                               0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65};
//
//    unsigned char aes_iv[] = {0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
//                              0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65};
    unsigned char aes_key[] = "khaleghkhalegh00";

    unsigned char aes_iv[] = "0000000011111111";

    memcpy(input->aes_settings->key, aes_key, sizeof(aes_key));
    memcpy(input->aes_settings->iv, aes_iv, sizeof(aes_iv));
    return 0;
}

Message *aes256_encrypt(Message *plaintext) {
    EVP_CIPHER_CTX *enc_ctx;
    Message *encrypted_message;
    int enc_length = *(plaintext->length) + (AES_BLOCK_SIZE - *(plaintext->length) % AES_BLOCK_SIZE);

    encrypted_message = message_init(enc_length);
    //set up encryption context
    enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(enc_ctx, EVP_aes_256_cbc(), plaintext->aes_settings->key, plaintext->aes_settings->iv);
    //encrypt all the bytes up to but not including the last block
    if (!EVP_EncryptUpdate(enc_ctx, encrypted_message->body, &enc_length, plaintext->body, *plaintext->length)) {
        EVP_CIPHER_CTX_cleanup(enc_ctx);
        printf("EVP Error: couldn't update encryption with plain text!\n");
        return NULL;
    }
    //update length with the amount of bytes written
    *(encrypted_message->length) = enc_length;
    //EncryptFinal will cipher the last block + Padding
    if (!EVP_EncryptFinal_ex(enc_ctx, enc_length + encrypted_message->body, &enc_length)) {
        EVP_CIPHER_CTX_cleanup(enc_ctx);
        printf("EVP Error: couldn't finalize encryption!\n");
        return NULL;
    }
    //add padding to length
    *(encrypted_message->length) += enc_length;
    //no errors, copy over key & iv rather than pointing to the plaintext msg
    memcpy(encrypted_message->aes_settings->key, plaintext->aes_settings->key, AES_KEY_SIZE);
    memcpy(encrypted_message->aes_settings->iv, plaintext->aes_settings->iv, AES_KEY_SIZE);
    //Free context and return encrypted message
    EVP_CIPHER_CTX_cleanup(enc_ctx);
    return encrypted_message;
}

Message *aes256_decrypt(Message *encrypted_message) {
    EVP_CIPHER_CTX *dec_ctx;
    int dec_length = 0;
    Message *decrypted_message;
    //initialize return message and cipher context
    decrypted_message = message_init(*encrypted_message->length);
    dec_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(dec_ctx, EVP_aes_256_cbc(), encrypted_message->aes_settings->key,
                    encrypted_message->aes_settings->iv);
    //same as above
    if (!EVP_DecryptUpdate(dec_ctx, decrypted_message->body, &dec_length, encrypted_message->body,
                           *encrypted_message->length)) {
        EVP_CIPHER_CTX_cleanup(dec_ctx);
        printf("EVP Error: couldn't update decrypt with text!\n");
        return NULL;
    }
    *(decrypted_message->length) = dec_length;
    if (!EVP_DecryptFinal_ex(dec_ctx, *decrypted_message->length + decrypted_message->body, &dec_length)) {
        EVP_CIPHER_CTX_cleanup(dec_ctx);
        printf("EVP Error: couldn't finalize decryption!\n");
        return NULL;
    }
    //auto handle padding
    *(decrypted_message->length) += dec_length;
    //Terminate string for easier use.
    *(decrypted_message->body + *decrypted_message->length) = '\0';
    //no errors, copy over key & iv rather than pointing to the encrypted msg
    memcpy(decrypted_message->aes_settings->key, encrypted_message->aes_settings->key, AES_KEY_SIZE);
    memcpy(decrypted_message->aes_settings->iv, encrypted_message->aes_settings->iv, AES_KEY_SIZE);
    //free context and return decrypted message
    EVP_CIPHER_CTX_cleanup(dec_ctx);
    return decrypted_message;
}



void aes_cleanup(AES_DATA *aes_data) {
    free(aes_data->iv);
    free(aes_data->key);
    free(aes_data);
}

void message_cleanup(Message *message) {
    //free message struct
    aes_cleanup(message->aes_settings);
    free(message->length);
    free(message->body);
    free(message);
}


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
                        ////////////////////////////////////////////////////////////////////

                        // Initialize openSSL
                        ERR_load_crypto_strings();
                        OpenSSL_add_all_algorithms();


                        Message *message, *enc_msg, *dec_msg;
                        message = message_init(1024);
                        strcpy((char *) message->body, (char *) h1[i].value.data);

                        if (aes256_init(message)) {
                            puts("Error: Couldn't initialize message with aes data!");
                            return 1;
                        }


                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                      "header_inspect: Sending message to be encrypted... %s ", message->body);

                        enc_msg = aes256_encrypt(message);
                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                      "header_inspect: Encrypted Message: %s", enc_msg->body);

                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                      "header_inspect: sending message to be decrypted...");

                        dec_msg = aes256_decrypt(enc_msg);

                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                      "header_inspect: Decrypted Message");

                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                      "header_inspect: AES encryption body and len %s -> %s", dec_msg->body,
                                      dec_msg->length);
                        //destroy messages
                        message_cleanup(message);
                        message_cleanup(enc_msg);
                        message_cleanup(dec_msg);
                        //clean up ssl;
                        EVP_cleanup();
                        CRYPTO_cleanup_all_ex_data(); //Stop data leaks
                        ERR_free_strings();




                        ///////////////////////////////////////////////////////////////////
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
                    if (ngx_atoi(h1[i].value.data, 8) >= ngx_atoi(conf->token_version.data, 8)) {
                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 1,
                                      "header_inspect: token version  matched with valid number");
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
