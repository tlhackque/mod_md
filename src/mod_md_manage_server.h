/* Copyright (C) 2020 Timothe Litt
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef MOD_MD_MANAGE_SERVER_H
#define MOD_MD_MANAGE_SERVER_H

typedef struct apr_pool_t apr_pool_t;
typedef struct server_rec server_rec;
typedef struct md_mod_conf_t md_mod_conf_t;
typedef struct apr_array_header_t apr_array_header_t;
typedef struct md_json_t md_json_t;
typedef struct apr_socket_t apr_socket_t;
#include <apr_time.h>

#ifndef MANAGE_LINK_TIMEOUT
#define MANAGE_LINK_TIMEOUT (60)
#endif

typedef struct {
    apr_pool_t          *p;
    server_rec          *s;
    const md_mod_conf_t *mc;
    apr_array_header_t  *jobs;
    unsigned char       *link_key;
#define MANAGE_KEY_LENGTH (256/8)
    md_json_t           *request;
    md_json_t           *response;
} md_gui_server_ctx_t;

typedef apr_status_t (md_guifcn_t)( md_gui_server_ctx_t *ctx );

void process_gui_server_request( md_gui_server_ctx_t *ctx, apr_socket_t *lsock );

apr_status_t md_manage_send_message(apr_socket_t *sock, const unsigned char *key,
                                    const char *body, apr_size_t length );
apr_status_t md_manage_recv_message(apr_socket_t *sock, const unsigned char *key,
                                    const char **body, apr_size_t *length, apr_pool_t *p);

#endif
