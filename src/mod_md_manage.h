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

#ifndef MOD_MD_MANAGE_H
#define MOD_MD_MANAGE_H

int md_manage_handler(request_rec *r);

typedef apr_status_t (md_postfcn_t)(md_json_t *response, request_rec *r,
                                    const md_mod_conf_t *mc,
                                    const md_srv_conf_t *sc,
                                    md_json_t *params);

apr_status_t md_json_resp( request_rec *r, apr_status_t rv, md_json_t *j,
                           const char *msg );

#endif