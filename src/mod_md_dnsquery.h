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

#ifndef MOD_MD_DNSQUERY_H
#define MOD_MD_DNSQUERY_H

#include <apr.h>
#include <apr_tables.h>

#define DNSQUERY_USE_HTML 0x1000
#define DNSQUERY_MASK_TTL 0x2000
typedef enum {
    DNSQUERY_CAA = 0,
    DNSQUERY_TXT,
    DNSQUERY_CAA_HTML = DNSQUERY_USE_HTML,
    DNSQUERY_TXT_HTML,
} md_dnsquery_rr_t;

apr_status_t dnsq_find_rrset( apr_pool_t *p, apr_array_header_t *recs,
                         const char *dom, md_dnsquery_rr_t rrtype );
#endif
