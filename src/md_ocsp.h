/* Licensed to the Apache Software Foundation (ASF) under one or more
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

#ifndef md_ocsp_h
#define md_ocsp_h

struct md_store_t;
struct md_timeslice_t;

typedef struct md_ocsp_reg_t md_ocsp_reg_t;

apr_status_t md_ocsp_reg_make(md_ocsp_reg_t **preg, apr_pool_t *p,
                              struct md_store_t *store, 
                              const md_timeslice_t *renew_window,
                              const char *user_agent, const char *proxy_url);

apr_status_t md_ocsp_prime(md_ocsp_reg_t *reg, md_cert_t *x, 
                           md_cert_t *issuer, const md_t *md);

apr_status_t md_ocsp_get_status(unsigned char **pder, int *pderlen,
                                md_ocsp_reg_t *reg, md_cert_t *cert,
                                apr_pool_t *p, const md_t *md);

apr_size_t md_ocsp_count(md_ocsp_reg_t *reg);

void md_ocsp_renew(md_ocsp_reg_t *reg, apr_pool_t *p, apr_pool_t *ptemp, apr_time_t *pnext_run);

#endif /* md_ocsp_h */
