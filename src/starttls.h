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

#ifndef STARTTLS_H
#define STARTTLS_H

#include <stdarg.h>

#include <apr.h>
#include <apr_network_io.h>

typedef enum {
    STARTTLS_UNKNOWN = -2,
    STARTTLS_NONE,
    STARTTLS_CONNECT,
    STARTTLS_FTP,
    STARTTLS_IMAP,
    STARTTLS_IRC,
    STARTTLS_LDAP,
    STARTTLS_LMTP,
    STARTTLS_MYSQL,
    STARTTLS_NNTP,
    STARTTLS_POP3,
    STARTTLS_POSTGRES,
    STARTTLS_SIEVE,
    STARTTLS_SMTP,
    STARTTLS_TELNET,
    STARTTLS_XMPP,
    STARTTLS_XMPP_SERVER,
} starttls_t;

/* Known port descriptor */

typedef struct {
    const apr_port_t  port;
    const starttls_t  type;
    const char *const name;
} starttls_port_t;

/* List of known ports, type & name.
 * Terminated by NULL name.
 */
extern starttls_port_t starttls_ports[];

typedef enum {
    START_STARTED = 0,
    START_UNKNOWN,       /* Unknown protocol */
    START_NOT_CAPABLE,   /* Host not capable */
    START_REFUSED,       /* Host refused to start */
    START_TIMEOUT,       /* Includes EOF */
    START_FAILED,        /* Unspecified failure */
} start_result_t;

#define FLG_DEBUG  0x0001
#define FLG_ESCAPE 0x0002
#define FLG_EXTRA  0x0004

start_result_t starttls_start( const char *hostname, apr_socket_t *sock,
                               const starttls_t type, int flags, ... );
const char *starttls_errstr( const start_result_t code );

const char *starttls_name( const starttls_t type );
starttls_t  starttls_type( const char *name, const apr_port_t port );
apr_port_t  starttls_port( const starttls_t type );

#endif
