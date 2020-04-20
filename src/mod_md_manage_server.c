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

#define MANAGE_GUI 1

#include <stddef.h>

#include <apr_optional.h>
#include <apr_time.h>
#include <apr_date.h>
#include <apr_network_io.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include <openssl/hmac.h>

#include "md_json.h"

#include "mod_md_manage_server.h"

#define MSG_SIG_TYPE EVP_sha256()
#define MSG_SIG_LEN (256/8)

typedef struct {
    apr_size_t length;
    apr_time_t tstamp;
} link_msg_header_t;

typedef unsigned char link_msg_sig_t[MSG_SIG_LEN];

#define XTRNL
#define GUI_FUNCTIONS                                   \
    GUIFUNC(acctnewkey,     static,account_newkey)      \
    GUIFUNC(acctdeactivate, static,deactivate_account)  \
    GUIFUNC(renew,          static,renew_certificate)   \
    GUIFUNC(revoke,         static,revoke_certificate)  \
    GUIFUNC(acctimport,     static,import_account)


#define GUIHANDLER(handler)                                             \
    apr_status_t md_manage_srv_##handler( md_gui_server_ctx_t *ctx )
#define GUIFUNC(function,locn, handler)         \
    locn md_guifcn_t md_manage_srv_##handler;   \
    locn GUIHANDLER(handler);

GUI_FUNCTIONS
#undef GUIFUNC

/* GUI dispatch and handlers */

typedef struct {
    const char  *const function;
    md_guifcn_t *const handler;
} md_guihandler_t;

#define GUIFUNC(function,locn, handler)        \
    { #function, md_manage_srv_##handler },

static md_guihandler_t md_guihandlers[] = {
    GUI_FUNCTIONS
};
#undef GUIFUNC

#define STUB_HANDLER                                            \
    md_json_setj(ctx->request, ctx->response, "request", NULL); \
    md_json_setb(1,ctx->response, "served", NULL);              \
    return APR_SUCCESS;

void process_gui_server_request( md_gui_server_ctx_t *ctx, apr_socket_t *lsock ) {
    apr_status_t    rv;
    apr_socket_t   *sock;
    apr_sockaddr_t *sa;
    apr_size_t      msglen;
    size_t          i;
    const char     *msg;
    char            errbuf[HUGE_STRING_LEN];

    if( !(APR_SUCCESS == (rv = apr_socket_accept(&sock, lsock, ctx->p)) &&
          APR_SUCCESS == (rv = apr_socket_addr_get(&sa, APR_REMOTE, sock)) ) ) {
        ap_log_error(APLOG_MARK, APLOG_TRACE4, rv, ctx->s,
                     "manage server failed to accept connection");
        return;
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE4, rv, ctx->s,
                  "manage server accepted connection from %s, port %u",
                  sa->hostname, sa->port );

    if( APR_SUCCESS != (rv = apr_socket_opt_set( sock, APR_SO_NONBLOCK, 0)) ||
        APR_SUCCESS != (rv = apr_socket_timeout_set( sock, APR_USEC_PER_SEC * 2 )) ) {
        apr_socket_close(sock);
        return;
    }

    if( APR_SUCCESS != (rv = md_manage_recv_message(sock, ctx->link_key, &msg,
                                                    &msglen, ctx->p)) ) {
        ap_log_error(APLOG_MARK, APLOG_TRACE5, rv, ctx->s,
                      "manage server request error");
        apr_socket_close( sock );
        return;
    }
    if( APR_SUCCESS != (rv = md_json_readd( &ctx->request, ctx->p, msg, msglen )) ) {
        ap_log_error(APLOG_MARK, APLOG_TRACE5, rv, ctx->s,
                      "manage server response body error");
        apr_socket_close( sock );
        return;
    }

    ctx->response = md_json_create(ctx->p);

    msg = md_json_gets(ctx->request, "function", NULL);
    if( msg ) {
        md_guihandler_t *gh;

        for( i = 0, gh = md_guihandlers;
             i < (sizeof(md_guihandlers)/sizeof(md_guihandlers[0]));
             ++i, ++gh ) {
            if( !strcmp( msg, gh->function ) ) {
                rv = gh->handler( ctx );
                msg = NULL;
                goto send_response;
            }
        }
        msg = apr_pstrcat(ctx->p, "unknown function ", msg, NULL);
        goto send_response;
    }
    msg = "no function";

 send_response:
    md_json_sets(apr_psprintf(ctx->p, "%d", rv), ctx->response, "status", NULL);
    if( msg == NULL ) {
        msg = md_json_gets(ctx->response, "message", NULL);
    } else {
        const char *m = md_json_gets(ctx->response, "message", NULL);
        if( m ) {
            msg = apr_pstrcat(ctx->p, m, "\n", msg, NULL);
        }
    }
    if( rv != OK && rv != APR_SUCCESS ) {
        apr_strerror(rv, errbuf, sizeof(errbuf));
        if( msg ) {
            msg = apr_pstrcat(ctx->p, msg, "<br>", errbuf, NULL);
        } else {
            msg = errbuf;
        }
    }
    if( msg ) md_json_sets(msg, ctx->response, "message", NULL);

    if( (msg = md_json_writep( ctx->response, ctx->p, MD_JSON_FMT_COMPACT )) &&
        APR_SUCCESS == (rv = md_manage_send_message(sock, ctx->link_key,
                                                    msg, strlen(msg))) ) {
        ap_log_error(APLOG_MARK,APLOG_TRACE6,rv,ctx->s,
                     "manage server response: %s", msg);
    } else {
        ap_log_error(APLOG_MARK,APLOG_TRACE5,rv,ctx->s,
                     "manage server response error: %s", msg);
    }
    apr_socket_close(sock);
    return;
}



GUIHANDLER(account_newkey) {
    STUB_HANDLER
}

GUIHANDLER(deactivate_account) {
    STUB_HANDLER
}


GUIHANDLER(renew_certificate) {
    STUB_HANDLER
}


GUIHANDLER(revoke_certificate) {
    STUB_HANDLER
}

GUIHANDLER(import_account) {
    STUB_HANDLER
}

/* Link message routines - exchange signed messages with ACME watchdog process */

apr_status_t md_manage_send_message(apr_socket_t *sock, const unsigned char *key,
                                    const char *body, apr_size_t length ) {
    apr_status_t rv;
    apr_size_t len;
    link_msg_header_t msghdr;
    link_msg_sig_t    msgsig;
    HMAC_CTX         *macctx;

    macctx = HMAC_CTX_new();
    HMAC_Init_ex(macctx, (const void *)key, MANAGE_KEY_LENGTH, MSG_SIG_TYPE, NULL);


    msghdr.length = length + sizeof(msgsig);

    msghdr.tstamp = apr_time_now();
    HMAC_Update(macctx, (const void *)&msghdr, sizeof(msghdr));
    HMAC_Update(macctx, (const void *)body, length);
    HMAC_Final(macctx, msgsig, NULL);
#if OPENSSL_VERSION_NUMBER < 0x0101000
    HMAC_CTX_cleanup(macctx);
#else
    HMAC_CTX_free(macctx);
#endif
    len = sizeof( msghdr );
    if( APR_SUCCESS != (rv = apr_socket_send(sock, (char *)&msghdr, &len)) ||
        len != sizeof( msghdr ) || !(len = length) ||
        APR_SUCCESS != (rv = apr_socket_send(sock, (char *)body, &len)) ||
        len != length || !(len = sizeof(msgsig)) ||
        APR_SUCCESS != (rv = apr_socket_send(sock, (char *)msgsig, &len)) ||
        len != sizeof(msgsig) ) {
        return (rv == APR_SUCCESS)? APR_EGENERAL : rv;
    }
    return rv;
}

apr_status_t md_manage_recv_message(apr_socket_t *sock, const unsigned char *key,
                                    const char **body, apr_size_t *length, apr_pool_t *p)
{
    apr_status_t      rv;
    apr_time_t        now;
    apr_size_t        len;
    link_msg_header_t msghdr;
    link_msg_sig_t    msgsig;
    HMAC_CTX         *macctx;

    macctx = HMAC_CTX_new();
    HMAC_Init_ex(macctx, (const void *)key, MANAGE_KEY_LENGTH, MSG_SIG_TYPE, NULL);

    now = apr_time_now();
#define FUZZ (10 * APR_USEC_PER_SEC)
    len = sizeof( msghdr );
    if( APR_SUCCESS != (rv = apr_socket_recv( sock, (char *)&msghdr, &len )) ||
        len != sizeof( msghdr ) ||
        msghdr.tstamp < now - FUZZ || msghdr.tstamp > now + FUZZ) {
        return (rv == APR_SUCCESS? APR_EGENERAL : rv);
    }
    HMAC_Update(macctx, (const void *)&msghdr, sizeof(msghdr));

    *body = (char *)apr_palloc( p, msghdr.length );
    *length = msghdr.length - sizeof(msgsig);

    len = msghdr.length;
    if( APR_SUCCESS != (rv = apr_socket_recv( sock, (char *)*body, &len )) ||
        len != msghdr.length ) {
        return (rv == APR_SUCCESS? APR_EGENERAL : rv);
    }
    HMAC_Update(macctx, (const unsigned char *)*body, *length);
    HMAC_Final(macctx, msgsig, NULL);
#if OPENSSL_VERSION_NUMBER < 0x0101000
    HMAC_CTX_cleanup(macctx);
#else
    HMAC_CTX_free(macctx);
#endif
    if( memcmp(msgsig, *body + *length, sizeof(msgsig)) ) {
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}
