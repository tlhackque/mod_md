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

#include <stddef.h>

#include <apr_optional.h>
#include <apr_time.h>
#include <apr_date.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "md.h"
#include "md_crypt.h"
#include "md_json.h"

#include "mod_md_config.h"
#include "mod_md_dnsquery.h"
#include "mod_md_inspect.h"
#include "mod_md_manage.h"

#include "starttls.h"

static void inspect_error( apr_pool_t *p, apr_array_header_t *log, apr_status_t rv );
static const char *cert_time_string( apr_pool_t *p,
                                     const ASN1_TIME *t, apr_status_t *prv );
static const char *cert_serial_string( apr_pool_t *p, X509 *x );
static const char *cert_key_desc( apr_pool_t *p, X509 *x );

typedef struct {
    int maxdepth;
    int first;
    apr_array_header_t *log;
    apr_pool_t *p;
} verify_t;
static int verify_data_idx = -1;

static int verify_callback( int preok, X509_STORE_CTX *ctx);
static void info_callback( const SSL *ssl, int where, int ret );

/* Inspect a host by negotiating a TLS connection and extracting its certificates.
 * Also look for any validation tokens that are installed.
 * Log what's interesting & deliver it as JSON.  This is used by the GUI.
 */

int md_manage_inspect_host( md_json_t *resp, request_rec *r,
                            const md_mod_conf_t *mc, const md_srv_conf_t *sc,
                            md_json_t *pars )
{
    const char *host = NULL, *port = NULL;
    apr_pool_t *p = r->pool;
    apr_status_t rv = APR_SUCCESS;
    apr_socket_t *sock = NULL;
    apr_os_sock_t osock;
    apr_sockaddr_t *sa;
    char *hn, *sid;
    apr_port_t pn;
    starttls_t starttls = STARTTLS_UNKNOWN;
    char *ipaddr;
    apr_array_header_t *log, *txt, *ktypes;
    int kt = 0;
    SSL_CTX *ctx = NULL;
    verify_t verify;
    long int err;
    const char *cafile, *capath;
    char buf[256];

    (void)mc;
    ERR_clear_error();
    log = apr_array_make(p, 5, sizeof(const char *));
    ktypes = apr_array_make(p, 3, sizeof(const char *));

    host = md_json_gets(pars, "host", NULL);
    port = md_json_gets(pars, "port", NULL);
    if (!(host && port)) return md_json_resp(r, HTTP_BAD_REQUEST, resp, "Missing host or port");

    if( APR_SUCCESS !=  md_json_getsa(ktypes, pars, "keytype", NULL) ) {
        const char *ktype;
        if( (ktype = md_json_gets(pars, "keytype", NULL)) ) {
            APR_ARRAY_PUSH(ktypes, const char *) = ktype;
        } else {
            return md_json_resp(r, HTTP_BAD_REQUEST, resp, "Invalid or missing keytype");
        }
    }
    md_json_sets(host, resp, "host", NULL);
    md_json_sets(port, resp, "port", NULL);

#define LOG APR_ARRAY_PUSH(log, const char *) =

    LOG apr_psprintf(p, "Inspecting %s:%s\n\n", host, port);
    if (APR_SUCCESS != (rv = apr_parse_addr_port( &hn, &sid, &pn, apr_psprintf(p,"%s:%s", host, port), p)) ||
        sid != NULL || hn == NULL ) {
        LOG apr_psprintf(p, "%s:%s:Invalid host or port\n", host, port);
        inspect_error(p, log, rv);
        goto respond;
    }

    /* starttls: 'none', a name, or if omitted, default for port# */

    if( md_json_is(MD_JSON_TYPE_STRING, pars, "starttls", NULL) ) {
        starttls = starttls_type( md_json_gets(pars, "starttls", NULL ), 0 );
        if( starttls == STARTTLS_UNKNOWN )
            return md_json_resp(r, HTTP_BAD_REQUEST, resp, "invalid starttls");
    } else {
        starttls = starttls_type( NULL, pn );
    }
    if( starttls >= STARTTLS_NONE ) {
        md_json_sets( starttls_name( starttls ), resp, "starttls", NULL );
    }
    if (APR_SUCCESS != (rv = apr_sockaddr_info_get(&sa, hn, APR_UNSPEC, pn, 0, p))) {
        LOG apr_psprintf(p, "%s:%u:Address resolution failed\n", hn, pn);
        inspect_error(p, log, rv);
        goto respond;
    }
    if( APR_SUCCESS != (rv = apr_sockaddr_ip_get(&ipaddr, sa)) ||
        !(ctx = SSL_CTX_new( TLS_client_method() )) ) {
        inspect_error(p, log, rv);
        goto respond;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_info_callback(ctx, info_callback);

    cafile = md_config_gets(sc, MD_CONFIG_TRUSTED_CERT_FILE);
    capath = md_config_gets(sc, MD_CONFIG_TRUSTED_CERT_PATH);

    if( (cafile || capath) &&
        !SSL_CTX_load_verify_locations(ctx, cafile, capath)) {
        inspect_error(p, log, rv);
        goto respond;
    }
    verify.maxdepth = 99;
    verify.log = log;
    verify.p = p;

    for( kt = 0; kt < ktypes->nelts; ++kt ) {
        const char *ktn;
        SSL *ssl = NULL;
        STACK_OF(X509) *sk = NULL;
        const SSL_CIPHER *cipher;
 
        ktn = APR_ARRAY_IDX(ktypes, kt, const char *);

        if( APR_SUCCESS != apr_socket_create(&sock,sa->family, SOCK_STREAM, APR_PROTO_TCP, p) )
            goto kt_done;
        LOG apr_psprintf(p, "Connecting to %s for %s certificate\n", ipaddr, ktn);
        if (APR_SUCCESS != (rv = apr_socket_opt_set(sock, APR_SO_NONBLOCK, 1)) ||
            APR_SUCCESS != (rv = apr_socket_timeout_set(sock, apr_time_from_sec(15))) ||
            APR_SUCCESS != (rv = apr_socket_connect(sock, sa)) ||
            APR_SUCCESS != (rv = apr_socket_opt_set(sock, APR_SO_NONBLOCK, 0)) ||
            APR_SUCCESS != (rv = apr_socket_timeout_set(sock, apr_time_from_sec(15))))
            goto kt_done;

        LOG "Connected, starting TLS inspection\n";

        if( starttls >= 0 ) {
            start_result_t rc;

            LOG "Issuing STARTTLS command\n";
            if( (rc = starttls_start( hn, sock, starttls,
                                      FLG_DEBUG | FLG_ESCAPE, &log )) == START_STARTED ) {
                LOG apr_psprintf(p, "STARTTLS (%s) accepted\n", starttls_name(starttls) );
            } else {
                LOG apr_psprintf(p, "STARTTLS (%s) failed: %s\n",
                                 starttls_name(starttls), starttls_errstr( rc ));
                goto kt_done;
            }
        }

        if( APR_SUCCESS != (rv = apr_os_sock_get(&osock, sock)) ) goto kt_done;

        /**** ####  Debug: */
        /* 
         * days left?  (days left wouldn't encompass multiple leaf certs) */

        if ((ssl = SSL_new(ctx)) == NULL) goto kt_done;
        verify.first = 1;

        if( verify_data_idx == -1 ) verify_data_idx =
            SSL_get_ex_new_index(0, (void *)"", NULL, NULL, NULL);
        SSL_set_verify_depth(ssl, verify.maxdepth +1);
        SSL_set_ex_data(ssl, verify_data_idx, &verify);
        if( !SSL_set_tlsext_host_name(ssl,hn) ) goto kt_done;

        if( !strcmp( ktn, "ECDSA" ) ) {
            SSL_set_cipher_list(ssl, ktn);
            SSL_set_ciphersuites(ssl, ktn);
        } else {
            SSL_set_cipher_list(ssl, "ALL:!ECDSA:!DSS");
            SSL_set_ciphersuites(ssl, "ALL:!ECDSA:!DSS");
        }
        SSL_set_fd(ssl, osock);
        LOG "Initiating TLS session\n";
        if (SSL_connect(ssl) == -1) {
            goto kt_done;
        }
        if (verify.first) {
            LOG apr_psprintf(p, "No certificate verification was done\n");
        }
        LOG apr_psprintf(p, "Connected with %s", SSL_get_version(ssl) );
        if ((cipher = SSL_get_current_cipher(ssl)) == NULL) {
            LOG "\n";
        } else {
            LOG apr_psprintf(p, " using %s\n", SSL_get_cipher_name(ssl));
        }
        if( (sk = SSL_get_peer_cert_chain(ssl)) != NULL ) {
            int i;
            BIO *b = BIO_new(BIO_s_mem() );
            char *u;
            size_t sl, pos;

            u = apr_psprintf(p, "%s_%u_%s_", hn, pn, ktn);
            sl = strlen( u );
            while( (pos = strcspn(u, ".:-")) < sl ) {
                u[pos] = '_';
            }
            LOG "Certificates sent by host (ordered leaf to root)\n";

            for (i = 0; i < sk_X509_num(sk); i++) {
                X509 *x;
                char *s;

                x = sk_X509_value(sk, i);
                BIO_printf(b, "<div id=\"%s%d\" class=\"pemcert hidden\">", u, i);
                PEM_write_bio_X509(b,x);
                BIO_printf(b, "</div>");
                BIO_write(b, "", 1);
                (void) BIO_get_mem_data(b, &s);
                X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
                LOG apr_psprintf(p, "%2d:Subject: %s\n", i, buf );
                X509_NAME_oneline(X509_get_issuer_name(x), buf, sizeof(buf));
                LOG apr_psprintf(p, "    Issuer: %s\n      Type: %s\n     Valid: %s - %s\n"
                                 "<span cert=\"#%s%d\" class=\"ui-icon ui-icon-circle-plus showcert\"></span>"
                                    "  Serial: %s\n%s", buf,
                                 cert_key_desc(p, x),
                                 cert_time_string(p,X509_get0_notBefore(x),NULL),
                                 cert_time_string(p,X509_get0_notAfter(x),NULL),
                                 u, i,
                                 cert_serial_string(p,x), apr_pstrdup(p, s ));
                BIO_reset(b);
            }
            BIO_set_close(b, BIO_CLOSE);
            BIO_free_all(b);
            LOG apr_psprintf(p, "End %s certificate chain\n", ktn );
        } else {
            LOG apr_psprintf(p, "No %s certificates sent by host\n", ktn );
        }

        if ((err = SSL_get_verify_result(ssl)) == X509_V_OK) {
            LOG apr_psprintf( p, "%s certificate verification succeeded\n", ktn );
        } else {
            LOG apr_psprintf(p, "%s certificate verification failed (%ld) - %s\n",
                             ktn, err, X509_verify_cert_error_string(err));
        }

    kt_done:
        inspect_error(p, log, rv);
        if( ssl ) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = NULL;
        }

        if (sock) {
            apr_socket_close( sock );
            sock = NULL;
        }
        LOG "<hr>";
    } /* Done with this key (certificate) type */

    SSL_CTX_free(ctx);

    /* Make conditional on enabled challenge DNS01.  What about http01? */
    LOG "\nInspecting DNS\n";
    txt = apr_array_make(p,5, sizeof(const char *));
    sid = apr_psprintf(p,"_acme-challenge.%s",host);
    if (APR_SUCCESS == (rv = dnsq_find_rrset(p, txt, sid, DNSQUERY_TXT))) {
        if( txt->nelts == 1 ) {
            LOG "1 DNS validation record found\n";
        } else {
            LOG apr_psprintf(p, "%u DNS validation records found\n", txt->nelts );
        }
        LOG apr_array_pstrcat(p,txt,'\n');
    } else {
        LOG "No DNS vaidation records were found\n";
        rv = APR_SUCCESS;
    }
    LOG "Inspection complete\n";

 respond:
    md_json_sets(apr_array_pstrcat(p, log, '\0'), resp, "log", NULL);
    return md_json_resp( r, OK, resp, NULL );
}

static void inspect_error( apr_pool_t *p, apr_array_header_t *log, apr_status_t rv ) {
    unsigned long e;
    char ebuf[1024+1];
    const char *data;
    int flags;

    while( (e = ERR_get_error_line_data(NULL, NULL, &data, &flags)) ) {
        ERR_error_string_n(e, ebuf, sizeof(ebuf));
        if( flags & ERR_TXT_STRING ) {
            LOG apr_psprintf(p, "%s, %s\n", ebuf, data);
        } else {
            LOG apr_psprintf(p, "%s\n", ebuf);
        }
    }

    if( rv != APR_SUCCESS ) {
        char buffer[HUGE_STRING_LEN];
        apr_strerror(rv, buffer, sizeof(buffer));
        LOG apr_psprintf(p, "Error:%s\n", buffer);
    }
}
#undef LOG

static const char *cert_time_string( apr_pool_t *p, const ASN1_TIME *t, apr_status_t *prv ) {
    apr_time_exp_t r;
    apr_status_t rv = APR_EGENERAL;
    char buf[sizeof("14-Jul-2020 19:47 GMT")+5];
    apr_size_t len;

    if (t == NULL || APR_SUCCESS != (rv = apr_time_exp_gmt(&r, md_asn1_time_get(t))) ||
        APR_SUCCESS != (rv = apr_strftime(buf,&len,sizeof(buf),"%d-%b-%Y %H:%M GMT",&r))) {
        if(prv) *prv = rv;
        return "Invalid time";
    }
    buf[len] = '\0';
    return apr_psprintf(p,"%s", buf);
}

static const char *cert_serial_string( apr_pool_t *p, X509 *x ) {
    const ASN1_INTEGER *sn;
    BIGNUM *bn;
    char *r, *hex;

    sn = X509_get0_serialNumber(x);
    bn = ASN1_INTEGER_to_BN(sn, NULL);
    hex = BN_bn2hex( bn );
    r = apr_psprintf(p, "%s", hex );

    OPENSSL_free( (void *)hex );
    BN_free(bn);

    return r;
}

#define LOG APR_ARRAY_PUSH(vt->log, const char *) =
static int verify_callback( int preok, X509_STORE_CTX *ctx) {
    char      buf[256];
    X509     *err_cert;
    int       err, depth;
    SSL      *ssl;
    verify_t *vt;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    vt = SSL_get_ex_data(ssl, verify_data_idx);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));
    if (depth > vt->maxdepth) {
        preok = 0;
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err);
    }
    if (vt->first) {
        LOG "Verifying certificate chain (ordered root to leaf)\n";
        vt->first = 0;
    }
    if (!preok) {
        LOG apr_psprintf(vt->p, "%2d:Subject: %s, %s\n"
                                "            ^- verify error:(%d) - %s\n",
                                depth, buf, cert_key_desc(vt->p, err_cert),
                                err, X509_verify_cert_error_string(err)
                                );
    } else {
        LOG apr_psprintf(vt->p, "%2d:Subject: %s, %s\n", depth, buf,
                                cert_key_desc(vt->p, err_cert));
    }
    if (!preok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
        X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, sizeof(buf));
        LOG apr_psprintf(vt->p, "issuer= %s\n", buf);
    }

    return 1;
    /* return preok; */
}

static void info_callback( const SSL *ssl, int where, int ret ) {
    verify_t *vt;
    vt = SSL_get_ex_data(ssl, verify_data_idx);

    if( !(where & SSL_CB_LOOP) ) {
        if( where & SSL_CB_ALERT ) {
            /* Ignore: CN - close notify */
            if( strcmp( "CN", SSL_alert_desc_string(ret ) )) {
                LOG apr_psprintf(vt->p, "TLS alert: %s - %s\n",
                                 SSL_alert_type_string_long(ret),
                                 SSL_alert_desc_string_long(ret));
            }
        } else if( (where & SSL_CB_EXIT) && ret <= 0 ) {
            LOG apr_psprintf(vt->p, "TLS connect %s in %s state\n",
                             (ret == 0? "failed" : "error"),
                             SSL_state_string_long(ssl));
        }
    }
    return;
}
#undef LOG

static const char *cert_key_desc( apr_pool_t *p, X509 *x ) {
    EVP_PKEY *pk;
    
    pk = X509_get0_pubkey( x );
    if( pk ) {
        const char *t;
        t = OBJ_nid2sn(EVP_PKEY_base_id(pk));
        if( t == NULL ) t = "Unknown";
        return apr_psprintf(p, "%d bit %s", EVP_PKEY_bits(pk), t);
    }
    return "Unknown";
}

static int add_if_new( apr_array_header_t *array, const int start, const char *text );

/* Locate any existing CAA records for a domain & analyze coverage.
 * Generate sample CAA records for any SANs that aren't covered.
 * **Debug - wildcard.logic.
 */
apr_status_t md_manage_caarecs( md_json_t *resp, request_rec *r,
                                       const md_mod_conf_t *mc,
                                       const md_srv_conf_t *sc,
                                       md_json_t *pars) {
    apr_status_t rv;
    apr_array_header_t *txt, *ids, *indns, *uniq, *needed;
    md_t *md;
    apr_pool_t *p = r->pool;
    const char *dom = md_json_gets(pars, "domain", NULL),
        *caurl = md_json_gets(pars, "caurl", NULL);
    int i, j, k, caasupport = 0;

    (void)sc;
    ids    = apr_array_make(p, 5, sizeof(const char *));
    indns  = apr_array_make(p, 5, sizeof(const char *));
    uniq   = apr_array_make(p, 5, sizeof(const char *));
    needed = apr_array_make(p, 5, sizeof(const char *));
    txt    = apr_array_make(p, 5, sizeof(const char *));
#define WT APR_ARRAY_PUSH(txt, const char *) =

    rv = md_json_getsa(ids, pars, "ids", NULL);
    if( !(dom && caurl && rv == APR_SUCCESS) )
        return md_json_resp( r, HTTP_BAD_REQUEST, resp,
                             "Domain, ca, or ids not specified" );
    caasupport = ids->nelts;

    /* Look for existing CAA records.
     * May be up-tree from host.  And may reference another CA.
     */

    for (i = 0; i < mc->mds->nelts; ++i) {
        md = (md_t*)APR_ARRAY_IDX(mc->mds, i, md_t *);
        if( strcmp( dom, md->name ) || strcmp( caurl, md->ca_url ) ) continue;

        for( j = 0; j < md->domains->nelts; ++j ) {
            const char *rec, *dp, *ep;
            const char *san = apr_pstrcat(p, APR_ARRAY_IDX(md->domains,j,const char *), ".", NULL );

            apr_array_clear(indns);
            if( APR_SUCCESS == dnsq_find_rrset(p, indns, san, DNSQUERY_CAA_HTML|DNSQUERY_MASK_TTL) ) {
                int covered = 0;
                for( k = 0; k < indns->nelts; ++k ) {
                    rec = APR_ARRAY_IDX(indns,k,const char *);
                    if( (dp = strstr(rec, "tag\">issue ")) ||
                        (dp = strstr(rec, "tag\">issuewild ")) ) {
                        int l;
                        dp = strstr(dp, "value\">");
                        if( !dp ) continue;
                        dp += 5+2;
                        while( *dp == ' ' || *dp == '"' ) ++dp;
                        for( ep = dp;
                             *ep && *ep != ' ' && *ep != '"' && *ep != ';'; )
                            ++ep;
                        for( l = 0; l < ids->nelts; ++l ) {
                            const char *id = APR_ARRAY_IDX(ids, l, const char *);
                            if( !strncmp( dp, id, (size_t)(ep - dp) ) ) {
                                covered = 1;
                                break;
                            }
                        }
                    }
                    add_if_new( uniq, 0, rec );
                }
                if( !covered )
                    add_if_new( needed, 0, san );
                continue;
            } else {
                add_if_new( needed, 0, san );
            }
        }
        break;
    }

    WT  "<table class=\"caarecords\"><tbody>";
    if( uniq->nelts ) {
        WT  "<tr class=\"caainfo\"><td colspan=\"99\">"
            "The following CAA records currently in the DNS cover ";
        if( needed->nelts ) {
            WT "some of the names in this certificate.";
        } else {
            WT "all of the names in this certificate.";
        }
        WT apr_array_pstrcat(p, uniq, '\0');
    }

    if( caasupport && needed->nelts ) {
        WT  "<tr class=\"caainfo\"><td colspan=\"99\">"
            "The following CAA records, or records encompassing these names, "
            "are required to authorize issuance of this certificate.";
    } else if( !caasupport && !uniq->nelts ) {
        WT "<tr class=\"caainfo\"><td colspan=\"99\">"
            "This Certificate Authority does not support CAA records."
            "However, the following records, or records encompassing these "
            "names, would instruct ALL CAs not to issue certificates for this domain.";
        APR_ARRAY_PUSH(ids, const char *) = ";";
    } else if( !caasupport && uniq->nelts ) {
        WT "<tr class=\"caainfo\"><td colspan=\"99\">"
            "This Certificate Authority does not support CAA records."
            "However, because CAA records exist, this CA will reject certificate "
            "requests for this domain when it adds support.  The necessary records "
            "will appear here once its requirements are published.";
    }

    if( needed->nelts ) {
        for (i = 0; i < mc->mds->nelts; ++i) {
            md = (md_t*)APR_ARRAY_IDX(mc->mds, i, md_t*);
            if( strcmp( dom, md->name ) || strcmp( caurl, md->ca_url ) ) continue;
            for( j = 0; j < md->domains->nelts; ++j ) {
                char *rec;
                const char *san = apr_pstrcat(p, APR_ARRAY_IDX(md->domains,j,const char *), ".", NULL );
                int missing = 0;

                for( k = 0; k < needed->nelts; ++k ) {
                    if( !strcmp( san, APR_ARRAY_IDX(needed, k, const char *) ) ) {
                        missing = 1;
                        break;
                    }
                }
                if( !missing ) continue;

                for( k = 0; k < ids->nelts; k++ ) {
                    if( san[0] == '*' ) {
                        rec = apr_psprintf(p, "<tr class=\"caarec\"><td class=\"domain wild\">%s"
                                           "<td class=\"ttl\">600"
                                           "<td class=\"class\">IN"
                                           "<td class=\"type\">CAA"
                                           "<td class=\"flags\">128"
                                           "<td class=\"tag\">issuewild"
                                           "<td class=\"caid value\">\"%s\"",
                                           san+2, APR_ARRAY_IDX(ids, k, const char *));
                    } else {
                        rec = apr_psprintf(p, "<tr class=\"caarec\"><td class=\"domain\">%s"
                                           "<td class=\"ttl\">600"
                                           "<td class=\"class\">IN"
                                           "<td class=\"type\">CAA"
                                           "<td class=\"flags\">128"
                                           "<td class=\"tag\">issue"
                                           "<td class=\"caid value\">\"%s\"",
                                           san, APR_ARRAY_IDX(ids, k, const char *));
                    }
                    WT rec;
                }
                for( k = 0; k < md->contacts->nelts; ++k ) {
                    char *contact = apr_pstrdup(p,APR_ARRAY_IDX(md->contacts, k, const char *)),
                        *cp, cbuf[HUGE_STRING_LEN], *qc;
                    for( cp = contact, qc = cbuf; *cp && qc < cbuf +sizeof(cbuf) - sizeof("\\;"); ) {
                        if ( *cp == '\\' || *cp == '"' ) *qc++ = '\\';
                        *qc++ = *cp++;
                    }
                    *qc++ = '\0';
                    if( !caasupport && uniq->nelts ) {
                        WT "<tr class=\"caainfo\"><td colspan=\"99\">"
                            "To request incident reports for this domain, add:";
                        caasupport = -1;
                    }
                    WT apr_psprintf(p, "<tr class=\"caarec\"><td class=\"domain\">%s"
                                           "<td class=\"ttl\">600"
                                           "<td class=\"class\">IN"
                                           "<td class=\"type\">CAA"
                                           "<td class=\"flags\">128"
                                           "<td class=\"tag\">iodef "
                                           "<td class=\"contact value\">\"%s\"",
                                    (caasupport < 0? (san[0] == '*'? san + 2: san) : "&nbsp;"), cbuf );
                }
            }
            break;
        }
    }
    WT  "</tbody></table><p class=\"notes\">Note: <span class=\"quote\">iodef</span> requests that incident reports be sent "
        "to the specified e-mail or web address.  See <a href=\"https://tools.ietf.org/html/rfc7970\" target=\"_blank\">RFC 7970</a> "
        "and <a href=\"https://tools.ietf.org/html/rfc6546\" target=\"_blank\">RFC 6546</a>.";
    if( uniq->nelts )
        WT "<p class=\"notes\">TTLs marked  <span class=\"quote\">123*</span> are artificial, but the rest of the record is live in the DNS.";

    md_json_sets(apr_array_pstrcat(p, txt, '\0'), resp, "caarecs", NULL);
#undef WT
    return md_json_resp( r, OK, resp, NULL );
}

static int add_if_new( apr_array_header_t *array, const int start, const char *text )
{
    int i;

    for( i = start; i < array->nelts; ++i ) {
        if( !strcmp( text, APR_ARRAY_IDX(array, i, const char *) ) ) return 0;
    }
    APR_ARRAY_PUSH(array, const char *) = text;

    return 1;
}

