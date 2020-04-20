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

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <apr.h>
#include <apr_optional.h>
#include <apr_time.h>
#include <apr_date.h>
#include <apr_escape.h>
#include <apr_strings.h>
#include <apr_network_io.h>

#include "starttls.h"

#define CRLF "\015\012"
#define CR   '\015'
#define LF   '\012'

/* STARTTLS types that we understand */

#define STARTTLS_TYPES                                  \
    STARTTLS_TYPE(   0, LMTP,         smtp )            \
    STARTTLS_TYPE(   0, CONNECT,      connect )         \
    STARTTLS_TYPE(  25, SMTP,         smtp )            \
    STARTTLS_TYPE( 587, SMTP,         smtp )            \
    STARTTLS_TYPE( 110, POP3,         pop3 )            \
    STARTTLS_TYPE( 143, IMAP,         imap )            \
    STARTTLS_TYPE(  21, FTP,          ftp )             \
    STARTTLS_TYPE(5222, XMPP,         xmpp )            \
    STARTTLS_TYPE(5269, XMPP_SERVER,  xmpp )            \
    STARTTLS_TYPE(  23, TELNET,       telnet )          \
    STARTTLS_TYPE( 194, IRC,          irc )             \
    STARTTLS_TYPE(3306, MYSQL,        mysql )           \
    STARTTLS_TYPE(5432, POSTGRES,     postgres )        \
    STARTTLS_TYPE( 119, NNTP,         nntp )            \
    STARTTLS_TYPE( 433, NNTP,         nntp )            \
    STARTTLS_TYPE(4190, SIEVE,        sieve )           \
    STARTTLS_TYPE( 389, LDAP,         ldap )

#define STARTTLS_TYPE(_port, _name, _handler)   \
    { (_port), STARTTLS_##_name, #_name },

/* Ports that require STARTTLS (variant) to start TLS */

starttls_port_t starttls_ports[] = {
    STARTTLS_TYPES

    {   0, STARTTLS_NONE,    "NONE"    },
    {   0, STARTTLS_UNKNOWN, "UNKNOWN" },
    {   0, STARTTLS_UNKNOWN, NULL      }
};
#undef STARTTLS_TYPE

const char *starttls_name( const starttls_t type ) {
    starttls_port_t *pd;

    for( pd = starttls_ports; pd->name; ++pd ) {
        if( pd->type == type ) return pd->name;
    }
    return "UNKNOWN";
}

starttls_t starttls_type( const char *name, const apr_port_t port ) {
    starttls_port_t *pd;

    for( pd = starttls_ports; pd->name; ++pd ) {
        if( name && !strcasecmp( pd->name, name ) ) return pd->type;
        if( port && pd->port == port )              return pd->type;
    }
    return STARTTLS_UNKNOWN;
}

apr_port_t starttls_port( const starttls_t type ) {
    starttls_port_t *pd;

    for( pd = starttls_ports; pd->name; ++pd ) {
        if( pd->type == type ) return pd->port;
    }
    return 0; /* Technically a valid port #, but apr_parse_addr_port does the same. */
}

typedef struct {
    const start_result_t code;
    const char *const msg;
} errs_t;

static errs_t errs[] = {
    { START_STARTED,     "Ready for TLS negotiation" },
    { START_UNKNOWN,     "Unknown protocol type" },
    { START_NOT_CAPABLE, "Host is not capable of STARTTLS" },
    { START_REFUSED,     "Host is capable, but refused to STARTTLS" },
    { START_TIMEOUT,     "Timeout, EOF, or other I/O error" },
    { START_FAILED,      "STARTTLS failed (no detail)" },

    { -1,                "Unknown STARTTLS error code" }
};
const char *starttls_errstr( const start_result_t code ) {
    size_t i;

    for( i = 0; i < sizeof(errs)/sizeof(errs[0]); ++i ) {
        if( code == errs[i].code ) return errs[i].msg;
    }
    return errs[i-1].msg;
}

/* Stand-alone test & debug shell - everything under the #ifdef SA_TEST
 * can safely be removed.  It may be useful for regression testing, but
 * is not intended (or suitable) for production use.
 */

#ifdef SA_TEST
#include <stddef.h>
#include <stdio.h>
#include <apr_lib.h>

#include <apr_portable.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/* gcc  -D_LARGEFILE64_SOURCE -DSA_TEST -Wall -Wextra -pedantic -g -o starttls -I/usr/include/apr-1 -lapr-1 -l ssl -lcrypto src/starttls.c
 */

static const char *pdate( apr_pool_t *p, ASN1_TIME *t ) {
    char *s;
    BIO *b = BIO_new(BIO_s_mem() );
    ASN1_TIME_print(b, t);
    BIO_write(b, "", 1);
    (void) BIO_get_mem_data(b, &s);
    s = apr_pstrdup(p, s);
    BIO_set_close(b, BIO_CLOSE);
    BIO_free_all(b);
    return s;
}
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
static const char *pcert( apr_pool_t *p, X509 *x ){
    char *s;
    BIO *b = BIO_new(BIO_s_mem() );
    PEM_write_bio_X509(b,x);
    BIO_write(b, "", 1);
    (void) BIO_get_mem_data(b, &s);
    s = apr_pstrdup(p, s);
    BIO_set_close(b, BIO_CLOSE);
    BIO_free_all(b);
    return s;
}
int main( int argc, char **argv ) {
    char *host = argv[1], *port = argv[2];
    apr_status_t rv = APR_SUCCESS;
    apr_socket_t *sock = NULL;
    apr_sockaddr_t *sa;
    char *hn, *sid;
    apr_port_t pn;
    char *ipaddr;
    char *ctarget = NULL;
    apr_pool_t *p;
    starttls_t mt = STARTTLS_UNKNOWN;
    start_result_t rc;
    apr_array_header_t *log = NULL;
    apr_os_sock_t osock;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(X509) *sk = NULL;
    int flags = FLG_EXTRA | FLG_DEBUG;
    const char *csl[] = { "ECDSA", "ALL:!ECDSA", NULL}, **cs = csl;

    if( argc < 3 ) {
        printf( "host port [type [connect_target]]\n" );
        exit(3);
    }
    if( argc >= 4 ) {
        mt = starttls_type( argv[3], 0 );
        if( mt == STARTTLS_UNKNOWN ) {
            printf( "Bad type %s\n", argv[3] );
            exit(4);
        }
        if( argc >= 5 ) {
            ctarget = argv[4];
        }
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    rv = apr_initialize();
    if( rv != APR_SUCCESS ) return 1;
    rv = apr_pool_create( &p, NULL );
    if( rv != APR_SUCCESS ) return 2;
    
    if (APR_SUCCESS != (rv = apr_parse_addr_port( &hn, &sid, &pn, apr_psprintf(p,"%s:%s", host, port), p)) ||
        sid != NULL || hn == NULL ) {
        printf( "Parse failed\n");
        goto leave;
    }
    if( mt != STARTTLS_UNKNOWN ) {
        if( pn == 0 ) pn = starttls_port(mt);
    } else if( pn ) {
        mt = starttls_type( NULL, pn );
    }
    if( mt == STARTTLS_UNKNOWN ) {
        printf( "Not a starttls type\n" );
        exit(7);
    }
    if( mt == STARTTLS_CONNECT && !ctarget ) {
        printf( "CONNECT requires a target host\n" );
        exit(8);
    }
    if (APR_SUCCESS != (rv = apr_sockaddr_info_get(&sa, hn, APR_UNSPEC, pn, 0, p))) {
        printf( "Info get\n");
        goto leave;
    }
    for( ; *cs; ++cs ) {
        if (APR_SUCCESS != (rv = apr_sockaddr_ip_get(&ipaddr, sa)) ||
            APR_SUCCESS != apr_socket_create(&sock,sa->family, SOCK_STREAM, APR_PROTO_TCP, p)){
            printf( "sockaddr or socket_create\n");
            goto leave;
        }
        if (APR_SUCCESS != (rv = apr_socket_opt_set(sock, APR_SO_NONBLOCK, 1)) ||
            APR_SUCCESS != (rv = apr_socket_timeout_set(sock, apr_time_from_sec(15))) ||
            APR_SUCCESS != (rv = apr_socket_connect(sock, sa)) ||
            APR_SUCCESS != (rv = apr_socket_opt_set(sock, APR_SO_NONBLOCK, 0)) ||
            APR_SUCCESS != (rv = apr_socket_timeout_set(sock, apr_time_from_sec(15)))) {
            printf( "%s:connect %s %u\n", strerror(errno), hn, pn );
            goto leave;
        }
        if( mt >= 0 ) {
            rc = starttls_start( hn, sock, mt, flags, ctarget, &log );

#define LOG(_val) do { if( flags & FLG_DEBUG ) APR_ARRAY_PUSH(log, const char *) = \
                           (flags & FLG_ESCAPE)? apr_pescape_entity( p, (_val), 1 ) : \
                           (_val); } while(0)

            printf( "STARTTLS: %d - %s\n", rc, starttls_errstr(rc) );
        } else {
            if( !log ) log = apr_array_make(p, 20, sizeof(const char *));
            printf( "Direct connection\n" );
        }
        if( APR_SUCCESS != (rv = apr_os_sock_get(&osock, sock)) ) goto leave;
        if (!(ctx = SSL_CTX_new( TLS_client_method() ))) goto sslerr;

        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        if ((ssl = SSL_new(ctx)) == NULL) goto sslerr;
        if( !SSL_set_tlsext_host_name(ssl,hn) ) goto sslerr;
        SSL_set_fd(ssl, osock);

        SSL_set_cipher_list(ssl, *cs);
        SSL_set_ciphersuites(ssl, *cs);

        if (SSL_connect(ssl) == -1) {
            goto sslerr;
        }
        if( (sk = SSL_get_peer_cert_chain(ssl)) != NULL ) {
            int i;
            LOG( "Certificates sent by host (ordered leaf to root)\n" );
            for (i = 0; i < sk_X509_num(sk); i++) {
                X509 *x;
                char buf[256];

                x = sk_X509_value(sk, i);
                X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
                LOG( apr_psprintf(p, "%2d:Subject: %s\n", i, buf ) );
                X509_NAME_oneline(X509_get_issuer_name(x), buf, sizeof(buf));
                LOG( apr_psprintf(p, "    Issuer: %s\n      Type: %s\n     Valid: %s - %s\n",
                                  buf,
                                  cert_key_desc(p, x),
                                  pdate(p, X509_get_notBefore(x)),
                                  pdate(p,X509_get_notAfter(x))));
            }
            if(0) {LOG("First certificate\n");
                LOG( pcert(p,sk_X509_value(sk,0)) );
            }
        } else {
            LOG( "No certificates sent by host\n" );
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        apr_socket_close(sock);
        SSL_CTX_free(ctx);
    }

    goto showlog;
 sslerr:
    {
        unsigned long e;
        char ebuf[1024+1];

        while( (e = ERR_get_error()) != 0 ) {
            ERR_error_string_n(e, ebuf, sizeof(ebuf));
            LOG( apr_psprintf(p, "%s\n", ebuf) );
        }
    }
 showlog:
    if( log ) {
        printf( "%s", apr_array_pstrcat(p, log, '\0') );
    }
    exit(0);

    leave:
    if( rv != APR_SUCCESS ) {
        char buffer[HUGE_STRING_LEN];
        apr_strerror(rv, buffer, sizeof(buffer));
        printf( "rv: %s\n", buffer );
    }
    exit(1);
}
#undef LOG
#endif

/* context */

typedef struct {
    apr_pool_t *p;
    apr_socket_t *sock;
    int flags;
    apr_array_header_t *log;
    char *line;
    size_t size;
    size_t len;
    void *extra;
    char myhost[APRMAXHOSTLEN+1];
    const char *remhost;
    char term[2];
} ctx_t;

/* Handler declarations for each type */

typedef start_result_t (starttls_fcn_t)(ctx_t *ctx, const starttls_t type);

typedef struct {
    const starttls_t type;
    starttls_fcn_t *const handler;
} starttls_handler_t;

#define DECL_HANDLER(tlstype) start_result_t start_##tlstype(ctx_t *ctx, const starttls_t type)

#define STARTTLS_TYPE(_port, _name, _handler)   \
     static starttls_fcn_t start_##_handler;    \
     DECL_HANDLER(_handler);

STARTTLS_TYPES
#undef STARTTLS_TYPE

#define STARTTLS_TYPE(_port, _name, _handler) { STARTTLS_##_name, start_##_handler },

static starttls_handler_t handlers[] = {
    STARTTLS_TYPES
};
#undef STARTTLS_TYPE

/* I/O routines - must not take anything from socket that SSL may want. */

static const char *sock_getline( ctx_t *ctx );
static int sock_putline( ctx_t *ctx, const char *s );

static const unsigned char *sock_getbin( ctx_t *ctx, apr_size_t len, int append );
static int sock_xpand( ctx_t *ctx, apr_size_t len );
static int sock_putbin( ctx_t *ctx, const unsigned char *s, const apr_size_t len );
static void printbin( ctx_t *ctx, int dir, const unsigned char *s, apr_size_t len );

/* Dispatcher: STARTTLS  as requested.
 * hostname - remote host (name used in some protocols)
 * sock     - open socket to host - with timeout set
 * type     - Type of negotiation to do.
 * flags    - Optional actions
 * ...      - As needed (logging array for FLG_DEBUG)
 */
start_result_t starttls_start( const char *hostname, apr_socket_t *sock,
                               const starttls_t type, int flags, ... ) {
    starttls_handler_t *fp;
    int i;
    va_list ap;

    for( i = 0, fp = handlers; i < (int)(sizeof(handlers)/sizeof(handlers[0]));
         ++i,++fp ) {
        if( fp->type == type ) {
            ctx_t ctx;
            ctx.p = apr_socket_pool_get(sock);
            ctx.sock = sock;
            ctx.flags = flags;
            ctx.term[0] = LF; ctx.term[1] = '\0';
            ctx.extra = NULL;
            if( flags & (FLG_EXTRA | FLG_DEBUG) ) {
                va_start(ap, flags );
                if( flags & FLG_EXTRA ) {
                    ctx.extra = va_arg(ap, void *);
                }
                if( flags & FLG_DEBUG ) {
                    apr_array_header_t **log;
                    log = va_arg(ap, apr_array_header_t **);
                    if( !*log ) {
                        *log = apr_array_make( ctx.p, 20, sizeof(const char *));
                    }
                    ctx.log = *log;
                }
                va_end(ap);
            }
            ctx.line = (char *)apr_palloc(ctx.p, 133);
            ctx.size = 133;
            ctx.len  = 0;
            if( APR_SUCCESS != apr_gethostname( ctx.myhost, sizeof( ctx.myhost ), ctx.p )) {
                strcpy( ctx.myhost, "noname.example.net" );
            }
            ctx.remhost = hostname;
            return fp->handler(&ctx,type);
        }
    }
    return START_UNKNOWN;
}

#define LOG(_val) do { if( ctx->flags & FLG_DEBUG ) APR_ARRAY_PUSH(ctx->log, const char *) =    \
                           (ctx->flags & FLG_ESCAPE)? apr_pescape_entity( ctx->p, (_val), 1 ) : \
                           (_val); } while(0)

DECL_HANDLER(smtp) { /* and LMTP */
    int ok, capable = 0;
    const char *line;

    do {
        if( !(line = sock_getline( ctx )) ) return START_TIMEOUT;
    } while (ctx->len > 3 && line[3] == '-');

    ok = sock_putline( ctx, apr_psprintf( ctx->p, "%s %s"CRLF,
                                          (type == STARTTLS_SMTP)? "EHLO" : "LHLO",
                                          ctx->myhost ));
    if( !ok ) return START_TIMEOUT;

    do {
        if( !(line = sock_getline( ctx )) ) return START_TIMEOUT;
        if (strstr(line, "STARTTLS")) capable = 1;
    } while (ctx->len > 3 && line[3] == '-');

    if (!capable) return START_NOT_CAPABLE;
    ok = sock_putline( ctx, "STARTTLS"CRLF );
    if( !ok ) return START_TIMEOUT;
    if( !(line = sock_getline( ctx )) ) return START_TIMEOUT;
    if( strncmp( line, "220 ", 4 ) )    return START_REFUSED;
    return START_STARTED;
}

DECL_HANDLER(pop3) {
    (void) type;

    if( !(sock_getline( ctx )) )           return START_TIMEOUT;
    if( !sock_putline( ctx, "STLS"CRLF ) ) return START_TIMEOUT;
    if( !(sock_getline( ctx )) )           return START_TIMEOUT;
    if( strncmp( ctx->line, "+OK", 3 ) )   return START_REFUSED;
    return START_STARTED;
}

DECL_HANDLER(imap) {
    int capable = 0;
    const char *line;

    (void) type;
    if( !(line = sock_getline( ctx )) )            return START_TIMEOUT;
    if( strncmp( line, "* OK", 4 ) )               return START_NOT_CAPABLE;
    if( !sock_putline( ctx, ". CAPABILITY"CRLF ) ) return START_NOT_CAPABLE;

    do {
        if( !(line = sock_getline( ctx )) )        return START_TIMEOUT;
        if (strstr(line, "STARTTLS")) capable = 1;
    } while (ctx->len > 3 && line[0] != '.');

    if( !capable )                                 return START_NOT_CAPABLE;
    if( !sock_putline( ctx, ". STARTTLS"CRLF ) )   return START_TIMEOUT;
    if( !(line = sock_getline( ctx )) )            return START_TIMEOUT;
    if( strncmp( line, ". OK", 4 ) )               return START_REFUSED;
    return START_STARTED;
}

DECL_HANDLER(ftp) {
    const char *line;

    (void) type;

    do {
        if( !(line = sock_getline( ctx )) )    return START_TIMEOUT;
    } while (ctx->len > 3 && !(isdigit(line[0]) && isdigit(line[1]) &&
                               isdigit(line[2]) && line[3] == ' '));

    if( !sock_putline( ctx, "AUTH TLS"CRLF ) ) return START_TIMEOUT;
    do {
        if( !(line = sock_getline( ctx )) )    return START_TIMEOUT;
    } while (ctx->len > 3 && !(isdigit(line[0]) && isdigit(line[1]) &&
                               isdigit(line[2]) && line[3] == ' '));
    if( ctx->len > 3 && line[0] == '2' && line[1] == '3' && line[2] == '4' )
        return START_STARTED;
    return START_REFUSED;
}

/* I don't think this is correct (though s_client does).
 * Should initiate with WILL START_TLS.
 * Should reject on WONT START_TLS
 * Is DO START_TLS always first?
 * Is a CRLF guaranteed?
 * I've found a draft RFC, no final and no implementation.
 */
DECL_HANDLER(telnet) {
    const unsigned char *line;
    static const unsigned char tls_do[3] = {
        /* IAC    DO   START_TLS */
           255,   253, 46
    };
    static const unsigned char tls_will[3] = {
        /* IAC  WILL START_TLS */
           255, 251, 46
    };
    static const unsigned char tls_follows[6] = {
        /* IAC  SB   START_TLS FOLLOWS IAC  SE */
           255, 250, 46,       1,      255, 240
    };

    (void) type;
    if( !(line = sock_getbin( ctx, 3, 0 )) )                     return START_TIMEOUT;
    if( ctx->len < 3 || memcmp(line, tls_do, 3) )                return START_REFUSED;
 
    if( !sock_putbin( ctx, tls_will, sizeof(tls_will) ) )        return START_TIMEOUT;
    if( !sock_putbin( ctx, tls_follows, sizeof( tls_follows) ) ) return START_TIMEOUT;

    if( !(line = sock_getbin( ctx, sizeof(tls_follows), 0 )) )   return START_TIMEOUT;
    if( ctx->len < sizeof(tls_follows) ||
        memcmp(line, tls_follows, sizeof(tls_follows)) )         return START_REFUSED;
    return START_STARTED;
}

DECL_HANDLER(xmpp) {
    const char *line;

    ctx->term[0] = '>';
    if( !sock_putline(ctx, apr_psprintf(ctx->p, "<stream:stream "
                                        "xmlns:stream='http://etherx.jabber.org/streams' "
                                        "xmlns='jabber:%s' to='%s' version='1.0'>"CRLF,
                                        type == STARTTLS_XMPP ? "client" : "server",
                                        ctx->remhost)) ) return START_TIMEOUT;
    while( 1 ) {
        if( !( line = sock_getline( ctx )) )             return START_TIMEOUT;
        if(strstr(line, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'") ||
           strstr(line, "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\""))
            break;
    }
    if( !sock_putline(ctx,
                      "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"CRLF) )
        return START_TIMEOUT;
    while( 1 ) {
        if( !( line = sock_getline( ctx )) )             return START_TIMEOUT;
        if(strstr(line, "<proceed "))
            break;
    }
    return START_STARTED;
}

/* This may not be adequate, but it IS what s_client does.
 * We establish a connection (tunnel) to the next remote.
 * Presumeably, it's ready to talk TLS.  If it requires
 * another level of STARTTLS, the caller will have to call
 * starttls_start() with the details.
 */

DECL_HANDLER(connect) {
    const char *target, *line, *lp;
    size_t cl = 0;
    char rc;

    (void) type;

    if( !(target = (const char *)ctx->extra) )                   return START_FAILED;

    if( !sock_putline( ctx, apr_psprintf( ctx->p, "CONNECT %s HTTP/1.0"CRLF
                                          "Host: %s"CRLF  CRLF, target, target ) ) )
                                                                 return START_TIMEOUT;

    if( !(line = sock_getline(ctx)) )                            return START_TIMEOUT;
    if( strncmp( line, "HTTP/", strlen("HTTP/") ) ||
        !(lp = strchr(line, ' ')) || strlen(lp) < 3  )           return START_NOT_CAPABLE;
    rc = lp[1];

    /* Headers - at least log them.  No data for success (the tunnel is up),
     * but an error response may well have some.
     */
    do {
        if( !(line = sock_getline(ctx)) )                        return START_TIMEOUT;
        if( !strncasecmp( "Content-Length:", line, sizeof("Content-Length") ) ) {
            cl = strtoul( line + sizeof( "Content-Length" ), NULL, 10 ); /* N.B. ':' replaces '\0'. */
        }
    } while( ctx->len );

    if( cl ) (void)sock_getbin(ctx, cl, 0 );

    if( rc != '2' )                                              return START_REFUSED;

    return START_STARTED;
}

DECL_HANDLER(irc) {
    const char *line;
    int n;

    (void)type;
    if( !sock_putline(ctx,  "STARTTLS"CRLF) ) return START_TIMEOUT;

    /* If the IRCd doesn't respond, assume it doesn't support STARTTLS.
     * Many IRCds will not give _any_ sort of response to a STARTTLS
     * command when it's not supported.
     */

    do {
        n = 0;
        if( !(line = sock_getline(ctx)) )                               return START_NOT_CAPABLE;
        if( sscanf(line, "%*s %d", &n) != 1)                            return START_REFUSED;
        /* :example.net 451 STARTTLS :You have not registered */
        /* :example.net 421 STARTTLS :Unknown command */
        if ((n == 451 || n == 421) && strstr(line, "STARTTLS") != NULL) return START_NOT_CAPABLE;
        if( n == 691 )                                                  return START_FAILED;
    } while( n != 670 );

    return START_STARTED;
}

DECL_HANDLER(mysql) {
    const unsigned char *packet;

    /* SSL request packet - Handshake response, but NO username. */
    static const unsigned char ssl_req[] = {
        /* payload_length,   sequence_id */
        0x20, 0x00, 0x00, 0x01,
        /* payload - 32 bytes */
        /* capability flags (CLIENT_SSL always set) */
        0x85, 0xae, 0x7f, 0x00,
        /* max-packet size */
        0x00, 0x00, 0x00, 0x01,
        /* character set */
        0x21,
        /* string[23] reserved (all [0]) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    size_t pktlen, pos;
    uint16_t flags;

    (void)type;

    /* Receiving Initial Handshake packet.
     * 4-byte header: length[0:2],seq
     */
    LOG( "Receiving server handshake\n" );

    if( !(packet = sock_getbin( ctx, 3+1, 0 )) ) return START_TIMEOUT;

    pktlen =(size_t)( packet[0] | (packet[1] << 8) | (packet[2] << 16));
    if( packet[3] != 0 || pktlen < 22 ) return START_NOT_CAPABLE;

    /* Payload: pversion[1], sversion[..\0], cxid[4], auth1[8],\0,
     * loflags[2], chs[1], sstatus[2], hiflags[2], ...
     */

    if( !(packet = sock_getbin( ctx, pktlen, 1 )) ) return START_NOT_CAPABLE;
    packet += 4;
    pktlen -= 4;
    if( packet[0] != 10 ) return START_NOT_CAPABLE;
    pos = 0;
    /* server version[string+NULL] */
    do {
        if (pos >= pktlen) return START_NOT_CAPABLE;
    } while( packet[pos++] != '\0');

    LOG( apr_psprintf(ctx->p, "MySQL server version: %s\n", packet+1) );

    /* make sure we have at least 15 bytes left in the packet */
    if (pos + 15 > pktlen) return START_NOT_CAPABLE;

    pos += 12; /* skip over conn id[4] + SALT[8], check filler */
    if (packet[pos++] != '\0') return START_NOT_CAPABLE;

    flags = (uint16_t)(packet[pos] | (packet[pos + 1] << 8));
    LOG( apr_psprintf(ctx->p, "Capability flags: %04x\n", flags) );

    /* capability flags[2], bit 11 is client SSL */
    if( !(flags & 0x0800) ) return START_NOT_CAPABLE;

    /* Send SSL Handshake packet. */
    LOG( "Requesting encryption\n" );

    if( !sock_putbin( ctx, ssl_req, sizeof(ssl_req) ) ) return START_TIMEOUT;
    return START_STARTED;
}

DECL_HANDLER(postgres) {
    const unsigned char *line;
    static const unsigned char ssl_request[] = {
        /* Length        SSLRequest */
        0, 0, 0, 8,   4, 210, 22, 47
    };
    
    (void)type;

    if( !sock_putbin(ctx, ssl_request, sizeof(ssl_request)) )    return START_TIMEOUT;
    if( !((line = sock_getbin(ctx, 1, 0)) && line[0] == 'S' ) )  return START_TIMEOUT;
    return START_STARTED;
}

DECL_HANDLER(nntp) {
    int capable = 0;
    const char *line;

    (void) type;

    if( !(line = sock_getline(ctx)) )                             return START_TIMEOUT;
    if( !(ctx->len >= 4 && line[0] == '2' && line[1] == '0' && /* 400/502 temp/perm unavail */
          (line[2] == '0' || line[2] == '1') && line[3] == ' ') ) return START_REFUSED;
    if( !sock_putline(ctx, "CAPABILITIES"CRLF) )                  return START_TIMEOUT;
    do {
        if( !(line = sock_getline(ctx)) )                         return START_TIMEOUT;
        if( !strncasecmp(line, "STARTTLS", 8) ) capable = 1;
    } while( ctx->len > 1 && line[0] != '.' );
    if( !capable )                                                return START_NOT_CAPABLE;
    if( !sock_putline( ctx, "STARTTLS"CRLF ) )                    return START_TIMEOUT;
    if( !(line = sock_getline(ctx)) )                             return START_TIMEOUT;
    if( !(ctx->len >= 4 && line[0] == '3' && line[1] == '8' &&
          line[2] == '2' && line[3] == ' ') )                     return START_REFUSED;
    return START_STARTED;
}

DECL_HANDLER(sieve) {
     int capable = 0;
    const char *line;

    (void) type;

    /* RFC 5804: CAPABILITIES are sent on connection */
    do {
        if( !(line = sock_getline(ctx)) )                         return START_TIMEOUT;
        if( ctx->len >= 8 && !strncasecmp(line, "STARTTLS", 8) ) capable = 1;
    } while( ctx->len > 1 && line[0] != '.' );
    if( !capable )                                                return START_NOT_CAPABLE;
    if( !sock_putline( ctx, "STARTTLS"CRLF ) )                    return START_TIMEOUT;
    if( !(line = sock_getline(ctx)) )                             return START_TIMEOUT;
    if( !(ctx->len >= 2 && !strncasecmp(line, "OK", 2)) )         return START_REFUSED;
    return START_STARTED;
}

/* From RFC 4511 - note some non-zero codes indicate success */

#define LDAP_CODES                              \
    LDDEF(success,0)                            \
         LDDEF(operationsError,1)               \
         LDDEF(protocolError,2)                 \
         LDDEF(timeLimitExceeded,3)             \
         LDDEF(sizeLimitExceeded,4)             \
         LDDEF(compareFalse,5)                  \
         LDDEF(compareTrue,6)                   \
         LDDEF(authMethodNotSupported,7)        \
         LDDEF(strongerAuthRequired,8)          \
         LDDEF(referral,10)                     \
         LDDEF(adminLimitExceeded,11)           \
         LDDEF(unavailableCriticalExtension,12) \
         LDDEF(confidentialityRequired,13)      \
         LDDEF(saslBindInProgress,14)           \
         LDDEF(noSuchAttribute,16)              \
         LDDEF(undefinedAttributeType,17)       \
         LDDEF(inappropriateMatching,18)        \
         LDDEF(constraintViolation,19)          \
         LDDEF(attributeOrValueExists,20)       \
         LDDEF(invalidAttributeSyntax,21)       \
         LDDEF(noSuchObject,32)                 \
         LDDEF(aliasProblem,33)                 \
         LDDEF(invalidDNSyntax,34)              \
         LDDEF(aliasDereferencingProblem,36)    \
         LDDEF(inappropriateAuthentication,48)  \
         LDDEF(invalidCredentials,49)           \
         LDDEF(insufficientAccessRights,50)     \
         LDDEF(busy,51)                         \
         LDDEF(unavailable,52)                  \
         LDDEF(unwillingToPerform,53)           \
         LDDEF(loopDetect,54)                   \
         LDDEF(namingViolation,64)              \
         LDDEF(objectClassViolation,65)         \
         LDDEF(notAllowedOnNonLeaf,66)          \
         LDDEF(notAllowedOnRDN,67)              \
         LDDEF(entryAlreadyExists,68)           \
         LDDEF(objectClassModsProhibited,69)    \
         LDDEF(affectsMultipleDSAs,71)          \
         LDDEF(other,80)

#define LDDEF(n,v) ldap_##n = v,
typedef enum {
LDAP_CODES
} ldap_error_t;
#undef LDDEF
#define LDDEF(n, v) { ldap_##n, #n },
typedef struct {
    ldap_error_t code;
    const char *const name;
} ldap_ecode_t;

static const ldap_ecode_t ldap_codes[] = {
LDAP_CODES
};
#undef LDDEF
#undef LDAP_CODES

static const char *ldap_errstr( ldap_error_t code ) {
    size_t i;

    for( i = 0; i < sizeof( ldap_codes ) / sizeof( ldap_codes[0] ); ++i ) {
        if( ldap_codes[i].code == code ) return ldap_codes[i].name;
    }
    return "Unknown";
}

DECL_HANDLER(ldap) { /* RFC 4511 - ish */
    /* This is quite odd.  The RFC specifies a SEQUENCE in the request; the OID
     * is actually ASCII, not an OID.  This is not what the RFC specifies, but
     * it is what OpenSSL does - and it does work.
     */
         /* SEQ ID int =1, req Expl: 23A Impl: 0c, ASCII/1.3.6.1.4.1.1466.20037 */
    static const unsigned char reqmsg[31] = {
        0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80,
        0x16, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31,
        0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36,
        0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37, };
    /* ID int =1 APP 25 */
    static const char rsphdr[4] = {
                    0x02, 0x01, 0x01, 0x78 };
    int i;
    size_t pktlen, alen, elen;
    ldap_error_t rc;
    const unsigned char *pkt;

    (void)type;

    /* Send request */

    if( !sock_putbin( ctx, reqmsg, sizeof(reqmsg) ) ) return START_TIMEOUT;

    /* Read response - a SEQUENCE - it's length is the packet length.
     * The length itself is variably encoded, so we extract it first.
     */

    if( !(pkt = sock_getbin(ctx, 2, 0 )) )      return START_TIMEOUT;
    if( pkt[0] != 0x30 )                        return START_FAILED; /* Not SEQ */
    if( pkt[1] & 0x80 ) {
        i = pkt[1] & 0x7F;
        if( i == 0 || i == 0x7F )               return START_FAILED; /* Invalid len */
        if( !(pkt = sock_getbin(ctx, (size_t)i, 0)) )   return START_TIMEOUT;
        pktlen = *pkt++;
        while( --i ) {
            pktlen <<= 8;
            pktlen |= *pkt++;
        }
    } else {
        pktlen = pkt[1] & 0x7F;
    }
    if( pktlen <= sizeof(rsphdr) || pktlen > 8192 )
        return START_FAILED; /* Invalid len */

    /* Response body */

    if( !(pkt = sock_getbin(ctx, pktlen, 0)) )  return START_TIMEOUT;

    if( memcmp(pkt, rsphdr, sizeof(rsphdr)) )   return START_FAILED; /* Msg ID/app */
    pkt += sizeof(rsphdr);                      /* APP 24 */
    pktlen -= sizeof(rsphdr);

    /* Length of APPLICATION 24 string */

    i = *pkt & 0x7F;
    --pktlen;
    if( *pkt++ & 0x80 ) {
        if( i == 0 || i == 0x7F )               return START_FAILED; /* Invalid len */
        alen = *pkt++;
        --pktlen;
        while( --i ) {
            if( pktlen-- == 0 )                 return START_FAILED;
            alen <<= 8;
            alen |= *pkt++;
        }
    } else {
        alen = (size_t)i;
    }
    if( alen > pktlen || alen < 3)              return START_FAILED;

    /* ENUMERATED response code - again, a variable length integer */

    elen = pkt[1] & 0x7F;
    if( !(pkt[0] == 0x0a && elen && !(pkt[1] & 0x80)) )
        return START_FAILED;
    alen -= 2;
    if( alen < elen )                           return START_FAILED;
    alen -= elen;
    pktlen -= elen + 2;
    pkt += 2;
    rc = *pkt++;
    --pktlen;
    while( --elen ) {
        rc <<= 8;
        rc |= *pkt++;
        --pktlen;
    }
    if( rc == ldap_success ) return START_STARTED;

    LOG(apr_psprintf(ctx->p, "LDAP response %d - %s\n", rc, ldap_errstr(rc) ));

    /* Additional information could be reported:
     * Octect string, len possibly 0 = responseName
     * Octect string, usually text, len possibly 0 = responseValue
     */
    return START_FAILED;
}

/* I/O routines.
 *
 * Note that any receive can re-allocate (and move) the input buffer.
 * Don't hold any references across reads.
 */

static const char *sock_getline( ctx_t *ctx ) {
    apr_size_t n;
    apr_status_t rv;

    ctx->len = 0;
    do {
        if( ctx->len >= ctx->size -1 ) {
            char *t = ctx->line;
            ctx->size *= 2;
            ctx->line = apr_palloc(ctx->p, ctx->size);
            memcpy( ctx->line, t, ctx->len );
        }
        n = 1;
        if( APR_SUCCESS != (rv = apr_socket_recv( ctx->sock, ctx->line+ctx->len, &n )) ||
            n != 1 ) {
            LOG( apr_psprintf(ctx->p, "<< error %d\n", rv ) );
            return NULL;
        }
        if( ctx->line[ctx->len] != CR ) {
            if( ctx->line[ctx->len++] == ctx->term[0] ) {
                ctx->line[--ctx->len] = '\0';
                LOG( apr_psprintf(ctx->p, "<< %s%s\n", ctx->line,
                                  ctx->term[0] == LF? "" : ctx->term ) );
                return ctx->line;
            }
        }
    } while( 1 );
}

static int sock_putline( ctx_t *ctx, const char *s ) {
    apr_status_t rv;
    apr_size_t ilen, olen;

    olen =
        ilen = strlen(s);
    if( APR_SUCCESS != (rv = apr_socket_send( ctx->sock, s, &olen)) ||
        ilen != olen ) {
        LOG( apr_psprintf(ctx->p, ">>error %d\n", rv ) );
        return 0;
    }
    LOG( apr_psprintf(ctx->p, ">> %s", s ) );
    return 1; 
}

static const unsigned char *sock_getbin( ctx_t *ctx, apr_size_t len, int append ) {
    apr_size_t n;
    apr_status_t rv;

    if( !append ) ctx->len = 0;
    if( !sock_xpand( ctx, ctx->len + len ) ) return NULL;

    do {
        n = ctx->size - ctx->len;
        if( n > len ) n = len;
        if( APR_SUCCESS != (rv = apr_socket_recv( ctx->sock, ctx->line+ctx->len, &n )) ||
            n <= 0 ) {
            LOG( apr_psprintf(ctx->p, "<< error %d\n", rv ) );
            return NULL;
        }
        ctx->len += n;
        if( n >= len ) {
            if( ctx->flags & FLG_DEBUG ) printbin( ctx, 0, (unsigned char *)ctx->line, ctx->len );
            return (unsigned char *)ctx->line;
        }
        len -= n;
    } while( 1 );
}

static int sock_xpand( ctx_t *ctx, apr_size_t len ) {
    char *t;
    if( ctx->size >= len ) return 1;
    if( !(t = apr_palloc(ctx->p, len )) ) return 0;
    memcpy( t, ctx->line, ctx->size );
    ctx->size = len;
    ctx->line = t;
    return 1;
}

static int sock_putbin( ctx_t *ctx, const unsigned char *s, const apr_size_t len ) {
    apr_status_t rv;
    apr_size_t olen;

    olen = len;
    if( APR_SUCCESS != (rv = apr_socket_send( ctx->sock, (char *)s, &olen)) ||
        olen != len ) {
        LOG( apr_psprintf(ctx->p, ">>error %d\n", rv ) );
        return 0;
    }
    if( ctx->flags & FLG_DEBUG ) printbin( ctx, 1, s, len );
    return 1; 
}

static void printbin( ctx_t *ctx, int dir, const unsigned char *s,
                      apr_size_t len ) {
    char line[2+1+ 4+1+ (8 * (1+(4*2))) + 1+1];
    char text[sizeof(line)];
    char *lp = line, *tp = text;
    const char *ds = dir? ">> " : "<< ";
    size_t l = 0, ofs = 0, dl = dir? 3 : 3;

    while( len ) {
        if( lp == line ) {
            if( ofs == 0 ) {
                strcpy( line, ds );
            } else {
                memset( line, ' ', dl );
            }
            lp += dl;
            lp += sprintf( lp, "%04x:", (unsigned int)ofs );
            l = 0;
            memset( text, ' ', dl+4+1 );
            tp = text + dl+4+1;
        }
        if( (l % 4) == 0 ) {
            *lp++ = ' ';
            *tp++ = ' ';
        }
        lp += sprintf( lp, "%02x", *s );
        tp += sprintf( tp, " %c", isprint(*s)? *s: '.' );
        ++s;
        ++l;
        ++ofs;
        if( --len == 0 || l == 32 ) {
            *tp = *lp = '\n';
            tp += 1; lp += 1;
            *tp = *lp = '\0';
            LOG( apr_pstrdup( ctx->p, line ) );
            LOG( apr_pstrdup( ctx->p, text ) );
            lp = line;
        }
    }
}
