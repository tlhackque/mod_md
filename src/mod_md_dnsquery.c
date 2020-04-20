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

/* Functions */

#define HAVE_RESOLV_CONF 1
#define DNSQ_HTML

#ifdef SA_TEST
  #define USE_SYSTEM_DNS_SERVERS 1
#else
  /* Get options from configure
   * Why not config.h? Twisty passages.
   */
  #include "md_version.h"
#endif

#ifndef DNSQ_RESOLV_CONF
  #define DNSQ_RESOLV_CONF "/etc/resolv.conf"
#endif

/* Formatting */
#ifndef DNSQ_DOM_WID
  #define DNSQ_DOM_WID 32u
#endif
#ifndef DNSQ_TTL_WID
  #define DNSQ_TTL_WID 4u
#endif
#ifndef DNSQ_CAFLG_WID
  #define DNSQ_CAFLG_WID 3u
#endif
#ifndef DNSQ_CATAG_WID
  #define DNSQ_CATAG_WID 9u
#endif
/* CAUTION: mod_md_status parses (some of) these.
 */
#define DNSQ_TR(c)    "<tr class=\""c"rec\"><td>"
#define DNSQ_TD_TTL   "<td class=\"ttl\">"
#define DNSQ_TD_CLS   "<td class=\"class\">"
#define DNSQ_TD_TYPE  "<td class=\"type\">"
#define DNSQ_TD_CAFLG "<td class=\"flags\">"
#define DNSQ_TD_CATAG "<td class=\"tag\">"
#define DNSQ_TD_CAVAL "<td class=\"value\">"
#define DNSQ_TD_TXT   "<td colspan=\"3\">"

#ifdef DNSQ_HTML
  #define HTML(x) do { if( use_html ){                            \
                           memcpy(tp, DNSQ_##x,sizeof(DNSQ_##x)); \
                           tp += sizeof(DNSQ_##x)-1; } } while(0)
  #define PAD (!use_html)
#else
  #define HTML(x)
#define PAD (1)
#endif

/* To build for stand-alone testing (Unix):
 * dnf install apr apr-devel apr-util apr-util-devel
 * gcc  -D_LARGEFILE64_SOURCE -DSA_TEST -Wall -Wextra -pedantic -g -o mod_md_dnsquery -I/usr/include/apr-1 -lapr-1 mod_md_dnsquery.c
 * Can also run as a console app under MS Visual Studio.
 */

#include "mod_md_dnsquery.h"

#define DNSQUERY_FLAGS (DNSQUERY_USE_HTML|DNSQUERY_MASK_TTL)

#ifdef SA_TEST
#include <stdio.h>
#else
  #include <httpd.h>
  #include <http_log.h>
  #ifdef APLOG_USE_MODULE
    APLOG_USE_MODULE(md);
  #endif
#endif

#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>

#include <apr.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_strings.h>

#if USE_SYSTEM_DNS_SERVERS
 #if HAVE_RESOLV_CONF
  #include <apr_file_io.h>
 #endif
 #if defined _WIN32 
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  #include <windows.h>
  #pragma comment(lib, "IPHLPAPI.lib")
  #pragma comment(lib, "Ws2_32.lib")
  #define WORKING_BUFFER_SIZE 15000
  #define MAX_TRIES 3
 #endif
#endif
#include <apr_pools.h>
#include <apr_network_io.h>
#include <apr_strings.h>
#define MALLOC(size) apr_palloc(p,(size))

#define DNS_MAXNLEN 255
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_TXT 16
#define DNS_TYPE_CAA 257
#define DNS_CLASS_IN 1

/* Must be public - or have the same view as CAs.
 * If USE_SYSTEM_DNS_SERVERS is enabled, these
 * will only be used if the system configuration
 * doesn't provide at least one.
 */
#ifndef DNSQ_PUBLIC_NAMESERVERS
#define DNSQ_PUBLIC_NAMESERVERS                                         \
    "8.8.8.8,"                "9.9.9.9,"       "1.1.1.1,"               \
    "[2001:4860:4860::8888]," "[2620:fe::fe]," "[2606:4700:4700::1111]"
#endif
static const char defaultns[] ={ DNSQ_PUBLIC_NAMESERVERS };

/* Forward */
static apr_array_header_t *find_ns( apr_pool_t *p );
#if USE_SYSTEM_DNS_SERVERS
  #if HAVE_RESOLV_CONF
    static apr_array_header_t *find_unix_ns( apr_array_header_t **result, apr_pool_t *p );
  #endif
  #ifdef _WIN32
    static apr_array_header_t *find_windows_ns( apr_array_header_t **result, apr_pool_t *p );
  #endif
#endif
static apr_array_header_t *find_default_ns( apr_array_header_t **result, apr_pool_t *p );
static uint8_t *txt2dnsname( uint8_t *rec, const char *dom );

#ifdef SA_TEST
int main(int argc, char **argv) {
    apr_pool_t *p;
    apr_status_t rv;
    apr_array_header_t *recs;

    rv = apr_initialize();
    if( rv != APR_SUCCESS ) return 1;
    rv = apr_pool_create( &p, NULL );
    if( rv != APR_SUCCESS ) return 2;

    if( argc >= 2 ) {
        int j;
        recs = apr_array_make(p,5, sizeof(const char *));
        j = (argc >= 3 && !strcmp(argv[2],"txt")? DNSQUERY_TXT: DNSQUERY_CAA);
        if( argc >=4 && !strcmp(argv[3],"html") ) j |= DNSQUERY_USE_HTML;
        rv = dnsq_find_rrset(p, recs, argv[1], j );
        for( j = 0; j < recs->nelts; j++ ) {
            printf( "%s\n", APR_ARRAY_IDX(recs, j,const char *));
        }
    }
    if( rv != APR_SUCCESS ) return 4;

    apr_pool_destroy(p);
    apr_terminate();
    return 0;
}
int errstr( apr_status_t rv ) {
    char buf[HUGE_STRING_LEN];

    printf( "%s\n", apr_strerror(rv, buf, sizeof(buf)));
    return 1;
}

#endif

/* Find the CAA or TXT records for a zone.
 * This is for a management display, not authorization.
 */
apr_status_t dnsq_find_rrset( apr_pool_t *p, apr_array_header_t *recs,
                         const char *dom, md_dnsquery_rr_t rrtype ) {
    apr_status_t rv;
    apr_array_header_t *ns;
    size_t n, nfound = 0;
    uint16_t type;
    uint16_t mask_ttl = rrtype & DNSQUERY_MASK_TTL;
#ifdef DNSQ_HTML
    uint16_t use_html = rrtype & DNSQUERY_USE_HTML;
#endif

    type = (uint16_t) rrtype;
    switch( type & ~DNSQUERY_FLAGS ) {
    case DNSQUERY_CAA:
        type = DNS_TYPE_CAA;
        break;
    case DNSQUERY_TXT:
        type = DNS_TYPE_TXT;
        break;
    default:
        return APR_EGENERAL;
    }
    
    ns = find_ns(p);
    if( !ns->nelts ) return APR_EGENERAL;

    for( n = 0; n < (size_t)ns->nelts; ++n ) {
        int serverok = 1;
        apr_sockaddr_t *sa;
        apr_socket_t *sock;
        char *hn, *sid;
        apr_port_t pn;

        if (APR_SUCCESS != (rv = apr_parse_addr_port( &hn, &sid, &pn, APR_ARRAY_IDX(ns,n,const char *), p)) ||
            sid != NULL || hn == NULL || pn != 0 )
            continue;
        if (APR_SUCCESS != (rv = apr_sockaddr_info_get(&sa, hn, APR_UNSPEC, 53, 0, p)) ||
            APR_SUCCESS != apr_socket_create(&sock,sa->family, SOCK_STREAM, APR_PROTO_TCP, p) ||
            APR_SUCCESS != (rv = apr_socket_opt_set(sock, APR_SO_NONBLOCK, 1)) ||
            APR_SUCCESS != (rv = apr_socket_timeout_set(sock, apr_time_from_sec(5))) ||
            APR_SUCCESS != (rv = apr_socket_connect(sock, sa))) continue;
        if (APR_SUCCESS != (rv = apr_socket_opt_set(sock, APR_SO_NONBLOCK, 0)) ||
            APR_SUCCESS != (rv = apr_socket_timeout_set(sock, apr_time_from_sec(10)))) {
            apr_socket_close(sock );
            continue;
        }

        do { /* Query this server */
            typedef struct {
                uint16_t msglen;
                uint16_t id;
                uint16_t opflags;
                uint16_t qdcount;
                uint16_t ancount;
                uint16_t nscount;
                uint16_t arcount;
                uint8_t data[DNS_MAXNLEN+1+(2*sizeof(uint16_t))]; /* Query */
            } dns_msg_t;
            typedef struct {
                uint16_t type;
                uint16_t class;
                uint32_t ttl;
                uint16_t rdlen;
            } dns_rr_t;
            dns_msg_t req, *rsp;
            dns_rr_t rr;
            apr_size_t slen, len;
            uint16_t rlen;
            uint8_t *data, *np;
            char txt[HUGE_STRING_LEN], *tp;

            apr_generate_random_bytes( (unsigned char *)&req.id, sizeof(req.id) );
            req.opflags = htons(0x0100); /* Query, RD */
            req.qdcount = htons(1);
            req.ancount = 0;
            req.nscount = 0;
            req.arcount = 0;

            data = txt2dnsname( req.data, dom );
            if( !data ) return APR_EGENERAL;
            *((uint16_t*)data) = htons(type);
            data += sizeof(uint16_t);
            *((uint16_t*)data) = htons(DNS_CLASS_IN);
            data += sizeof(uint16_t);
            slen = len = (apr_size_t)(data - (uint8_t *)&req);
            req.msglen = htons((uint16_t)(len - offsetof(dns_msg_t,id)));

            if (APR_SUCCESS != (rv = apr_socket_send( sock, (char *)&req, &len )) ||
                len != slen) {
                break;
            }
            slen = len = sizeof(rlen);
            if (APR_SUCCESS != (rv = apr_socket_recv( sock, (char *)&rlen, &len )) ||
                len != slen) {
                break;
            }
            slen = len = ntohs(rlen);
            rsp = (dns_msg_t *)MALLOC(slen + offsetof(dns_msg_t,id));
            if( !rsp ) return APR_EGENERAL;
            if (APR_SUCCESS != (rv = apr_socket_recv( sock, offsetof(dns_msg_t,id)+(char *)rsp, &len )) ||
                len != slen || req.id != rsp->id) break;
            rsp->qdcount = ntohs(rsp->qdcount);
            rsp->ancount = ntohs(rsp->ancount);
            rsp->nscount = ntohs(rsp->nscount);
            rsp->arcount = ntohs(rsp->arcount);
            rsp->opflags = ntohs(rsp->opflags);
            switch( (rsp->opflags ^0x80) & 0x8f ) { /* RA */
            case 0:  /* NOERROR */
            case 3:  /* NAMERR/NXDOMAIN */
                break;
            case 1:  /* FMTERR */
            case 2:  /* SRVFAIL */
            case 4:  /* NOTIMP */
            case 5:  /* REFUSED */
            case 6:  /* YXDOMAIN */
            case 7:  /* XRRSET */
            case 8:  /* YXRRSET */
            case 9:  /* NOTAUTH */
            case 10: /* NOTZONE */
            default:
                serverok = 0;
                continue;
            }
            if( !rsp->ancount ) {
                dom += req.data[0];
                if( *dom == '.' ) ++dom;
                if( type != DNS_TYPE_CAA ||
                    !*dom || (*dom == '.' && !dom[1]) ) {
                    apr_socket_close(sock);
                    return APR_NOTFOUND;
                }
                continue;
            }
            data = rsp->data;
            while( rsp->qdcount ) {
                --rsp->qdcount;
                while( *data ) {
                    if( *data > 63 ) {
                        data += sizeof(uint16_t);
                        break;
                    }
                    data += 1 + *data;
                    if( (apr_size_t)(data - (uint8_t *)rsp) > len ) break;
                }
                data += 1 + (2 * sizeof( uint16_t ));
                if( (apr_size_t)(data - (uint8_t *)rsp) > len ) break;
            }
            while( rsp->ancount ) {
                int ptrlimit = 100;

                tp = txt;
                if( type == DNS_TYPE_CAA ) { HTML(TR("caa")); } else { HTML(TR("txt")); }
                np = NULL;
                while( *data ) {
                    if( *data > 63 ) {
                        if(!np) np = data + sizeof(uint16_t);
                        rlen = ntohs(((uint16_t*)data)[0]) & 0x3FF;
                        if( ((*data & 0xC0) != 0xC0) || ptrlimit-- <= 0 ||
                            rlen < offsetof(dns_msg_t,data) - offsetof(dns_msg_t,id) ||
                            rlen + offsetof(dns_msg_t,data) >= len ) {
                            apr_socket_close(sock);
                            return APR_EGENERAL;
                        }
                        data = rlen + (uint8_t *)&rsp->id;
                        continue;
                    }
                    rlen = *data++;
                    if( (tp -txt) + rlen > DNS_MAXNLEN ) {
                        apr_socket_close(sock);
                        return APR_EGENERAL;
                    }
                    memcpy(tp, data, rlen);
                    tp += rlen;
                    *tp++ = '.';
                    data += rlen;
                }
                if(np) data = np; else ++data;
                if( PAD && (rlen = (uint16_t)(tp-txt)) < DNSQ_DOM_WID ) {
                    memset( tp, ' ', DNSQ_DOM_WID - rlen);
                    tp += DNSQ_DOM_WID - rlen;
                }
                *tp++ = ' ';
                rr.type = ntohs(((uint16_t *)data)[0]);
                rr.class = ntohs(((uint16_t *)data)[1]);
                data += 2 * sizeof(uint16_t);
                rr.ttl = ntohl(((uint32_t *)data)[0]);
                data += sizeof(uint32_t);
                rr.rdlen = ntohs(((uint16_t *)data)[0]);
                data += sizeof(uint16_t);
                HTML(TD_TTL);
                if( mask_ttl ) {
                    tp += sprintf( tp, "%*s ", DNSQ_TTL_WID, "123*" );
                } else {
                    tp += sprintf( tp, "%*u ", DNSQ_TTL_WID,rr.ttl );
                }
                HTML(TD_CLS);
                if( rr.class == DNS_CLASS_IN ) {
                    strcpy( tp, "IN  " );
                    tp += 4;
                } else {
                    tp += sprintf( tp, "CLASS%u ", rr.class );
                }
                HTML(TD_TYPE);
                if( rr.type == DNS_TYPE_CAA ) {
                    strcpy( tp, "CAA " );
                    tp += 4;
                } else if( rr.type == DNS_TYPE_TXT ) {
                    strcpy( tp, "TXT " );
                    tp += 4;
                } else {
                    tp += sprintf( tp, "TYPE%u ", rr.type );
                }
                rlen = rr.rdlen;
                if( rr.type == DNS_TYPE_CAA ) {
                    size_t j;
                    HTML(TD_CAFLG);
                    tp += sprintf( tp, "%*u ", DNSQ_CAFLG_WID, *data++ );
                    j = *data++;
                    rlen = (uint16_t)(rlen - 2);
                    HTML(TD_CATAG);
                    if( j > rlen ) j = rlen;
                    memcpy( tp, data, j );
                    tp += j;
                    data += j;
                    rlen = (uint16_t)(rlen -j);
                    if( PAD && j < DNSQ_CATAG_WID ) {
                        memset( tp, ' ', DNSQ_CATAG_WID - j );
                        tp += DNSQ_CATAG_WID -j;
                    }
                    *tp++ = ' ';
                    HTML(TD_CAVAL);
                    *tp++ = '"';
                    memcpy( tp, data, rlen );
                    tp += rlen;
                    *tp++ = '"';
                    *tp = '\0';
                } else if( rr.type == DNS_TYPE_TXT ) {
                    HTML(TD_TXT);
                    if( rlen ) {
                        do {
                            size_t j = *data++;
                            --rlen;
                            if( j > rlen ) j = rlen;
                            if( j == 0 ) break;
                            *tp++ = ' ';
                            *tp++ = '"';
                            memcpy( tp, data, j );
                            data += j;
                            tp += j;
                            rlen = (uint16_t)(rlen - j);
                            *tp++ = '"';
                            *tp = '\0';
                        } while( rlen );
                    } else {
                        tp += sprintf( tp, "\"\"" );
                    }
                } else if( rr.type == DNS_TYPE_CNAME ) {
                    if( type == DNS_TYPE_CAA ) { /* Don't follow, climb */
                        dom += req.data[0];
                        if( *dom == '.' ) ++dom;
                        if( *dom && *dom != '.' && dom[1] ) break;
                        apr_socket_close(sock);
                        return APR_NOTFOUND;
                    }
                    /* Informational, ignore - answer, if any, follows */
                    data += rlen;
                    --rsp->ancount;
                    continue;
                }
                data += rlen;
                APR_ARRAY_PUSH(recs, const char *) = apr_pstrdup(p,txt);
                ++nfound;
                --rsp->ancount;
            }
            if( !rsp->ancount ) {
                apr_socket_close(sock);
                return APR_SUCCESS;
            }
        } while(serverok);

        apr_socket_close(sock);
    }

    if( nfound ) return APR_SUCCESS;
    return APR_EGENERAL;
}

/* Find available recursive nameservers
 */
static
apr_array_header_t *find_ns( apr_pool_t *p ) {
    apr_array_header_t *ns = NULL;

#if USE_SYSTEM_DNS_SERVERS
  #ifdef _WIN32
    (void) find_windows_ns( &ns, p );
  #endif
  #if HAVE_RESOLV_CONF
    (void) find_unix_ns( &ns, p );
  #endif
    return ns;
#else
    return find_default_ns( &ns, p );
#endif
}


#if USE_SYSTEM_DNS_SERVERS
#if HAVE_RESOLV_CONF
static
apr_array_header_t *find_unix_ns( apr_array_header_t **result, apr_pool_t *p ) {
    apr_array_header_t *ns;
    apr_status_t rv;
    apr_file_t *rc;
    char buf[HUGE_STRING_LEN];

    if( result ) {
        ns = *result;
        if( ns == NULL ) {
            *result =
                ns = apr_array_make(p, 5, sizeof(const char *));
        }
    } else {
        ns = apr_array_make(p, 5, sizeof(const char *));
    }

    if( APR_SUCCESS == (rv = apr_file_open(&rc, DNSQ_RESOLV_CONF,
                                           APR_FOPEN_READ | APR_FOPEN_BUFFERED,
                                           APR_OS_DEFAULT, p)) ) {
    
        while( APR_SUCCESS == (rv = apr_file_gets(buf, sizeof(buf), rc)) ) {
            char *s, *e;

            for( s = buf; *s == ' '; s++ )
                ;
            if( strncmp(s, "nameserver", 10 ) ) continue;
            for( s += 10; *s == ' '; ++s)
                ;
            if( !*s ) continue;
            if( (e = strchr(s,'\n')) ) *e = '\0';
            if( !strlen(s) ) continue;
            if( s[0] != '[' && strchr(s, ':') ) {
                APR_ARRAY_PUSH(ns, const char *) = apr_psprintf(p, "[%s]", s);
            } else {
                APR_ARRAY_PUSH(ns, const char *) = apr_pstrdup(p, s);
            }
        }
        apr_file_close( rc );

        if( rv == APR_EOF && ns->nelts ) return ns;
    }

    return find_default_ns( &ns, p );
}
#endif

#ifdef _WIN32
static
apr_array_header_t *find_windows_ns( apr_array_header_t **result, apr_pool_t *p ) {
    apr_array_header_t *ns;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    ULONG outBufLen = WORKING_BUFFER_SIZE;
    ULONG Iterations = 0;
    ULONG flags = GAA_FLAG_SKIP_UNICAST|GAA_FLAG_SKIP_ANYCAST|
        GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_FRIENDLY_NAME;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;

    if( result ) {
        ns = *result;
        if( ns == NULL ) {
            *result =
                ns = apr_array_make(p, 5, sizeof(const char *));
        }
    } else {
        ns = apr_array_make(p, 5, sizeof(const char *));
    }

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *) MALLOC(outBufLen);
        if (pAddresses == NULL) return ns;

        dwRetVal =
            GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            pAddresses = NULL;
        } else {
            break;
        }
        Iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {
        for(pCurrAddresses = pAddresses; pCurrAddresses;
            pCurrAddresses = pCurrAddresses->Next) {

            for( pDnServer = pCurrAddresses->FirstDnsServerAddress; pDnServer;
                 pDnServer = pDnServer->Next ) {
                char buf[HUGE_STRING_LEN];
                const char *s;

                if( getnameinfo( pDnServer->Address.lpSockaddr,
                                 pDnServer->Address.iSockaddrLength,
                                 buf, sizeof(buf), NULL, 0, NI_NUMERICHOST ) )
                    continue;
                s = buf;
                if( strchr( s, ':') ) {
                    APR_ARRAY_PUSH(ns, const char *) =
                        apr_psprintf(p, "[%s]", s);
                } else {
                    APR_ARRAY_PUSH(ns, const char *) =
                        apr_pstrdup(p, s);
                }
            }
        }
        if (ns->nelts) return ns;
    }

    return find_default_ns( &ns, p );
}
#endif
#endif

static
apr_array_header_t *find_default_ns( apr_array_header_t **result, apr_pool_t *p ) {
    apr_array_header_t *ns;
    const char *sp, *ep;
    char tbuf[DNS_MAXNLEN+1];

    if( result ) {
        ns = *result;
        if( ns == NULL ) {
            *result =
                ns = apr_array_make(p, 5, sizeof(const char *));
        }
    } else {
        ns = apr_array_make(p, 5, sizeof(const char *));
    }

    /* Parse the string.  (It's a string to get through configure easily.) */

    for( sp = defaultns; *sp; ++sp ) {
        if( isspace( *sp ) ) continue;
        for( ep = sp; ep - sp < DNS_MAXNLEN; ++ep ) {
            if( !*ep || isspace(*ep) || *ep == ',' ) {                
                ptrdiff_t len = ep - sp;
                if( len ) {
                    memcpy( tbuf, sp, (size_t)len );
                    tbuf[len] = '\0';
                    if( tbuf[0] != '[' && strchr( tbuf, ':') ) {
                        memmove( tbuf+1, tbuf, (size_t)len );
                        tbuf[0] = '['; tbuf[len+1] = ']'; tbuf[len+2] = '\0';
                    }
                    APR_ARRAY_PUSH(ns, const char *) = apr_pstrdup(p, tbuf);
                    sp = *ep? ep: ep -1;
                    break;
                }
                break;
            }
        }
    }

    return ns;
}

/* Encode DNS name for query.  No point in compression;
 * there's at most one time, and this is a bare bones
 * stub resolver.
 */

static
uint8_t *txt2dnsname( uint8_t *rec, const char *dom ) {
    const char *dp = NULL;
    size_t dlen = strlen(dom);

    while( dlen ) {
        if( (dp = strchr(dom, '.')) ) {
            ptrdiff_t ll;

            ll = dp - dom;
            if( ll > 63 ) return NULL;
            *rec++ = (uint8_t)ll;
            memcpy(rec, dom, (size_t)ll);
            rec += ll;
            dom = ++dp;
            dlen -= (size_t)ll+1;
        } else {
            if( dlen > 63 ) return NULL;
            *rec++ = (uint8_t)dlen;
            memcpy(rec, dom, dlen);
            rec += dlen;
            dlen = 0;
        }
    }
    *rec++ = 0;
    return rec;
}
