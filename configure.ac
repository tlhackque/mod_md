# Copyright 2019 greenbytes GmbH (https://www.greenbytes.de)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

AC_PREREQ([2.69])
AC_INIT([mod_md], [2.3.3], [stefan.eissing@greenbytes.de])

LT_PREREQ([2.2.6])
LT_INIT()
dnl See versioning rule:
dnl  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST(LT_CURRENT, 11)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 6)

major=`echo $PACKAGE_VERSION |cut -d. -f1 | sed -e "s/[^0-9]//g"`
minor=`echo $PACKAGE_VERSION |cut -d. -f2 | sed -e "s/[^0-9]//g"`
patch=`echo $PACKAGE_VERSION |cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g"`

PACKAGE_VERSION_NUM=`printf "0x%02x%02x%02x" "$major" "$minor" "$patch"`

AC_SUBST(PACKAGE_VERSION_NUM)

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([subdir-objects no-define])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_HEADERS([src/config.h])

AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
                    [Turn on compile time warnings])],
    [werror=$enableval], [werror=no])

AC_ARG_ENABLE([unit-tests],
    [AS_HELP_STRING([--enable-unit-tests],
                    [Enable C-based unit tests (requires libcheck)])],
    [enable_unit_tests=$enableval], [enable_unit_tests=yes])

AC_ARG_WITH([apxs], [AS_HELP_STRING([--with-apxs],
    [Use APXS executable [default=check]])],
    [request_apxs=$withval], [request_apxs=check])

AC_ARG_WITH([curl], [AS_HELP_STRING([--with-curl], [Use curl from this prefix])],
    [request_curl=$withval], [request_curl=check])

AC_ARG_WITH([serverdir], [AS_HELP_STRING([--with-serverdir],
    [Use serverdir directory for setup [default=gen/apache]])],
    [request_serverdir=$withval], [request_serverdir=$PWD/test/gen/apache])

AC_ARG_WITH([boulder], [AS_HELP_STRING([--with-boulder], [Use given url for boulder])],
    [request_boulder=$withval], [request_boulder=def])

AC_ARG_WITH([jansson], [AS_HELP_STRING([--with-jansson], [Use jansson from this prefix])],
    [request_jansson=$withval], [request_jansson=check])

AC_ARG_WITH([openssl], [AS_HELP_STRING([--with-openssl], [Use openssl from this prefix])],
    [request_openssl=$withval], [request_openssl=check])

AC_ARG_WITH([boulder-dir], [AS_HELP_STRING([--with-boulder-dir], [Use boulder from this directory])],
    [request_boulder_dir=$withval], [request_boulder_dir=def])

AC_ARG_WITH([jQuery], [AS_HELP_STRING([--with-jQuery], [URL of jQuery])],
    [jq_url="$with_jQuery"], [jq_url=https://code.jquery.com/jquery-3.5.0.min.js])
AC_SUBST(JQUERY_URL,["$jq_url"])

AC_ARG_WITH([jQueryUI], [AS_HELP_STRING([--with-jQueryUI], [URL of jQueryUI])],
    [jqui_url="$with_jQueryUI"], [jqui_url=https://code.jquery.com/ui/1.12.1/jquery-ui.min.js])
AC_SUBST(JQUERYUI_URL,["$jqui_url"])

AC_ARG_WITH([jQueryUITheme], [AS_HELP_STRING([--with-jQueryUITheme], [URL of jQueryUI theme's CSS])],
    [jquicss_url="$with_jQueryUITheme"], [jquicss_url=https://code.jquery.com/ui/1.12.1/themes/base/jquery-ui.css])
AC_SUBST(JQUERYUICSS_URL,["$jquicss_url"])

AC_ARG_ENABLE([system-dns-servers],AS_HELP_STRING([--enable-system-dns-servers],[Enables use of the DNS servers configured by the operating system for management queries.The default public servers are often a better choice.]))
AS_IF([test "x$enable_system_dns_servers" = "xyes"],[system_dns=$enableval], [system_dns=no])
AS_IF([test "x$system_dns" = "xyes"],[AC_SUBST([USE_SYSTEM_DNS_SERVERS],[1])],[AC_SUBST([USE_SYSTEM_DNS_SERVERS],[0])])

AC_ARG_WITH([resolv-conf], [AS_HELP_STRING([--with-resolv-conf], [Alternate file to /etc/resolv.conf if --enable-system-dns-servers])],
    [DNSQ_RESOLV_CONF="$with_resolv_conf"], [DNSQ_RESOLV_CONF="/etc/resolv.conf"])
AC_SUBST(DNSQ_RESOLV_CONF)

AC_ARG_WITH([public-dns], [AS_HELP_STRING([--with-public-dns], [Public DNS servers to use as default, last resort, and --disable-system-dns-servers])],
    [DNSQ_PUBLIC_NAMESERVERS="$with_public_dns"], [DNSQ_PUBLIC_NAMESERVERS="8.8.8.8,9.9.9.9,1.1.1.1,[2001:4860:4860::8888],2620:fe::fe,[2606:4700:4700::1111]"])
AC_SUBST(DNSQ_PUBLIC_NAMESERVERS)

AC_ARG_WITH([debug-js], [AS_HELP_STRING([--with-debug-js], [URI for debugging management GUI javascript.])],
    [AC_SUBST(MANAGE_DEBUG_JS,["#define MD_MANAGE_DEBUG_JS \"$with_debug_js\""])AC_SUBST(MANAGE_DEBUG_DATA,["#define MD_MANAGE_DEBUG_DATA 1"])],)

AC_SUBST([MOD_MD_CONFIGURE_ARGS],["$ac_configure_args"])

SERVER_NAME=$(hostname -f)
AC_SUBST(SERVER_NAME)
GEN_DIR="$PWD/test/gen"
AC_SUBST(GEN_DIR)
SERVER_DIR="$request_serverdir"
AC_SUBST(SERVER_DIR)
HTTP_PORT=5002
AC_SUBST(HTTP_PORT)
HTTPS_PORT=5001
AC_SUBST(HTTPS_PORT)
HTTP_PROXY_PORT=5052
AC_SUBST(HTTP_PROXY_PORT)

HTTPD_USER="$USER"
AC_SUBST(HTTPD_USER)

MODULE_SRC="$PWD/src"
AC_SUBST(MODULE_SRC)


# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

WERROR_CFLAGS=""
if test "x$werror" != "xno"; then
    AX_CHECK_COMPILE_FLAG([-Wall], [WERROR_CFLAGS="$WERROR_CFLAGS -Wall"])
    AX_CHECK_COMPILE_FLAG([-Wconversion], [WERROR_CFLAGS="$WERROR_CFLAGS -Wconversion"])
    AX_CHECK_COMPILE_FLAG([-Wextra], [WERROR_CFLAGS="$WERROR_CFLAGS -Wextra"])
    AX_CHECK_COMPILE_FLAG([-Werror], [WERROR_CFLAGS="$WERROR_CFLAGS -Werror"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wmissing-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wstrict-prototypes"])
    AX_CHECK_COMPILE_FLAG([-Wmissing-declarations], [WERROR_CFLAGS="$WERROR_CFLAGS -Wmissing-declarations"])
    AX_CHECK_COMPILE_FLAG([-Wpointer-arith], [WERROR_CFLAGS="$WERROR_CFLAGS -Wpointer-arith"])
    # we like to use such things...
    #AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdeclaration-after-statement"])
    AX_CHECK_COMPILE_FLAG([-Wformat-security], [WERROR_CFLAGS="$WERROR_CFLAGS -Wformat-security"])
    AX_CHECK_COMPILE_FLAG([-Wwrite-strings], [WERROR_CFLAGS="$WERROR_CFLAGS -Wwrite-strings"])
    AX_CHECK_COMPILE_FLAG([-Wshadow], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshadow"])
    AX_CHECK_COMPILE_FLAG([-Winline], [WERROR_CFLAGS="$WERROR_CFLAGS -Winline"])
    AX_CHECK_COMPILE_FLAG([-Wnested-externs], [WERROR_CFLAGS="$WERROR_CFLAGS -Wnested-externs"])
    AX_CHECK_COMPILE_FLAG([-Wfloat-equal], [WERROR_CFLAGS="$WERROR_CFLAGS -Wfloat-equal"])
    AX_CHECK_COMPILE_FLAG([-Wundef], [WERROR_CFLAGS="$WERROR_CFLAGS -Wundef"])
    AX_CHECK_COMPILE_FLAG([-Wendif-labels], [WERROR_CFLAGS="$WERROR_CFLAGS -Wendif-labels"])
    AX_CHECK_COMPILE_FLAG([-Wempty-body], [WERROR_CFLAGS="$WERROR_CFLAGS -Wempty-body"])
# does not make sense with APR as it prefers char* to void*
#    AX_CHECK_COMPILE_FLAG([-Wcast-align], [WERROR_CFLAGS="$WERROR_CFLAGS -Wcast-align"])
    AX_CHECK_COMPILE_FLAG([-Wvla], [WERROR_CFLAGS="$WERROR_CFLAGS -Wvla"])
    AX_CHECK_COMPILE_FLAG([-Wunreachable-code], [WERROR_CFLAGS="$WERROR_CFLAGS -Wunreachable-code"])
    AX_CHECK_COMPILE_FLAG([-Waddress], [WERROR_CFLAGS="$WERROR_CFLAGS -Waddress"])
    AX_CHECK_COMPILE_FLAG([-Wattributes], [WERROR_CFLAGS="$WERROR_CFLAGS -Wattributes"])
    AX_CHECK_COMPILE_FLAG([-Wdiv-by-zero], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdiv-by-zero"])
    AX_CHECK_COMPILE_FLAG([-Wshorten-64-to-32], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshorten-64-to-32"])
    #AX_CHECK_COMPILE_FLAG([-Wno-sign-compare], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-sign-compare"])
    #AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-unused-parameter"])
    #AX_CHECK_COMPILE_FLAG([-Wno-shadow], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-shadow"])
    #AX_CHECK_COMPILE_FLAG([-Wno-undef], [WERROR_CFLAGS="$WERROR_CFLAGS -Wno-undef"])

    AX_CHECK_COMPILE_FLAG(["-std=c89"], [WERROR_CFLAGS="$WERROR_CFLAGS -std=c89"])
    AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdeclaration-after-statement"])

# gcc warnings, considered useful as in https://kristerw.blogspot.de/2017/09/useful-gcc-warning-options-not-enabled.html
#
    #AX_CHECK_COMPILE_FLAG(["-Wduplicated-cond"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wduplicated-cond"])
    #AX_CHECK_COMPILE_FLAG(["-Wduplicated-branches"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wduplicated-branches"])
    #AX_CHECK_COMPILE_FLAG(["-Wlogical-op"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wlogical-op"])
    #AX_CHECK_COMPILE_FLAG(["-Wrestrict"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wrestrict"])
    AX_CHECK_COMPILE_FLAG(["-Wnull-dereference"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wnull-dereference"])
    #AX_CHECK_COMPILE_FLAG(["-Wuseless-cast"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wuseless-cast"])
    #AX_CHECK_COMPILE_FLAG(["-Wjump-misses-init"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wjump-misses-init"])
    AX_CHECK_COMPILE_FLAG(["-Wdouble-promotion"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wdouble-promotion"])
    AX_CHECK_COMPILE_FLAG(["-Wshadow"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wshadow"])
    AX_CHECK_COMPILE_FLAG(["-Wformat=2"], [WERROR_CFLAGS="$WERROR_CFLAGS -Wformat=2"])
fi
AC_SUBST(WERROR_CFLAGS)

# Do we have a pkg-config?
AC_ARG_VAR([PKGCONFIG], [pkg-config executable])
AC_PATH_PROG([PKGCONFIG], [pkg-config])

ACME_DEFv1_URL=https://acme-v01.api.letsencrypt.org/directory
AC_SUBST(ACME_DEFv1_URL)

AC_ARG_WITH([default-ca-name], [AS_HELP_STRING([--with-default-ca-name], [Descriptive name of default Certificate Authority])],
    [ACME_DEF_CA_NAME="$with_default_ca_name"], [ACME_DEF_CA_NAME="Let's Encrypt"])
AC_SUBST(ACME_DEF_CA_NAME)
AC_ARG_WITH([default-ca], [AS_HELP_STRING([--with-default-ca], [URL of default Certificate Authority's ACME directory])],
    [ACME_DEF_URL="$with_default_ca"], [ACME_DEF_URL=https://acme-v02.api.letsencrypt.org/directory])
AC_SUBST(ACME_DEF_URL)

if test "x$request_boulder" = "xdef"; then
    BOULDER_URL=http://localhost:4000/directory
    BOULDERv2_URL=http://localhost:4001/directory
elif test "x${request_boulder##http}" = "x${request_boulder}"; then
    BOULDER_URL="http://${request_boulder}/directory"
else
    BOULDER_URL="$request_boulder"
fi
AC_SUBST(BOULDER_URL)
AC_SUBST(BOULDERv2_URL)

# the path where boulder is installed
if test "x$request_boulder_dir" = "xdef"; then
    BOULDER_DIR="$GOPATH/src/github.com/letsencrypt/boulder"
else
    BOULDER_DIR="$request_boulder_dir"
fi

AC_SUBST(BOULDER_DIR)

# this is always the same, so far
BOULDER_TOS=http://boulder:4000/terms/v1
AC_SUBST(BOULDER_TOS)


# extern, we need to find where the apxs is. which then
# can tell us the various directories we need.
#
if test x"$request_apxs" = "xcheck"; then
    AC_PATH_PROG([APXS], [apxs])
    if test "x${APXS}" = "x"; then
        AC_MSG_ERROR("no APXS installation found")
    fi
else
    APXS="$request_apxs"
    AC_MSG_NOTICE("using APXS=$APXS as configured")
fi

export BUILD_SUBDIRS="src test"

prefix="$($APXS -q prefix)"
prefix="${prefix:-/usr}"
export PREFIX="${prefix}"
LDFLAGS="$LDFLAGS -L$($APXS -q libdir)"
CPPFLAGS="$CPPFLAGS -I$($APXS -q includedir) -I$($APXS -q APR_INCLUDEDIR)"
export SYSCONF_DIR="$($APXS -q sysconfdir)"
export LIBEXEC_DIR="$($APXS -q LIBEXECDIR)"

HTTPD_VERSION="$($APXS -q HTTPD_VERSION)"

# We need crypto to be in our link path, check for it.
#
AC_CHECK_LIB([crypto], [SHA256_Init], , [AC_MSG_ERROR("library crypto not found")])

# We need a JSON lib, like jansson
#

if test x"$request_jansson" = "xcheck"; then
    AC_CHECK_LIB([jansson], [json_loads], , [AC_MSG_ERROR("library jansson not found")])

    AC_CHECK_HEADER([jansson.h], [],  [AC_MSG_WARN("header jansson.h not found")], [
    #include <jansson_config.h>
    #undef   JSON_INLINE
    #define JSON_INLINE 
    #include <jansson.h>
    ])
    JANSSON_PREFIX=""
else
    LDFLAGS="$LDFLAGS -L$request_jansson/lib";
    CFLAGS="$CFLAGS -I$request_jansson/include";
    CPPFLAGS="$CPPFLAGS -I$request_jansson/include";
    JANSSON_PREFIX="$request_jansson"
fi


AC_CHECK_LIB([apr-1], [apr_pool_create_ex], [LIB_APR=apr-1], [AC_MSG_ERROR("library apr-1 not found")])
AC_SUBST(LIB_APR)
AC_CHECK_LIB([aprutil-1], [apr_brigade_create], [LIB_APRUTIL=aprutil-1], [AC_MSG_ERROR("library aprutil-1 not found")])
AC_SUBST(LIB_APRUTIL)

# We need a HTTP client which can talk https: and, optionally even HTTP/2
#

if test x"$request_curl" = "xcheck"; then
    AC_CHECK_LIB([curl], [curl_global_init], , [AC_MSG_ERROR("libcurl not found")])
    curl_config="curl-config"
    AC_CHECK_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
    if  test "x$CURL_CONFIG" = xno; then
        curl_config="${prefix}/bin/curl-config"
        AC_CHECK_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
    fi
else
    curl_config="$request_curl/bin/curl-config"
    AC_PATH_PROG([CURL_CONFIG],[$curl_config],[yes],[no])
fi

AM_CONDITIONAL([FOUND_CURL_CONFIG], [test "x$CURL_CONFIG" = xyes])
AM_COND_IF([FOUND_CURL_CONFIG],,[AC_MSG_ERROR([required program 'curl-config' not found.])])

# $curl_config is available. Does it off SSL?
curl_ssl=$( $curl_config --features | fgrep SSL )
if test "x$curl_ssl" = "x"; then
    AC_MSG_ERROR([curl from $curl_config does not support SSL.])
fi

if test x"$curl_config" = "xcurl-config"; then
    CURL_BIN="curl"
else
    CURL_BIN=$( dirname $curl_config)/curl
fi
AC_SUBST(CURL_BIN)

AC_CHECK_HEADERS([curl/curl.h])

CFLAGS=`$curl_config --cflags`" $CFLAGS"
LDFLAGS=`$curl_config --libs`" $LDFLAGS"

AC_MSG_CHECKING([for curl version >= 7.50])
AC_TRY_COMPILE([#include <curl/curlver.h>],[
#if !defined(LIBCURL_VERSION_MAJOR)
#error "Missing libcurl version"
#endif
#if LIBCURL_VERSION_MAJOR < 7
#error "Unsupported libcurl version " LIBCURL_VERSION
#endif
#if LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR < 50
#error "Unsupported libcurl version " LIBCURL_VERSION
#endif],
      [AC_MSG_RESULT(OK)
       curl_version_ok=yes],
      [AC_MSG_RESULT(FAILED)])

if test x"$curl_version_ok" = "x"; then
    AC_MSG_ERROR([curl from $curl_config must be at least version 7.50.])
fi
AC_CHECK_FUNCS([gethostname])
AC_CHECK_HEADERS([limits.h unistd.h Winsock2.h])
AC_DEFUN([MD_CURL_CA_CHECK],
[AC_CACHE_CHECK(
 [for Curls default trusted CA certificate locations],
 [md_cv_curl_ca_locations],[dnl
 AC_RUN_IFELSE([dnl
        AC_LANG_PROGRAM(
                [[#include <ctype.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_GETHOSTNAME
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#elif defined HAVE_WINSOCK2_H
#include <Winock2.h>
#endif
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif
#endif
#include <curl/curl.h>
static char *urls[] = {
    NULL, NULL,
    "https://localhost/",
    "https://127.0.0.1/",
    "https://[::1]/",
    "https://letsencrypt.org/",
    "https://www.google.com/",
};
static struct {
    const char *const key;
    const char *varname;
    const char *value;
} wanted[] = {
    {
        "CAfile",
        "MD_TRUSTEDCAFILE",
        NULL,
    }, {
        "CApath",
        "MD_TRUSTEDCAPATH",
        NULL,
    },
};
static
int done(void) {
    size_t i, n = 0;
    for( i = 0; i < sizeof(wanted)/sizeof(wanted[0]); ++i ) {
        if( wanted[i].value ) ++n;
    }
    return n >= 1;
}
static char *buf = NULL;
static size_t bufsize = 0;
static
int addtxt(CURL *handle, curl_infotype type,
            char *data, size_t size,
            void *userp) {
    char *p;
    (void)handle;
    (void)userp;
    if( type != CURLINFO_TEXT || size == 0 ) return CURLE_OK;
    p = realloc( buf, bufsize + size +1 );
    if( !p ) {
        printf( "Out of memory!\n" );
        exit(1);
    }
    buf = p;
    memcpy( p + bufsize, data, size );
    bufsize += size;
    return CURLE_OK;
}
static void scantext( char *buf, size_t size ) {
    char *p;
    ptrdiff_t len, llen = 1;
    size_t i;
    buf[size] = '\0';
    for( ;size; buf += llen, size -= llen) {
        p = strchr( buf, '\n' );
        if( !p ) p = buf +size;
        *p++ = '\0';
        for( ; size; --size, ++buf ) {
            if( !isspace( *buf ) ) break;
        }
        llen = p - buf;
        p = strchr( buf, ':' );
        if( !p ) continue;
        *p++ = '\0';
        while( *p && isspace(*p) ) {
            ++p;
        }
        if( !strcmp( p, "none" ) ) continue;
        for( i = 0; i < sizeof(wanted)/sizeof(wanted[0]); i++ ) {
            if( strcmp( wanted[i].key, buf ) ) continue;
            if( (len = llen - (p - buf)) && !wanted[i].value ) {
                char *ip;
                ip = malloc( len +1 );
                if( !ip ) {
                    printf( "Out of memory!\n" );
                    exit(1);
                }
                memcpy( ip, p, len );
                ip[len] = '\0';
                wanted[i].value = ip;
            }
            break;
        }
    }
    return;
}
static
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)ptr;
    (void)nmemb;
    (void)userdata;
    return nmemb * size;
}
]],[[    CURL *curl;
    size_t u;
    struct { /* Ver 6 of curl_version_info_data */
      CURLversion age;
      const char *version;
      unsigned int version_num;
      const char *host;
      int features;
      const char *ssl_version;
      long ssl_version_num;
      const char *libz_version;
      const char * const *protocols;
      const char *ares;
      int ares_num;
      const char *libidn;
      int iconv_ver_num;
      const char *libssh_version;
      unsigned int brotli_ver_num;
      const char *brotli_version;
      unsigned int nghttp2_ver_num;
      const char *nghttp2_version;
      const char *quic_version;
      const char *cainfo;
      const char *capath;
    } *curlvi;
    curl = curl_easy_init();
    if(!curl) exit(1);
    curlvi = curl_version_info( CURLVERSION_NOW );
    if( curlvi && curlvi->age >= 6 ) {
        wanted[0].value = curlvi->cainfo;
        wanted[1].value = curlvi->capath;
    } else {
#ifdef HAVE_GETHOSTNAME
#define H_OFS sizeof("https://")
#define W_OFS sizeof("https://www.")
        char hostname[W_OFS+HOST_NAME_MAX+1+1] = { "https://www." };
        if( !gethostname( hostname+W_OFS, HOST_NAME_MAX ) ) {
            hostname[sizeof(hostname)-1]='\0';
            urls[0] = malloc( strlen( hostname ) + 1 );
            if( urls[0] ) strcpy( urls[0], hostname );
            memmove( hostname+H_OFS, hostname+W_OFS, strlen(hostname+W_OFS)+1 );
            urls[1] = malloc( strlen( hostname ) + 1 );
            if( urls[1] ) strcpy( urls[1], hostname );
        }
#endif
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, addtxt);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        for( u = 0; u < sizeof(urls)/sizeof(urls[0]); ++u ) {
            if( !urls[u] ) continue;
            curl_easy_setopt(curl, CURLOPT_URL, urls[u]);
            (void) curl_easy_perform(curl);
            scantext( buf, bufsize );
            free( buf );
            buf = NULL;
            bufsize = 0;
            if( done() ) break;
        }
    }
    for( u = 0; u < sizeof(wanted)/sizeof(wanted[0]); ++u ) {
        fprintf( stderr, "%s%s=", (u?" ":""), wanted[u].varname );
        if( wanted[u].value ) {
            fprintf( stderr, "\"\\\\\"%s\\\\\"\"", wanted[u].value );
        } else {
            fprintf( stderr, "NULL" );
        }
    }
    curl_easy_cleanup(curl);
    exit( !done() );
]])],
        [md_cv_curl_ca_locations=$(./conftest$EXEEXT 2>&1)],
        [AC_MSG_ERROR(Failed to compile or run curl CA locations test program!?)],
        [AC_MSG_WARN(Unable to probe libcurl for CA locations when cross-compiling.  Set MD_TRUSTEDCAPATH and MDTRUSTEDCAFILE in CPPFLAGS, or the md_cv_curl_ca_locations cache variable.)])
])
eval "$md_cv_curl_ca_locations"
AC_SUBST(MD_TRUSTEDCAFILE)
AC_SUBST(MD_TRUSTEDCAPATH)
m4_pattern_allow(MD_TRUSTEDCAFILE)
m4_pattern_allow(MD_TRUSTEDCAPATH)
])
MD_CURL_CA_CHECK

if test x"$request_openssl" = "xcheck"; then
    OPENSSL_BIN="${prefix}/bin/openssl"
    if test -x "$OPENSSL_BIN"; then
        : # all fine
    else
        OPENSSL_BIN=openssl
        AC_CHECK_PROG([FOUND_OPENSS_BIN],[$OPENSSL_BIN],[yes],[no])
    fi
else
    OPENSSL_BIN="$request_openssl/bin/openssl"
    LDFLAGS="$LDFLAGS -L$request_openssl/lib";
    CFLAGS="$CFLAGS -I$request_openssl/include";
    CPPFLAGS="$CPPFLAGS -I$request_openssl/include";
fi
AM_CONDITIONAL([FOUND_OPENSSL_BIN], [test "x$FOUND_OPENSSL_BIN" != xno])
AM_COND_IF([FOUND_OPENSSL_BIN],,[AC_MSG_ERROR([required program 'openssl' not found.])])
AC_SUBST(OPENSSL_BIN)

# Should we build unit tests?
have_check=false

if test "x$enable_unit_tests" != "xno"; then
    # The Check library is needed for C-based unit tests. Only pkg-config
    # discovery is supported for it at the moment.
    AC_MSG_CHECKING([for Check to enable unit tests])

    if test "x$PKGCONFIG" != "x" && $PKGCONFIG --atleast-version='0.9.12' check; then
        CHECK_CFLAGS=`$PKGCONFIG --cflags check`
        CHECK_LIBS=`$PKGCONFIG --libs check`

        AC_SUBST(CHECK_CFLAGS)
        AC_SUBST(CHECK_LIBS)

        have_check=true
        AC_MSG_RESULT([yes])
    else
        AC_MSG_RESULT([no])
    fi
fi

AC_PATH_PROG([XMLTO], [xmlto])
AM_CONDITIONAL([BUILD_MANPAGES], [test "x$XMLTO" != "x"])

AM_CONDITIONAL([BUILD_UNIT_TESTS], [test "x$have_check" = "xtrue"])

# Checks for header files.
AC_CHECK_HEADERS([ \
    assert.h \
    stddef.h \
])

# we'd like to use this, if it exists
AC_CHECK_FUNC(arc4random_buf, [CFLAGS="$CFLAGS -DMD_HAVE_ARC4RANDOM"], [])


# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memmove memset strcasecmp strchr])

AC_CHECK_PROG([A2ENMOD],[a2enmod])

# substitution in generated files
AC_SUBST(PREFIX)
AC_SUBST(BUILD_SUBDIRS)
AC_SUBST(SYSCONF_DIR)
AC_SUBST(LIBEXEC_DIR)

AC_CONFIG_FILES([
    Makefile
    src/md_version.h
    src/Makefile
    test/Makefile
    test/conf/proxy.conf
    test/conf/httpd.conf
    test/conf/modules.conf
    test/conf/std_vhosts.conf
    test/test.ini
])

AC_OUTPUT

## Determine the compiler's vendor.

COMPILER_VERSION=`"$CC" --version | head -n1 2>/dev/null`

## IBM xlC test if COMPILER_VERSION is empty
if test x"$COMPILER_VERSION" = "x"; then
   COMPILER_VERSION=`"$CC" -qversion | head -n1 2>/dev/null`
fi

## SunCC test if COMPILER_VERSION is empty
if test x"$COMPILER_VERSION" = "x"; then
   COMPILER_VERSION=`"$CC" -V | had -n1 2>&1`
fi

if test x"$COMPILER_VERSION" != "x"; then
   COMPILER_VERSION="=> $COMPILER_VERSION"
fi

AC_MSG_NOTICE([summary of build options:

    Version:        ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
    Host type:      ${host}
    Install prefix: ${prefix}
    APXS:           ${APXS}
    HTTPD-VERSION:  ${HTTPD_VERSION}
    C compiler:     ${CC} ${COMPILER_VERSION}
    CFLAGS:         ${CFLAGS}
    WARNCFLAGS:     ${WERROR_CFLAGS}
    LDFLAGS:        ${LDFLAGS}
    LIBS:           ${LIBS}
    CPPFLAGS:       ${CPPFLAGS}
    curl            ${CURL_BIN:--}
    curl-config     ${curl_config:--}
    Trusted CA file ${MD_TRUSTEDCAFILE}
    Trusted CA path ${MD_TRUSTEDCAPATH}
    jansson         ${JANSSON_PREFIX:--}
    openssl         ${OPENSSL_BIN:--}
    default ACME CA ${ACME_DEF_CA_NAME} (${ACME_DEF_URL})
    boulder         ${BOULDER_DIR} (${BOULDER_URL})
    jQuery          $jq_url
    jQueryUI        $jqui_url
    jQueryUI Theme  $jquicss_url
])
