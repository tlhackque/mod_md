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

#include <ctype.h>
#include <stddef.h>

#include <apr_optional.h>
#include <apr_time.h>
#include <apr_date.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include "md_json.h"

#include "md.h"
#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_crypt.h"
#include "md_git_version.h"
#include "md_http.h"
#include "md_reg.h"
#include "md_status.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_util.h"

#include "mod_md_config.h"
#include "mod_md_private.h"
#include "mod_md_status.h"
#include "mod_md_manage.h"
#include "mod_md_manage_server.h"
#include "mod_md_manage_data.h"
#include "mod_md_dnsquery.h"
#include "mod_md_inspect.h"

#if 0
  #define MD_JSON_FMT_DEBUG MD_JSON_FMT_INDENT
#else
  #define MD_JSON_FMT_DEBUG MD_JSON_FMT_COMPACT
#endif

/* Management GUI */

typedef struct {
    apr_pool_t          *p;
    const md_mod_conf_t *mc;
    const md_srv_conf_t *sc;
    apr_bucket_brigade  *bb;
    const char          *separator;
    apr_array_header_t  *tt;
    md_store_t          *store;
    md_json_t           *resp;
} manage_ctx;

typedef struct {
    const char         *filter;
    apr_array_header_t *matched;
    long                nfound;
    long                limit;
} find_ctx_t;

static int md_manage_get( request_rec *r,  const md_mod_conf_t *mc, const md_srv_conf_t *sc );
static int md_manage_get_console( request_rec *r,  const md_mod_conf_t *mc, const md_srv_conf_t *sc );

static int md_manage_post( request_rec *r,  const md_mod_conf_t *mc, const md_srv_conf_t *sc );

#define XTRNL
#define POST_FUNCTIONS                                  \
    POSTFUNC(findnames,     static, find_names)         \
    POSTFUNC(certformdata,  static, get_domains)        \
    POSTFUNC(getcadir,      static, get_cadir)          \
    POSTFUNC(inspecthost,   XTRNL,  inspect_host)       \
    POSTFUNC(caarecs,       XTRNL,  caarecs)            \
    POSTFUNC(acctnewkey,    static, queue_function)     \
    POSTFUNC(acctdeactivate,static, queue_function)     \
    POSTFUNC(renew,         static, queue_function)     \
    POSTFUNC(revoke,        static, queue_function)     \
    POSTFUNC(acctimport,    static, queue_function)

#define POSTHANDLER(handler)                                            \
    int md_manage_##handler( md_json_t *resp, request_rec *r,           \
                                    const md_mod_conf_t *mc,            \
                                    const md_srv_conf_t *sc, md_json_t *pars )
#define POSTFUNC(function,locn, handler)        \
    locn md_postfcn_t md_manage_##handler;      \
    locn POSTHANDLER(handler);

POST_FUNCTIONS
#undef POSTFUNC

#define STUB_HANDLER                                                    \
    (void)mc; (void)sc; (void)pars;                                     \
    return md_json_resp(r, HTTP_NOT_FOUND, resp, "Not yet implemented" );

static int md_name_cmp(const void *v1, const void *v2);
static int add_md_mrow(void *baton, apr_size_t index, md_json_t *mdj);
static apr_status_t get_keys(void **ep, md_json_t *j, apr_pool_t *p, void *baton);
static int manage_display_key( void *baton, size_t index, md_json_t *key );
static apr_status_t md_manage_filter_match( void *value, void *baton );

/* Hook */

int md_manage_handler(request_rec *r)
{
    const md_srv_conf_t *sc;
    const md_mod_conf_t *mc;

    if (strcmp(r->handler, "md-manage")) return DECLINED;

    sc = ap_get_module_config(r->server->module_config, &md_module);
    if (!sc || !(mc = sc->mc)) return DECLINED;

    if (!mc->manage_gui_enabled) return HTTP_NOT_IMPLEMENTED;

    ap_allow_standard_methods(r, 1, M_GET, M_POST, -1);

    if( ap_some_auth_required(r) ) {
        if (r->method_number == M_POST) return md_manage_post(r, mc, sc);
        if (r->method_number == M_GET)  return md_manage_get(r, mc, sc);

        return HTTP_METHOD_NOT_ALLOWED;
    }
    ap_set_content_type(r, "text/html");
    r->status = 503;
    r->status_line = apr_pstrdup( r->pool, "503 Service Unavailable" );
    if( r->header_only ) return OK;

    ap_rprintf(r, "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
"<html><head>"
"<title>503 Service Unavailable</title>"
"</head><body>"
"<h1>Service Unavailable</h1>"
"<p>This URL is not configured with an authentication method, which "
"is required.  The site administrator should refer to the <I>mod_md</I> "
"documentation.</p>"
"<hr>"
"<address>%s Server at %s Port %d, %s</address>"
"</body></html>",ap_get_server_banner(), ap_get_server_name(r),
               ap_get_server_port(r), r->server->server_admin);
    return OK;
}

static int md_manage_get( request_rec *r,  const md_mod_conf_t *mc, const md_srv_conf_t *sc )
{
    if (r->path_info && r->path_info[0] && (r->path_info[0] != '/' || r->path_info[1]))
        return md_manage_get_data(r, mc, sc);

    return md_manage_get_console( r, mc, sc );
}

static int md_manage_get_console( request_rec *r,  const md_mod_conf_t *mc, const md_srv_conf_t *sc )
{
    apr_bucket_brigade  *bb;
    const char          *a;
    ap_version_t         server_version;

    (void)sc;

    ap_set_content_type( r, "text/html");
    r->no_cache = 1;
    apr_table_set(r->headers_out, "Cache-Control", "no-cache no-store");

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    a = ap_auth_type(r);
    ap_get_server_revision(&server_version);
    apr_brigade_puts(bb, NULL, NULL,
                     "<!DOCTYPE html>"
                     "<html><head><title>Managed domain administration</title>");
    apr_brigade_printf(bb, NULL, NULL, 
                       "<link rel=\"stylesheet\" type=\"text/css\" href=\"%s\">",
                       ap_escape_quotes(r->pool, MD_JQUERYUI_CSS_URL));
    if(mc->manage_gui_stylesheet && mc->manage_gui_stylesheet[0]) {
        apr_brigade_printf(bb, NULL, NULL, 
                       "<link rel=\"stylesheet\" type=\"text/css\" href=\"%s\">",
                           ap_escape_quotes(r->pool, mc->manage_gui_stylesheet) );
    } else {
        apr_brigade_printf(bb, NULL, NULL, 
                       "<link rel=\"stylesheet\" type=\"text/css\" href=\"%s/css\">",
                           ap_escape_quotes(r->pool, r->parsed_uri.path) );
    }
    apr_brigade_printf(bb, NULL, NULL, 
                       "<script src=\"%s\"></SCRIPT>"
                       "<script src=\"%s\"></SCRIPT>"
                       "<script src=\"%s/js\"></script>",
                       ap_escape_quotes(r->pool, MD_JQUERY_URL),
                       ap_escape_quotes(r->pool, MD_JQUERYUI_URL),
                       ap_escape_quotes(r->pool, r->parsed_uri.path));
    apr_brigade_puts(bb, NULL, NULL,
                        "</head><body><div class=\"pagewrapper\">"
                        "<div class=\"pageheader\">");
    if( mc->manage_gui_logo && mc->manage_gui_logo[0] ) {
        apr_brigade_printf(bb, NULL, NULL,
                           "<img src=\"%s\" class=\"logo\">",
                           ap_escape_quotes(r->pool, mc->manage_gui_logo));
    } else {
        apr_brigade_printf(bb, NULL, NULL,
                           "<img src=\"%s/logo\" class=\"logo\">",
                           ap_escape_quotes(r->pool, r->parsed_uri.path) );
    }
    apr_brigade_printf(bb, NULL, NULL,
                       "<div class=\"headertext\"><h1>Managed domain administration</h1>"
                       "<p>Apache server %d.%d.%d%s with mod_md ",
                       server_version.major, server_version.minor, server_version.patch,
                       (server_version.add_string?server_version.add_string:""));
#ifdef MD_GIT_VERSION
    apr_brigade_puts(bb, NULL, NULL, MD_GIT_VERSION);
#else
    apr_brigade_printf(bb, NULL, NULL,"%u.%u.%u",
                       ((unsigned)MOD_MD_VERSION_NUM >> 16),
                       ((unsigned)MOD_MD_VERSION_NUM >> 8) & 0xFF,
                       ((unsigned)MOD_MD_VERSION_NUM & 0xFF));
#endif
    apr_brigade_printf(bb, NULL, NULL, " on %s (%s)<br>Logged-in as %s from %s with %s authentication",
                       ap_get_local_host(r->pool), r->connection->local_ip,
                       r->user? r->user : "Unknown",
                       ap_get_useragent_host(r, REMOTE_NAME, NULL), a? a : "Unknown");
    apr_brigade_puts(bb, NULL, NULL,
                     "</p><button id=\"clearmsg\" class=\"messages hidden\">clear messages</buttom></div>"
                     "<div id=\"messages\" class=\"messages hidden\">&nbsp;</div></div>"
                     "<div class=\"pagebody\">"
                     "<form method=\"post\" id=\"certform\"><input type=\"hidden\" name=\"function\">"
                     "<table class=\"crtlist\">"
                     "<thead><tr><th><label for=\"selectall\"></label><input type=\"checkbox\" id=\"selectall\" "
                     "name=\"selectall\" value=\"1\"></th>"
                     "<th>Certificate</th><th>Names</th><th>Keys</th><th>Status</th><th>Validity period</th>"
                     "<th>CA</th><th>Activity</th></tr></thead>"
                     "<tbody id=\"domains\">"
                     "<noscript><tr><td colspan=\"99\" class=\"noscript\">This page requires javascript</noscript></td></tr>"
                     "<tr><td colspan=\"99\" class=\"comfort\">Retrieving data&hellip;</td></tr>" /* Note: keep synched with JS */
                     "</tbody>"
                     "<tfoot><tr><td colspan=\"99\" class=\"certend\"><table class=\"actions\"><tbody>"
                     "<tr class=\"pagenav\"><td>Display</td>"
                     "<td><input type=\"text\" name=\"filter\" size=\"32\""
                     " maxlength=\"255\" id=\"namefilter\" placeholder=\"Find/select domain or SAN\"></td>"
                     "<td id=\"pagelist\" class=\"pages\"></td>"
                     "<td class=\"pagelimit\">Domains per page<select name=\"pagelimit\">"
#if 0
                     "<option value=\"1\">1</option>"
#endif
                     "<option value=\"5\">5</option>"
                     "<option value=\"10\" selected=\"selected\">10</option>"
                     "<option value=\"25\">25</option>"
                     "<option value=\"50\">50</option>"
                     "</select></td></tr>"
                     "<tr><td>Certificate actions</td>"
                     "<td><button type=\"button\" name=\"renew\">Renew now</button></td>"
                     "<td><button type=\"button\" name=\"revoke\">Revoke</button></td></tr>"
                     "<tr><td>Account actions"
                     "<td><button type=\"button\" name=\"acctimport\">Import account</button></td></tr>"
                     "</tbody></table></tfoot></table>"
                     "</form></div>"
                     "<div id=\"domaindialogs\"></div>"
                     "</div></body></html>");
    ap_pass_brigade(r->output_filters,bb);
    apr_brigade_destroy(bb);

    return OK;
}

/* POST dispatch and handlers */

typedef struct {
    const char *const function;
    md_postfcn_t *const handler;
} md_posthandler_t;

#define POSTFUNC(function,locn, handler)        \
    { #function, md_manage_##handler },

static md_posthandler_t md_posthandlers[] = {
    POST_FUNCTIONS
};
#undef POSTFUNC

static int md_manage_post( request_rec *r,  const md_mod_conf_t *mc, const md_srv_conf_t *sc )
{
    int rv;
    const char *s;
    md_json_t *req = NULL, *resp = NULL;

    (void)mc; (void)sc;

    ap_set_content_type( r, "application/json");
    r->no_cache = 1;
    apr_table_set(r->headers_out, "Cache-Control", "no-cache no-store");

    resp = md_json_create(r->pool);

    if (r->path_info && r->path_info[0] && (r->path_info[0] != '/' || r->path_info[1]))
        return md_json_resp( r, HTTP_NOT_FOUND, resp, "Invalid path_info" );

    s = apr_table_get(r->headers_in, "Content-Type");
    if (s && !strncasecmp("application/json", s, 16)) {
        apr_bucket_brigade *bb = NULL;
        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        if( APR_SUCCESS != (rv = ap_get_brigade( r->input_filters, bb,
                                                 AP_MODE_READBYTES,
                                                 APR_BLOCK_READ,
                                                 HUGE_STRING_LEN)) ) {
            apr_brigade_destroy(bb);
            return md_json_resp( r,(rv == AP_FILTER_ERROR) ? rv : HTTP_BAD_REQUEST,
                                 resp, NULL );
        }
        if( APR_SUCCESS != (rv = md_json_readb(&req, r->pool, bb)) ) {
             apr_brigade_destroy(bb);
             return md_json_resp( r, rv, resp, NULL );
        }
    } else {
        ap_discard_request_body(r);
        return HTTP_BAD_REQUEST;
    }

    s = md_json_gets(req, "function", NULL);
    if( s ) {
        md_posthandler_t *ph;

        for (rv = 0, ph = md_posthandlers;
             rv < (int)(sizeof(md_posthandlers)/sizeof(md_posthandlers[0]));
             ++rv, ++ph ) {
            if( !strcmp( s, ph->function ) )
                return ph->handler( resp, r, mc, sc, req );
        }
    }
    return md_json_resp( r, HTTP_BAD_REQUEST, resp,
                         apr_pstrcat(r->pool, "Invalid function:",
                                     s? s: "unspecified", NULL) );
}

POSTHANDLER(get_domains)
{
    apr_array_header_t *mds, *sel;
    char *s; apr_off_t len;
    apr_status_t rv;
    manage_ctx ctx;
    find_ctx_t find;
    long start, count, i, j;

    /* Generate the table rows for each configured domain.
     * Both initial population and updates/selections.
     */

    ctx.p = r->pool;
    ctx.mc = mc;
    ctx.sc = sc;
    ctx.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    ctx.tt = apr_array_make(r->pool, 25, sizeof(const char *));
    ctx.separator = " ";
    ctx.store = md_reg_store_get(mc->reg);

#define WT APR_ARRAY_PUSH(ctx.tt, const char *) =

    md_json_setl(mc->mds->nelts, resp, "paging", "total", NULL );

    mds = apr_array_copy(r->pool, mc->mds);
    qsort(mds->elts, (size_t)mds->nelts, sizeof(md_t *), md_name_cmp);

    start = md_json_is( MD_JSON_TYPE_INT, pars, "paging", "start", NULL )?
        md_json_getl( pars, "paging", "start", NULL ) -1 : 0;

    count = md_json_is( MD_JSON_TYPE_INT, pars, "paging", "count", NULL )?
        md_json_getl( pars, "paging", "count", NULL ) : mds->nelts;

    if( start < 0 ) start = 0;
    if( count < 1 ) count = 1;

    find.matched = NULL;
    find.nfound  = 0;
    find.limit   = 0;
    find.filter  =  md_json_is( MD_JSON_TYPE_STRING, pars, "paging", "filter", NULL )?
        md_json_gets(pars, "paging", "filter", NULL ) : NULL;

    sel = apr_array_make(r->pool, mds->nelts, sizeof(const md_t *));

    if( !find.filter || !find.filter[0]) {
        if( start >= mds->nelts ) start = mds->nelts -1;
        if( start + count > mds->nelts ) count = mds->nelts - start;

        md_json_setl(mds->nelts, resp, "paging", "total", NULL );

        for( i = 0; i < count; i++ ) {
            APR_ARRAY_PUSH(sel, md_t *) = APR_ARRAY_IDX(mds, start+i, md_t *);
        }
    } else {
        for( i = 0; i < mds->nelts; ++i ) {
            md_t *md;

            md = (md_t *)APR_ARRAY_IDX(mds, i, md_t *);
            if( APR_SUCCESS == md_manage_filter_match( (void *)md->name, &find ) ) {
                if( find.nfound > start && sel->nelts < count ) {
                    APR_ARRAY_PUSH(sel, md_t *) = md;
                }
                continue;
            }
            for( j = 0; j < md->domains->nelts; ++j ) {
                const char *san = (const char *)APR_ARRAY_IDX(md->domains, j, const char *);

                if( APR_SUCCESS == (rv = md_manage_filter_match( (void *)san, &find )) ) {
                    if( find.nfound > start && sel->nelts < count ) {
                        APR_ARRAY_PUSH(sel, md_t *) = md;
                    }
                    break;
                }
            }
        }

        if( start >= sel->nelts ) start = sel->nelts -1;
        md_json_setb( start + count < find.nfound,
                      resp, "paging", "limited", NULL );

        if( start + count > sel->nelts ) count = sel->nelts - start;
        md_json_setl(find.nfound, resp, "paging", "total", NULL);
        md_json_setl(find.nfound, resp, "paging", "matches", NULL);
    }

    if( sel->nelts <= 0 ) {
        apr_brigade_printf(ctx.bb, NULL, NULL, "<tr><td>&nbsp;<td colspan=\"99\" class=\"nocerts\">"
                             "No managed domains %s",
                             mc->mds->nelts <= 0? "are configured" : "selected");
        md_json_setl(1, resp, "paging", "start", NULL);
        md_json_setl(0, resp, "paging", "count", NULL);
    } else {
        md_json_t *jstatus = NULL;

        md_json_setl(start+1, resp, "paging", "start", NULL );
        md_json_setl(count,   resp, "paging", "count", NULL );

        md_status_get_json(&jstatus, sel, mc->reg, mc->ocsp, r->pool);
        md_json_itera(add_md_mrow, &ctx, jstatus, MD_KEY_MDS, NULL);
    }

    apr_brigade_length( ctx.bb, 1, &len );
    s = apr_palloc(r->pool, (apr_size_t)len + 1);
    if (APR_SUCCESS == (rv = apr_brigade_flatten(ctx.bb, s, (apr_size_t*)&len))) {
        s[len] = '\0';
        md_json_sets(s, resp, "domainrows", NULL);
    } else {
        char buffer[HUGE_STRING_LEN];
        apr_strerror(rv, buffer, sizeof(buffer));
        md_json_sets(buffer, resp, "message", NULL);
    }
    if( ctx.tt->nelts ) {
        md_json_sets(apr_array_pstrcat(r->pool, ctx.tt, '\0'), resp,
                     "domaindialogs", NULL);
    }
#undef WT
    apr_brigade_destroy(ctx.bb);
    return md_json_resp(r, OK, resp, NULL);
}

static int md_name_cmp(const void *v1, const void *v2)
{
    return strcmp((*(const md_t**)v1)->name, (*(const md_t**)v2)->name);
}

static int add_md_mrow(void *baton, apr_size_t index, md_json_t *mdj)
{
    manage_ctx *ctx = (manage_ctx *)baton;
    const char *s, *u, *domain, *qdomain;
    md_timeslice_t *renew_window, *warn_window;
    apr_time_t until;
    md_json_t *j, *k;
    int acct_haskey = 0, acct_valid = 0;

    if( !mdj ) return 1;

#define WT APR_ARRAY_PUSH(ctx->tt, const char *) =

    md_config_get_timespan(&warn_window, ctx->sc, MD_CONFIG_WARN_WINDOW);
    md_config_get_timespan(&renew_window, ctx->sc, MD_CONFIG_RENEW_WINDOW);

    apr_brigade_puts(ctx->bb, NULL, NULL, "<tr class=\"domain\"><td>");

    domain= md_json_gets(md_json_getj(mdj, MD_KEY_NAME, NULL),NULL);
    qdomain = ap_escape_quotes(ctx->p, domain );
    apr_brigade_printf(ctx->bb, NULL, NULL,
                       "<label for=\"select%lu\"></label>"
                       "<input type=\"checkbox\" id=\"select%"APR_SIZE_T_FMT"\" name=\"select\" value=\"%s\">"
                       "<td>",
                       index, index, qdomain );

    j = md_json_getj(mdj, MD_KEY_DOMAINS, NULL);
    if( j ) {
        apr_array_header_t *dl;
        int i;

        dl =  apr_array_make(ctx->p, 5,  sizeof(void *));
        (void) md_json_getsa(dl,j,NULL);

        apr_brigade_printf(ctx->bb, NULL, NULL,
                           "<a class=\"popclick\" popup=\"#pop%"APR_SIZE_T_FMT"\" title=\"Click to inspect.\">%s</a>",
                           index, qdomain);
        WT apr_psprintf(ctx->p,
                        "<div id=\"pop%"APR_SIZE_T_FMT"\" title=\"%s\" class=\"popup hostselect\">"
                        "<form id=\"inspecthost%"APR_SIZE_T_FMT"\" class=\"inspecthost\"><input type=\"hidden\" name=\"host\">"
                        "<input type=\"hidden\" name=\"function\" id=\"function\" value=\"inspecthost\">"
                        "<div class=\"inspectoptions\">Certificate covers the hosts listed below."
                        "<p>Select one or more ports, then click a name to inspect installed certificate(s).<br>"
                        "<select class=\"portsel\" name=\"port\" multiple=\"multiple\" size=\"1\">"
                        "<Optgroup label=\"WWW\">"
                        "<option value=\"443\" selected=\"selected\">https</option>"
                        "<Optgroup label=\"E-mail\">"
                        "<option value=\"25\">smtp (starttls)</option>"
                        "<option value=\"587\">submit (starttls)</option>"
                        "<option value=\"465\">smtps</option>"
                        "<option value=\"143\">imap (starttls)</option>"
                        "<option value=\"993\">imaps</option>"
                        "<option value=\"110\">pop3 (starttls)</option>"
                        "<option value=\"995\">pop3s</option>"
                        "<option value=\"4190\">sieve (starttls)</option>"
                        "<Optgroup label=\"Files&amp;Printing\">"
                        "<option value=\"21\">ftp (starttls)</option>"
                        "<option value=\"990\">ftps</option>"
                        "<option value=\"3306\">mysql (starttls)</option>"
                        "<option value=\"5432\">postgres (starttls)</option>"
                        "<Optgroup label=\"Directory&amp;News\">"
                        "<option value=\"389\">ldap (starttls)</option>"
                        "<option value=\"636\">ldaps</option>"
                        "<option value=\"119\">NNTP (starttls)</option>"
                        "<option value=\"563\">NNTP</option>"
                        "<option value=\"433\">NNSP (starttls)</option>"
                        "<Optgroup label=\"Chat&amp;Misc\">"
                        "<option value=\"194\">irc (starttls)</option>"
                        "<option value=\"23\">telnet (starttls)</option>"
                        "<option value=\"5222\">xmpp (starttls)</option>"
                        "<option value=\"5269\">xmpp server (starttls)</option>"
                        "</select>" /* Floats reverse select and label */
                        "<span class=\"label\">Port(s) to inspect: <span "
                        "class=\"portsel-open ui-icon ui-icon-triangle-1-e\" "
                        "title=\"Click to open or close selection box\"></span></span>"
                        "<br>Selected: <span class=\"selected\">443</span>"
                        "</div><div class=\"hosts\"><ul class=\"horiz\">",
                        index, qdomain, index );
        /* "<option value=\"631\">ipps</option>"
         * TODO Send OPTIONS * w/host, upgrade: TLS/1.0 connection:upgrade => 101 switching ... eoh
         */

        for( i = 0; i < dl->nelts; i++ ) {
            const char *name;
            name = ap_escape_quotes(ctx->p, APR_ARRAY_IDX(dl,i,void *));
            WT apr_psprintf(ctx->p, "<li><button type=\"button\" class=\"host\" value=\"%s\" title=\"%s\">%s</button></li>",
                            name, name, name);
        }
        WT apr_psprintf(ctx->p, "</ul></div><div id=\"hostlist%"APR_SIZE_T_FMT"\" class=\"hostlist hidden\"><ul class=\"horiz hostlist\">", index);
        for( i = 0; i < dl->nelts; i++ ) {
            WT apr_psprintf(ctx->p, "<li>%s</li>", (const char *)APR_ARRAY_IDX(dl,i,void *));
        }
        WT "</ul></div>";
        apr_brigade_printf(ctx->bb, NULL, NULL, "<td class=\"dnames\" hostlist=\"#hostlist%"APR_SIZE_T_FMT"\">%d</td>", index, dl->nelts );
        apr_array_clear(dl);
        (void) md_json_geta(dl, get_keys, (void *)ctx, mdj, MD_KEY_PKEY, NULL);

        for( i = 0; i < dl->nelts; ++i ) {
            WT apr_psprintf( ctx->p,  "<input type=\"hidden\" name=\"keytype\" value=\"%s\">",
                             APR_ARRAY_IDX(dl, i, const char * ) );
        }

        WT "</form></div>";
    } else {
        apr_brigade_puts(ctx->bb, NULL, NULL, "<td class=\"dnames\">Unknown</td>");
    }
    
    apr_brigade_puts(ctx->bb, NULL, NULL, "<td class=\"dkeys\">");
    ctx->separator = "<br>";
    md_json_itera( manage_display_key, (void *)ctx, md_json_getj(mdj, MD_KEY_PKEY, NULL),NULL);
 
    apr_brigade_puts(ctx->bb, NULL, NULL, "</td><td class=\"dstatus\">");

    s = "unknown";
    switch( md_json_getl(mdj, MD_KEY_STATE, NULL) ) {
    case MD_S_INCOMPLETE:
        s = "incomplete";
        break;
    case MD_S_EXPIRED_DEPRECATED:
    case MD_S_COMPLETE:
        until = md_json_get_time(mdj, MD_KEY_CERT, MD_KEY_VALID, MD_KEY_UNTIL, NULL);
        s = (!until || until > apr_time_now())? "good" : "expired"; 
        break;
    case MD_S_ERROR:
        s = "error";
        break;
    case MD_S_MISSING_INFORMATION:
        s = "missing information";
        break;
    default:
        break;
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, s);

    apr_brigade_puts(ctx->bb, NULL, NULL, "</td><td class=\"dvalid\">");
    if( (j = md_json_getj(mdj, MD_KEY_CERT, MD_KEY_VALID, NULL)) != NULL ) {
        const char *vt, *xt;
        vt = md_json_gets(j, MD_KEY_FROM, NULL);
        xt = md_json_gets(j, MD_KEY_UNTIL, NULL);
        apr_brigade_printf( ctx->bb, NULL, NULL, "%s<br>%s</td>", vt, xt );
    } else {
        apr_brigade_puts( ctx->bb, NULL, NULL, "<span class=\"nodates\">&mdash;</span></td>" );
    }

    if( (j = md_json_getj(mdj, MD_KEY_CA, NULL)) != NULL &&
        (u = md_json_gets(j, MD_KEY_URL, NULL))  != NULL ) {
        const char *acct, *caref = NULL;
        apr_status_t rv = 0;
        static const char dtfmt[] = { "%a, %d-%b-%Y %H:%M:%S" };
        apr_time_exp_t tm;
        char acct_mtime[64+1] = { "" };
        apr_size_t rs;
        const char *acct_loc = NULL;

        s = apr_table_get( ctx->mc->ca_names, u );
        if( !s ) s = u;

        if( (acct = md_json_gets(j, MD_KEY_ACCOUNT, NULL)) == NULL ) {
            acct = "";
        } 

        caref = apr_psprintf( ctx->p, "pop%"APR_SIZE_T_FMT, index+1000000 );

        apr_brigade_printf(ctx->bb, NULL, NULL,
                           "<td class=\"dca\">"
                           "<a class=\"popclick\" popup=\"#%s\" domain=\"%s\" "
                           "title=\"Click for CA and account information.\">%s</a></td>",
                           caref, qdomain, s);
        WT apr_psprintf(ctx->p,
                        "<div id=\"%s\" title=\"%s\" class=\"popup cainfo\">",
                        caref, ap_escape_quotes(ctx->p, s));

        if( APR_SUCCESS == (rv = md_store_load_json(ctx->store, MD_SG_STAGING, domain,
                                                    MD_FN_ACCOUNT, &j, ctx->p)) ) {
            if( APR_SUCCESS ==
                (rv = apr_time_exp_lt( &tm,
                                       md_store_get_modified(ctx->store, MD_SG_STAGING,
                                                             domain, MD_FN_ACCOUNT, ctx->p) )) &&
                APR_SUCCESS == (rv = apr_strftime( acct_mtime, &rs, sizeof(acct_mtime),
                                                   dtfmt, &tm )) &&
                rs < sizeof(acct_mtime) ) {
                acct_mtime[rs] = '\0';
            } else {
                acct_mtime[0] = '\0';
            }
            acct_loc = "staged";
        } else {
            if( acct[0] && APR_STATUS_IS_ENOENT(rv) ) {
                if( APR_SUCCESS == (rv = md_store_load_json(ctx->store, MD_SG_ACCOUNTS,
                                                            acct, MD_FN_ACCOUNT, &j, ctx->p)) ) {
                    if( APR_SUCCESS ==
                        (rv = apr_time_exp_lt( &tm,
                                               md_store_get_modified(ctx->store, MD_SG_ACCOUNTS,
                                                                     acct, MD_FN_ACCOUNT, ctx->p) )) &&
                        APR_SUCCESS == (rv = apr_strftime( acct_mtime, &rs, sizeof(acct_mtime),
                                                           dtfmt, &tm )) &&
                        rs < sizeof(acct_mtime) ) {
                        acct_mtime[rs] = '\0';
                    } else {
                        acct_mtime[0] = '\0';
                    }
                    acct_loc = "finalized";
                } else {
                    j = NULL;
                }
            } else {
                j = NULL;
            }
        }

        u = ap_escape_quotes(ctx->p, u);
        WT apr_psprintf(ctx->p,
                        "Account information"
                        "<form method=\"post\" id=\"acctform\">"
                        "<input type=\"hidden\" name=\"function\">"
                        "<input type=\"hidden\" name=\"domain\" value=\"%s\">"
                        "<input type=\"hidden\" name=\"ca\" value=\"%s\">"
                        "<table class=\"accountinfo\"><tbody>"
                        "<tr><td>Domain<td class=\"domain\">%s</td></tr>"
                        "<tr><td>Certificate Authority</td><td class=\"cainfo\" "
                        "calink=\"%s\" title=\"Click for CA information, including CAA support\">%s"
                        "</td><tr><td>Account</td><td>",
                        qdomain, u, domain, u, s);
        if( j ) {
            apr_array_header_t *ac;
            int i;

            ac = apr_array_make(ctx->p, 10, sizeof(const char *));
            if( (u = md_json_gets(j, "url", NULL)) ) {
                apr_uri_t uparsed;
                if(APR_SUCCESS == apr_uri_parse(ctx->p, u, &uparsed)) {
                    u = uparsed.path;
                }
                WT apr_psprintf(ctx->p, "%s (%s)",
                                u, (acct_loc? acct_loc : "not found"));
            } else {
                WT apr_psprintf(ctx->p, "%s", acct[0]? acct: "None");

            }
            u = md_json_gets(j, "status", NULL);
            WT apr_psprintf(ctx->p, "</td></tr><tr><td>Account status</td><td>%s</td></tr>", u? u : "unknown");
            if( acct_mtime[0] ) {
                WT apr_psprintf(ctx->p, "<tr><td>Last modified</td><td>%s</td></tr>", acct_mtime);
            }
            if( (k = md_json_getj(j, "registration", "contact", NULL)) ) {
                md_json_getsa(ac, k, NULL);
            }
            switch( ac->nelts ) {
            case 0:
                WT "<tr><td>Contact</td><td>None registered</td></tr>";
                break;
            case 1:
                WT apr_psprintf(ctx->p, "<tr><td>Contact</td><td>%s</td></tr>", APR_ARRAY_IDX(ac, 0, const char *));
                break;
            default:
                WT apr_psprintf(ctx->p, "<tr><td>Contacts</td><td>%s</td></tr>", apr_array_pstrcat(ctx->p, ac, ','));
                break;
            }
            apr_array_clear(ac);
            if( (u = md_json_gets(j, "registration", "status", NULL )) ) {
                WT apr_psprintf(ctx->p, "<tr><td>Registration</td><td>%s</td></tr>", u);
                if( !strcmp( u, "valid" ) ) acct_valid = 1;
            }
            if( (k = md_json_getj(j, "registration", "key", NULL)) &&
                (u = md_json_gets(k, "kty", NULL)) &&
                !strcmp( u, "RSA" ) &&
                (u = md_json_gets(k, "n", NULL))) {
                size_t klen;
                md_data_t key;
                char kx[(8*2)+1];

                klen = md_util_base64url_decode( &key, u, ctx->p);
                if( klen > 8 ) klen = 8;
                for( i = 0; i < (int)klen; i++ ) {
                    sprintf( kx+(2*i), "%02x", (uint8_t)key.data[i] );
                }
                WT apr_psprintf(ctx->p, "<tr><td>Public key tag</td><td>%s</td></tr>", kx);
            }
            if( k ) acct_haskey = 1;
        } else {
            if( acct_loc ) {
                WT acct_loc;
            } else {
                WT "None";
            }
        }
        WT "</tbody>";
        if( acct_valid || acct_haskey ) {
            WT "<tfoot><tr>";
            if( acct_haskey ) {
                WT "<td><button type=\"button\" name=\"acctnewkey\">Replace key</button></td>";
            } else {
                WT "<td>&nbsp;</td>";
            }
            if( acct_valid ) {
                WT "<td><button type=\"button\" name=\"acctdeactivate\">Deactivate account</button></td>";
            } else {
                WT "<td>&nbsp;";
            }
            WT "</tr></tfoot>";
        }
        WT "</table></form></div>";
    } else {
        s = "Unknown";
        u = NULL;
        apr_brigade_printf(ctx->bb, NULL, NULL, "<td class=\"dca\">%s</td>", s);
    }

    apr_brigade_puts(ctx->bb, NULL, NULL, "<td class=\"log");

    if (md_json_has_key(mdj, MD_KEY_RENEWAL, NULL)) {
        char buffer[HUGE_STRING_LEN];
        apr_status_t rv;
        int finished, errors;
        apr_time_t t;
        const char *summary = "", *detail = "", *classes = "";
    
        if (md_json_has_key(mdj, MD_KEY_RENEWAL, NULL)) {
            finished = (int)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_FINISHED, NULL);
            errors = (int)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_ERRORS, NULL);
            rv = (apr_status_t)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_STATUS, NULL);
    
            if (rv != APR_SUCCESS) {
                classes = " error";
                summary = apr_psprintf(ctx->p, "Error[%s]", 
                                    apr_strerror(rv, buffer, sizeof(buffer)));
                s = md_json_gets(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_PROBLEM, NULL);
                if( s ) detail = s;
            }
    
            if (finished) {
                summary = apr_pstrcat(ctx->p, summary,
                                      (summary[0]? "<br>":""),
                                      "finished successfully.", NULL );
            } else {
                s = md_json_gets(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_DETAIL, NULL);
                if (s) {
                    if( detail[0] ) {
                        detail = apr_pstrcat(ctx->p, "<br>", s, NULL );
                    } else {
                        detail = s;
                    }
                }
            }
    
            errors = (int)md_json_getl(mdj, MD_KEY_ERRORS, NULL);
            if (errors > 0) {
                classes = " error";
                summary = apr_psprintf(ctx->p, "%s (%d %s) ", summary, 
                                       errors, (errors > 1)? "retry" : "retries");
            }
    
            if( detail[0] ) {
                apr_brigade_printf(ctx->bb, NULL, NULL,
                                   "%s popclick\" popup=\"#pop%"APR_SIZE_T_FMT"\"><a title=\"Click for detail\">%s</a>",
                                   classes, index+2000000, summary);
                WT apr_psprintf(ctx->p,
                                "<div id=\"pop%"APR_SIZE_T_FMT"\" title=\"%s\" class=\"popup activity\">%s</div>",
                                index+2000000, qdomain, detail );
            } else {
                apr_brigade_printf(ctx->bb, NULL, NULL, "%s\">%s",
                                   classes, summary );
            }

            t = md_json_get_time(mdj, MD_KEY_RENEWAL, MD_KEY_NEXT_RUN, NULL);
            if (t > apr_time_now() && !finished) {
                print_time(ctx->bb, "<br>Next run", t);
            } else if (!summary[0]) {
                apr_brigade_puts(ctx->bb, NULL, NULL, "<br>Ongoing&hellip;");
            }
        }
    } else {
        apr_time_t t;
        apr_brigade_puts(ctx->bb, NULL, NULL, "\">");
        t = md_json_get_time(mdj, MD_KEY_RENEW_AT, NULL);
        if (t > apr_time_now()) {
            print_time(ctx->bb, "Renew", t);
        } else if (t) {
            apr_brigade_puts(ctx->bb, NULL, NULL, "Pending");
        } else if (MD_RENEW_MANUAL == md_json_getl(mdj, MD_KEY_RENEW_MODE, NULL)) {
            apr_brigade_puts(ctx->bb, NULL, NULL, "Manual renewal");
        }
    }
    WT "</td></tr>";
#undef WT
    return 1;
}

static apr_status_t get_keys(void **ep, md_json_t *j, apr_pool_t *p, void *baton) {
    manage_ctx *ctx = baton;
    const char *ktype;

    (void)p;

    if( (ktype = md_json_gets(j, MD_KEY_TYPE, NULL)) ) {
        if( !strcmp(ktype, "EC") ) ktype = "ECDSA";
        *((char **)ep) = apr_pstrdup(ctx->p, ktype);
        return APR_SUCCESS;
    }
    return APR_ENOENT;
}

static int manage_display_key( void *baton, size_t index, md_json_t *key )
{
    manage_ctx *ctx = baton;
    const char *s;
    long l;

    if(index) apr_brigade_puts(ctx->bb, NULL, NULL, ctx->separator );

    if( (s = md_json_gets(key, MD_KEY_CURVE, NULL )) ) {
        apr_brigade_puts(ctx->bb, NULL, NULL, s );
    } else if( (s = md_json_gets(key, MD_KEY_TYPE, NULL ) ) ){
        apr_brigade_puts(ctx->bb, NULL, NULL, s );
        if( (l = md_json_getl(key, MD_KEY_BITS, NULL ) ) ){
            apr_brigade_printf(ctx->bb, NULL, NULL, "-%ld", l  );
        }
    }
    return 1;
}

POSTHANDLER(get_cadir)
{
    apr_status_t rv;
    const char *s;
    md_http_t *http = NULL;
    md_json_t *j = NULL;

    (void)sc;

    if( !(s = md_json_gets(pars, "cadirurl", NULL)) ) {
        return md_json_resp( r, HTTP_NOT_FOUND, resp, "No CA URL" );
    }
    
    if( APR_SUCCESS != (rv = md_http_create( &http, r->pool,
                                             "mod_md/"MOD_MD_VERSION,
                                             mc->proxy_url )) ||
        APR_SUCCESS != (rv = md_json_http_get( &j, r->pool, http, s)) ) {
        return md_json_resp( r, rv, resp, "no data" );
    }

    md_json_setj(j, resp, "cadir", NULL );

    return md_json_resp( r, OK, resp, NULL );
}

POSTHANDLER(find_names)
{
    apr_status_t rv = APR_SUCCESS;
    apr_array_header_t *mds;
    find_ctx_t ctx;
    int i,j;

    (void)sc; (void)mc;
    if( !(ctx.filter = md_json_gets(pars, "paging", "filter", NULL)) ) {
        return md_json_resp( r, HTTP_NOT_FOUND, resp, "No filter" );
    }

    ctx.matched = apr_array_make(r->pool, mc->mds->nelts, sizeof(const char *));
    ctx.nfound = 0;
    /* Limit: 0: unlimited.  >0 stop at limit.  <0 stop storing at -limit (but count matches) */
    ctx.limit  =  md_json_is( MD_JSON_TYPE_INT, pars, "paging", "maxmatch", NULL )?
        md_json_getl(pars, "paging", "maxmatch", NULL) : 0;

    mds = apr_array_copy(r->pool, mc->mds);
    qsort(mds->elts, (size_t)mds->nelts, sizeof(md_t *), md_name_cmp);

    for( i = 0; i < mds->nelts; ++i ) {
        md_t *md;

        md = (md_t *)APR_ARRAY_IDX(mds, i, md_t *);

        if( APR_INCOMPLETE == (rv = md_manage_filter_match( (void *)md->name, &ctx )) ) {
            break;
        }
        for( j = 0; j < md->domains->nelts; ++j ) {
            const char *san = (const char *)APR_ARRAY_IDX(md->domains, j, const char *);

            if( APR_INCOMPLETE == (rv = md_manage_filter_match( (void *)san, &ctx )) ) {
                i = mds->nelts;
                break;
            }
        }
    }
    md_json_setsa( ctx.matched, resp, "names", NULL );

    md_json_setl(ctx.matched->nelts, resp, "paging", "total", NULL);
    if( md_json_is( MD_JSON_TYPE_INT, pars, "paging", "count", NULL ) ) {
        md_json_setl(md_json_getl(pars, "paging", "count", NULL),
                     resp, "paging", "count", NULL);
    }
    md_json_setl(ctx.limit,  resp, "paging", "maxmatch", NULL);
    md_json_setl(ctx.nfound, resp, "paging", "matches", NULL);
    md_json_setl(1,          resp, "paging", "start", NULL);
    md_json_setb( (rv == APR_INCOMPLETE || ctx.nfound > ctx.limit),
                             resp, "paging", "limited", NULL );
    switch( rv ) {
    case APR_SUCCESS:
        break;
    case APR_ENOENT:
        rv = APR_SUCCESS;
        break;
    case APR_INCOMPLETE:
        rv = APR_SUCCESS;
        break;
    default:
        break;
    }


    return md_json_resp( r, rv, resp, NULL );
}

static apr_status_t md_manage_filter_match( void *value, void *baton )
{
    unsigned const char *candidate = (unsigned char *)value;
    find_ctx_t *ctx = (find_ctx_t *)baton;
    size_t i;
    int c;

    if( !(c = tolower((unsigned char)*ctx->filter)) ) {
        goto matched;
    }

    for( ; *candidate; candidate++ ) {
        if( c == tolower(*candidate) ) {
            for( i = 0; ; ) {
                if( !(unsigned char)ctx->filter[++i] ) {
                    goto matched;
                }
                if( tolower((unsigned char)ctx->filter[i]) != tolower(candidate[i]) )
                    break;
            }
        }
    }
    return APR_ENOENT;

 matched:
    if( ctx->limit > 0 && ctx->nfound >= ctx->limit ) return APR_INCOMPLETE;
    ++ctx->nfound;
    if( !ctx->matched )                               return APR_SUCCESS;

    for( c = 0; c < ctx->matched->nelts; ++c ) {
        if( !strcasecmp( (char *)value, APR_ARRAY_IDX(ctx->matched, c, const char *) ) ) {
            --ctx->nfound;
            return APR_SUCCESS;
        }
    }
    if( ctx->limit ) {
        if( ctx->limit > 0 ) {
            if( ctx->nfound > ctx->limit ) {
                --ctx->nfound;
                return APR_INCOMPLETE;
            }
        } else if( ctx->nfound > -ctx->limit )        return APR_SUCCESS;
    }

    APR_ARRAY_PUSH(ctx->matched, const char *) = (char *)value;
    return APR_SUCCESS;
}

POSTHANDLER(queue_function) {
    apr_status_t    rv;
    apr_sockaddr_t *sa;
    apr_socket_t  *sock = NULL;
    const char    *msg = NULL;
    apr_size_t     msglen;
    const char    *req = NULL;
    apr_time_t     now;
    int            i;
    unsigned char  link_key[MANAGE_KEY_LENGTH];

    (void)sc;

    md_store_fs_get_manage_key(md_reg_store_get(mc->reg),link_key, sizeof(link_key));

    now = apr_time_now();

    md_json_sets(r->user? r->user : "Unknown", pars, "requestor", "username", NULL );
    md_json_sets(ap_get_useragent_host(r, REMOTE_NAME, NULL), pars, "requestor", "host", NULL );
    md_json_set_time(now, pars, "timestamp", NULL );

    if( !((req = md_json_writep( pars, r->pool, MD_JSON_FMT_DEBUG )) &&
          (msglen = strlen(req))) ){
        return md_json_resp( r, APR_EGENERAL, resp, "Failed to queue" );
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                  "manage GUI request:%s", req);


    if( APR_SUCCESS != (rv = apr_sockaddr_info_get( &sa, "127.0.0.1", APR_INET,
                             (apr_port_t)(mc->manage_gui_enabled & (apr_port_t)-1),
                                                    0, r->pool )) ||
        APR_SUCCESS != (rv = apr_socket_create( &sock, sa->family, SOCK_STREAM,
                                                APR_PROTO_TCP, r->pool )) ) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, rv, r, "Unable to create queuing socket");
        goto respond;
    }

    for( i = 0; i < 5; ++i ) {
        md_json_t *rs;

        if( APR_SUCCESS != (rv = apr_socket_opt_set( sock, APR_SO_NONBLOCK, 1))                          ||
            APR_SUCCESS != (rv = apr_socket_timeout_set( sock, APR_USEC_PER_SEC * MANAGE_LINK_TIMEOUT )) ||
            APR_SUCCESS != (rv = apr_socket_connect( sock, sa )) ) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE5, rv, r,
                  "manage server connection failed, will retry %s", req);
            apr_sleep( APR_USEC_PER_SEC );
            continue;
        }
        if( APR_SUCCESS != (rv = apr_socket_opt_set( sock, APR_SO_NONBLOCK, 0))                          ||
            APR_SUCCESS != (rv = apr_socket_timeout_set( sock, APR_USEC_PER_SEC * MANAGE_LINK_TIMEOUT )) ||
            APR_SUCCESS != (rv = md_manage_send_message(sock, link_key, req, msglen)) ) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE5, rv, r,
                          "manage server send failed, will retry:%s", req);
            apr_sleep( APR_USEC_PER_SEC );
            continue;
        }
        if( APR_SUCCESS != (rv = md_manage_recv_message(sock, link_key, &msg, &msglen, r->pool)) ||
            APR_SUCCESS != (rv = md_json_readd( &rs, r->pool, msg, msglen )) ) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE5, rv, r,
                  "manage server response body error:%s", req);
            break;
        }
        apr_socket_close( sock );
        md_json_setj( rs, resp, "result", NULL );
        ((char *)msg)[msglen] = '\0';
        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                  "manage server response:%s", msg);
        return md_json_resp( r, OK, resp, NULL );
    }

    apr_socket_close( sock );
    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, rv, r,
                  "manage server not responding:%s", req);
 respond:
    return md_json_resp( r, rv, resp, "Service not responding" );
}

/*
POSTHANDLER(import_account) {
    STUB_HANDLER
}
*/

/* Construct a JSON response and complete request.
 * Status is always OK, and JSON must be at least an empty object to
 * satisfy clients.
 * Install msg - appending any specified in call, or by the nominal status.
 */
apr_status_t md_json_resp( request_rec *r, apr_status_t rv, md_json_t *j, const char *msg )
{
    apr_bucket_brigade *bb;
    char s[HUGE_STRING_LEN];
    const char *m = NULL;

    if( j ) {
        m = md_json_gets(j, "message", NULL );
    } else {
        j = md_json_create(r->pool);
    }
    md_json_sets(apr_psprintf(r->pool, "%d", rv), j, "status", NULL);
    if( msg ) {
        if( m ) {
            m = apr_pstrcat(r->pool, m, "\n", msg, NULL);
        } else {
            m = msg;
        }
    }
    if( rv != OK ) {
        apr_strerror(rv, s, sizeof(s));
        if( m ) {
            m = apr_pstrcat(r->pool, m, "<br>", s, NULL);
        } else {
            m = s;
        }
    }
    if( m ) {
        md_json_sets(m, j, "message", NULL);
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    md_json_writeb(j, MD_JSON_FMT_DEBUG, bb);
    ap_pass_brigade(r->output_filters, bb);
    apr_brigade_destroy(bb);

    return OK;
}
