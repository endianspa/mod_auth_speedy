/*
 * mod_proxy_speedy.c
 *
 * Mod Proxy Express + Backend protection
 *
 *  eeee     _nn_       dd   ii   _aa      _nn_
 * ee""ee   _n""n_      dd   -    a"a_    _n""n_
 * ee  ee   nn  nn      dd           a    nn  nn
 * ee  ee   nn  nn   _dddd   ii   _aaa    nn  nn
 * ee  ee   nn  nn  _d""dd   ii  _a""aa   nn  nn
 * ee__ee   nn  nn  dd  dd   ii  aa  aa   nn  nn
 * eeee"    nn  nn  dd  dd   ii  aa  aa   nn  nn
 * ee"      nn  nn  dd  dd   ii  aa  aa   nn  nn
 * ee       nn  nn  dd  dd   ii  aa  aa   nn  nn
 *  ee      nn  nn  dd  dd   ii  aa  aa   nn  nn
 *   ee     nn  nn   ddddd   ii   aaaaa   nn  nn
 *    -"    -"  "'    -'-"   "'    -'-"   "'  -"
 *
 * ||  ||  ||  ||  ||  ||  ||||||||||||||||||||||
 *
 * Changelog:
 *
 * v 0.1.0 - a.bonomi@endian.com 2017-04-14
 *
 * Based on mod_proxy_express.c
 *
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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either speedy or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_proxy.h"
#include "apr_dbm.h"
#include "util_cookies.h"

module AP_MODULE_DECLARE_DATA proxy_speedy_module;

#define DBMFILE_DEFAULT      NULL
#define DBMFILE_TYPE         "default"
#define COOKIE_NAME_DEFAULT  NULL
#define ENABLED_DEFAULT      0

static int proxy_available = 0;

/**
 * Module config structure
 */
typedef struct {
    char *dbmfile;
    char *dbmtype;
    char *cookie_name;
    int enabled;
} speedy_server_conf;

/**
 * Set ProxySpeedyDBMFile config parameter
 */
static const char *set_dbmfile(cmd_parms *cmd, void *dconf, const char *arg)
{
    speedy_server_conf *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &proxy_speedy_module);
    if ((sconf->dbmfile = ap_server_root_relative(cmd->pool, arg)) == NULL) {
        return apr_pstrcat(cmd->pool, "ProxySpeedyDBMFile: bad path to file: ", arg, NULL);
    }
    return NULL;
}

/**
 * Set ProxySpeedyDBMType config parameter
 */
static const char *set_dbmtype(cmd_parms *cmd, void *dconf, const char *arg)
{
    speedy_server_conf *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &proxy_speedy_module);
    sconf->dbmtype = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/**
 * Set ProxySpeedyEnable config parameter
 */
static const char *set_enabled(cmd_parms *cmd, void *dconf, int flag)
{
    speedy_server_conf *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &proxy_speedy_module);
    sconf->enabled = flag;
    return NULL;
}

/**
 * Set ProxySpeedyCookieName config parameter
 */
static const char *set_cookie_name(cmd_parms *cmd, void *dconf, const char *arg)
{
    speedy_server_conf *sconf;
    sconf = ap_get_module_config(cmd->server->module_config, &proxy_speedy_module);
    sconf->cookie_name = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/**
 * Create per-server config structures
 */
static void *server_create(apr_pool_t *p, server_rec *s)
{
    speedy_server_conf *sconf;
    sconf = (speedy_server_conf *)apr_pcalloc(p, sizeof(speedy_server_conf));
    sconf->dbmfile = DBMFILE_DEFAULT;
    sconf->dbmtype = DBMFILE_TYPE;
    sconf->cookie_name = COOKIE_NAME_DEFAULT;
    sconf->enabled = ENABLED_DEFAULT;
    return (void *)sconf;
}

/**
 * Merge per-server config structures
 */
static void *server_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    speedy_server_conf *a, *base, *overrides;

    a         = (speedy_server_conf *)apr_pcalloc(p, sizeof(speedy_server_conf));
    base      = (speedy_server_conf *)basev;
    overrides = (speedy_server_conf *)overridesv;

    a->dbmfile = (overrides->dbmfile) ? overrides->dbmfile : base->dbmfile;
    a->dbmtype = (overrides->dbmtype) ? overrides->dbmtype : base->dbmtype;
    a->cookie_name = (overrides->cookie_name) ? overrides->cookie_name : base->cookie_name;
    a->enabled = (overrides->enabled) ? overrides->enabled : base->enabled;

    return (void *)a;
}

/**
 * Post config hook
 */
static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    proxy_available = (ap_find_linked_module("mod_proxy.c") != NULL);
    return OK;
}

/**
 * Get a cookie value by name
 *
 * @param return        The request
 * @param cookie_name   Cookie name
 * @return              Return the cookie value or NULL
 */
static char *get_cookie(request_rec *r, const char *cookie_name)
{
    const char *cookies;
    const char *start_cookie;


    if ((cookies = apr_table_get(r->headers_in, "Cookie"))) {
        if (!cookies) {
            return NULL;
        }
        for (start_cookie = ap_strstr_c(cookies, cookie_name); start_cookie;
                start_cookie = ap_strstr_c(start_cookie + 1, cookie_name)) {
            if (start_cookie == cookies ||
                    start_cookie[-1] == ';' ||
                    start_cookie[-1] == ',' ||
                    isspace(start_cookie[-1])) {

                start_cookie += strlen(cookie_name);
                while(*start_cookie && isspace(*start_cookie))
                    ++start_cookie;
                if (*start_cookie++ == '=' && *start_cookie) {
                    /*
                     * Session cookie was found, get its value
                     */
                    char *end_cookie, *cookie;
                    cookie = apr_pstrdup(r->pool, start_cookie);
                    if ((end_cookie = strchr(cookie, ';')) != NULL)
                        *end_cookie = '\0';
                    if ((end_cookie = strchr(cookie, ',')) != NULL)
                        *end_cookie = '\0';
                    return cookie;
                }
            }
        }
    }
    return NULL;
}

/**
 * Set a cookie
 *
 * @param return        The request
 * @param cookie_name   Cookie name
 * @param cookie_value  New cookie value
 * @return              Return the new cookie value
 */
static const char *set_cookie(request_rec *r, const char *cookie_name, const char *cookie_value)
{
    char *new_cookie = apr_pstrcat(r->pool, cookie_name, "=", cookie_value, NULL);
    apr_table_add(r->headers_out, "Set-Cookie", new_cookie);
    return cookie_value;
}

/**
 * Parse the query string, extract the token parameter and store in a cookie with the same name
 *
 * @param return        The request
 * @param cookie_name   Cookie name
 * @return              Return the location without the token
 */
static const char *process_query_string(request_rec *r, const char *cookie_name)
{
    const int len = strlen(cookie_name);
    char *querystring = r->parsed_uri.query;
    char *location = r->parsed_uri.path;
    const char *param;
    const char *value = NULL;

    if (!querystring) {
        return NULL;
    }

    /*
     * First check if the identifier is at the beginning of the
     * querystring and followed by a '='
     */
    if (!strncmp(querystring, cookie_name, len) && (*(querystring + len) == '=')) {
        param = querystring;

    } else {
        char *complete;

        /*
         * In order to avoid subkey matching (PR 48401) prepend
         * identifier with a '&' and append a '='
         */
        complete = apr_pstrcat(r->pool, "&", cookie_name, "=", NULL);
        param = strstr(querystring, complete);
        /* If we found something we are sitting on the '&' */
        if (param) {
            param++;
        }
    }

    if (param) {
        const char *amp;

        if (querystring != param) {
            querystring = apr_pstrndup(r->pool, querystring, param - querystring); /* First part, before the token */
        } else {
            querystring = "";
        }

        value = param;
        if ((amp = ap_strchr_c(param + len + 1, '&'))) {
            value = apr_pstrndup(r->pool, param + len + 1, amp - param - len - 1);
            querystring = apr_pstrcat(r->pool, querystring, amp + 1, NULL);
        } else {
            value = apr_pstrdup(r->pool, param + len + 1);
            if (*querystring) {
                /*
                 * If querystring is not "", then we have the case
                 * that the identifier parameter we removed was the
                 * last one in the original querystring. Hence we have
                 * a trailing '&' which needs to be removed.
                 */
                querystring[strlen(querystring) - 1] = '\0';
            }
        }
    }

    /*
     * Concatenate the query string to the location
     */
    if (*querystring) {
        location = apr_pstrcat(r->pool, location, "?", querystring, NULL);
    }

    if (!value) {
        return NULL;

    } else {
        /*
         * Store the parameter value in a cookie with the same name
         */
        set_cookie(r, cookie_name, value);
        return location;
    }
}

/**
 * If the backend is protected, check if the cookie value matches the password
 *
 * A protectd backend is in the format:
 * <password hash>:<url>
 * Example:
 * $apr1$Fu4p6/..$OJD4ywafwKzhSRRdwXYea.:http://10.1.2.11/
 *
 * @param return        The request
 * @param backend       The backend (URL or <password hash>:<url>)
 * @param cookie_value  Cookie value
 * @return              Returns the backend or NULL if the token is not verified
 */
static const char *check_request(request_rec *r, const char *backend, const char *cookie_value) {
    char *result = apr_pstrdup(r->pool, backend);
    char *t;
    apr_status_t status;

    if ((result[0] == '$') && (t = ap_strchr_c(result, ':'))) {
        /*
         * Split password and backend
         */
        const char *password = result;
        *t = '\0';
        result = t + 1;

        /*
         * Verify the token
         */
        status = apr_password_validate(cookie_value, password);
        if (status != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01012)
                "Invalid password for %s", backend);
            return NULL;
        }
    }
    return result;
}

/**
 * Set the status, content type and messag
 *
 * @param return        The request
 * @param status        Status code
 * @param message       Message
 * @return              Always returns DONE
 */
static int done(request_rec *r, int status, const char *message)
{
    ap_set_content_type(r, "text/plain");
    ap_rprintf(r, "%s\n", message);
    r->status = status;
    return DONE;
}

/**
 * Get the backend URL for the given request
 *
 * @param return        The request
 * @param name          Server name
 * @param dbmfile       DBM file path
 * @param dbmtyp        DBM type
 * @return              Returns the backend URL (or URL and password) or NULL
 */
static const char *get_backend(request_rec *r, const char *name, const char *dbmfile, char *dbmtype)
{
    apr_dbm_t *db;
    apr_datum_t key, val;
    apr_status_t rv;
    char *backend;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01002)
            "proxy_speedy: Opening DBM file: %s (%s)",
            dbmfile, dbmtype);
    rv = apr_dbm_open_ex(&db, dbmtype, dbmfile, APR_DBM_READONLY,
            APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01010)
                "proxy_speedy: Error opening DBM file: %s (%s)",
                dbmfile, dbmtype);
        return NULL;
    }

    name = ap_get_server_name(r);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01003)
            "proxy_speedy: looking for %s", name);
    key.dptr = (char *)name;
    key.dsize = strlen(key.dptr);

    rv = apr_dbm_fetch(db, key, &val);
    apr_dbm_close(db);
    if (rv != APR_SUCCESS) {
        return NULL;
    }

    backend = apr_pstrmemdup(r->pool, val.dptr, val.dsize);
    if (!backend) {
        return NULL;
    }

    return backend;
}

/**
 * Proxy the request
 *
 * @param return        The request
 * @param name          Server name
 * @param backend       Backend URL
 * @return              Always returns OK
 */
static int proxy_request(request_rec *r, const char *name, const char *backend)
{
    int i;
    struct proxy_alias *ralias;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &proxy_module);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01004)
            "proxy_speedy: found %s -> %s", name, backend);
    r->filename = apr_pstrcat(r->pool, "proxy:", backend, r->uri, NULL);
    r->handler = "proxy-server";
    r->proxyreq = PROXYREQ_REVERSE;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01005)
            "proxy_speedy: rewritten as: %s", r->filename);

    ralias = (struct proxy_alias *)dconf->raliases->elts;
    /*
     * See if we have already added a ProxyPassReverse entry
     * for this host... If so, don't do it again.
     */
    /*
     * NOTE: dconf is process specific so this wil only
     *       work as long as we maintain that this process
     *       or thread is handling the backend
     */
    for (i = 0; i < dconf->raliases->nelts; i++, ralias++) {
        if (strcasecmp(backend, ralias->real) == 0) {
            ralias = NULL;
            break;
        }
    }

    /* Didn't find one... add it */
    if (!ralias) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01006)
                "proxy_speedy: adding PPR entry");
        ralias = apr_array_push(dconf->raliases);
        ralias->fake = "/";
        ralias->real = apr_pstrdup(dconf->raliases->pool, backend);
        ralias->flags = 0;
    }
    return OK;
}

static int translate_name(request_rec *r)
{
    const char *name;
    const char *backend;
    speedy_server_conf *sconf;
    const char *cookie_value;
    const char *location = NULL;

    sconf = ap_get_module_config(r->server->module_config, &proxy_speedy_module);

    /*
     * Check if the module is enabled
     */
    if (!sconf->enabled) {
        return DECLINED;
    }

    /*
     * Check if the proxy module is enabled
     */
    if (!proxy_available) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01014)
                "please enable mod_proxy");
        return DECLINED;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01001)
            "proxy_speedy: Enabled");
    if (!sconf->dbmfile || (r->filename && strncmp(r->filename, "proxy:", 6) == 0)) {
        /* it should be go on as an internal proxy request */
        return DECLINED;
    }

    /*
     * Get the backend URL
     */
    name = ap_get_server_name(r);
    backend = get_backend(r, name, sconf->dbmfile, sconf->dbmtype);
    if (!backend) {
        return DECLINED;
    }

    /*
     * Check the cookie
     */
    if (sconf->cookie_name != NULL) {
        cookie_value = get_cookie(r, sconf->cookie_name);
        if (cookie_value != NULL && strlen(cookie_value) != 0) {
            /*
             * If the destination is protected, check the cookie
             */
            backend = check_request(r, backend, cookie_value);
            if (!backend) {
                set_cookie(r, sconf->cookie_name, NULL); /* Delete the (invalid) cookie */
                return done(r, HTTP_FORBIDDEN, "Forbidden"); /*  Close this thread without further processing */
            }

        } else if ((location = process_query_string(r, sconf->cookie_name))) {
            /*
             * Redirect to the location without the token
             */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01013)
                    "redirecting to %s", location);
            apr_table_add(r->headers_out, "Location", location);
            return done(r, HTTP_TEMPORARY_REDIRECT, "Redirecting..."); /*  Close this thread without further processing */

        } else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01014)
                    "%s requested without token", name);
            return done(r, HTTP_FORBIDDEN, "Forbidden"); /*  Close this thread without further processing */
        }
    }

    /*
     * Proxy the request
     */
    return proxy_request(r, name, backend);
}

static const command_rec command_table[] = {
    AP_INIT_FLAG("ProxySpeedyEnable", set_enabled, NULL, OR_FILEINFO,
            "Enable the ProxySpeedy functionality"),
    AP_INIT_TAKE1("ProxySpeedyDBMFile", set_dbmfile, NULL, OR_FILEINFO,
            "Location of ProxySpeedyDBMFile file"),
    AP_INIT_TAKE1("ProxySpeedyDBMType", set_dbmtype, NULL, OR_FILEINFO,
            "Type of ProxySpeedyDBMFile file"),
    AP_INIT_TAKE1("ProxySpeedyCookieName", set_cookie_name, NULL, OR_FILEINFO,
            "Cookie name"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_translate_name(translate_name, NULL, NULL, APR_HOOK_FIRST);
}

/* the main config structure */

AP_DECLARE_MODULE(proxy_speedy) =
{
    STANDARD20_MODULE_STUFF,
    NULL,           /* create per-dir config structures */
    NULL,           /* merge  per-dir config structures */
    server_create,  /* create per-server config structures */
    server_merge,   /* merge  per-server config structures */
    command_table,  /* table of config file commands */
    register_hooks  /* register hooks */
};

