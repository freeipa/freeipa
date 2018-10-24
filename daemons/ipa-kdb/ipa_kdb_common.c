/*
 * MIT Kerberos KDC database backend for FreeIPA
 *
 * Authors: Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2011  Simo Sorce, Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ipa_kdb.h"
#include <unicase.h>

static struct timeval std_timeout = {300, 0};

char *ipadb_filter_escape(const char *input, bool star)
{
    char *output;
    size_t i = 0;
    size_t j = 0;

    if (!input) {
        return NULL;
    }

    /* Assume the worst-case. */
    output = malloc(strlen(input) * 3 + 1);
    if (!output) {
        return NULL;
    }

    while (input[i]) {
        switch(input[i]) {
        case '*':
            if (star) {
                output[j++] = '\\';
                output[j++] = '2';
                output[j++] = 'a';
            } else {
                output[j++] = '*';
            }
            break;
        case '(':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = '8';
            break;
        case ')':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = '9';
            break;
        case '\\':
            output[j++] = '\\';
            output[j++] = '5';
            output[j++] = 'c';
            break;
        default:
            output[j++] = input[i];
        }

        i++;
    }
    output[j] = '\0';

    return output;
}

static krb5_error_code ipadb_simple_ldap_to_kerr(int ldap_error)
{
    switch (ldap_error) {
    case LDAP_SUCCESS:
        return 0;

    case LDAP_NO_SUCH_OBJECT:
    case LDAP_NO_SUCH_ATTRIBUTE:
        return KRB5_KDB_NOENTRY;

    case LDAP_ALIAS_PROBLEM:
    case LDAP_INVALID_DN_SYNTAX:
    case LDAP_ALIAS_DEREF_PROBLEM:
    case LDAP_UNDEFINED_TYPE:
    case LDAP_INAPPROPRIATE_MATCHING:
    case LDAP_INVALID_SYNTAX:
    case LDAP_NAMING_VIOLATION:
    case LDAP_OBJECT_CLASS_VIOLATION:
    case LDAP_NO_OBJECT_CLASS_MODS:
        return KRB5_KDB_INTERNAL_ERROR;

    case LDAP_ALREADY_EXISTS:
    case LDAP_NOT_ALLOWED_ON_NONLEAF:
    case LDAP_NOT_ALLOWED_ON_RDN:
    case LDAP_TIMELIMIT_EXCEEDED:
    case LDAP_SIZELIMIT_EXCEEDED:
    case LDAP_ADMINLIMIT_EXCEEDED:
    case LDAP_STRONG_AUTH_REQUIRED:
    case LDAP_CONFIDENTIALITY_REQUIRED:
    case LDAP_INAPPROPRIATE_AUTH:
    case LDAP_INVALID_CREDENTIALS:
    case LDAP_INSUFFICIENT_ACCESS:
    case LDAP_BUSY:
    case LDAP_UNAVAILABLE:
    case LDAP_UNWILLING_TO_PERFORM:
    case LDAP_CONSTRAINT_VIOLATION:
    case LDAP_TYPE_OR_VALUE_EXISTS:
        return KRB5_KDB_CONSTRAINT_VIOLATION;
    }

    return KRB5_KDB_SERVER_INTERNAL_ERR;
}

static bool ipadb_need_retry(struct ipadb_context *ipactx, int error)
{
    switch(error) {
    /* connection errors */
    case LDAP_SERVER_DOWN:
    case LDAP_LOCAL_ERROR:
    case LDAP_ENCODING_ERROR:
    case LDAP_DECODING_ERROR:
    case LDAP_TIMEOUT:
    case LDAP_USER_CANCELLED:
    case LDAP_PARAM_ERROR:
    case LDAP_NO_MEMORY:
    case LDAP_CONNECT_ERROR:
    case LDAP_NOT_SUPPORTED:
    case LDAP_CLIENT_LOOP:
    case LDAP_X_CONNECTING:

    /* server returned errors */
    case LDAP_PROTOCOL_ERROR:
    case LDAP_BUSY:
    case LDAP_UNAVAILABLE:
    case LDAP_UNWILLING_TO_PERFORM:
    case LDAP_LOOP_DETECT:

        /* prob connection error, try to reconnect */
        error = ipadb_get_connection(ipactx);
        if (error == 0) {
            return true;
        }
        /* fall through */
    default:
        break;
    }

    return false;
}

static int ipadb_check_connection(struct ipadb_context *ipactx)
{
    if (ipactx->lcontext == NULL) {
        return ipadb_get_connection(ipactx);
    }
    return 0;
}

krb5_error_code ipadb_simple_search(struct ipadb_context *ipactx,
                                    char *basedn, int scope,
                                    char *filter, char **attrs,
                                    LDAPMessage **res)
{
    int ret;

    ret = ipadb_check_connection(ipactx);
    if (ret != 0)
        return ipadb_simple_ldap_to_kerr(ret);

    ret = ldap_search_ext_s(ipactx->lcontext, basedn, scope,
                            filter, attrs, 0, NULL, NULL,
                            &std_timeout, LDAP_NO_LIMIT,
                            res);

    /* first test if we need to retry to connect */
    if (ret != 0 &&
        ipadb_need_retry(ipactx, ret)) {
        ldap_msgfree(*res);
        ret = ldap_search_ext_s(ipactx->lcontext, basedn, scope,
                                filter, attrs, 0, NULL, NULL,
                                &std_timeout, LDAP_NO_LIMIT,
                                res);
    }

    return ipadb_simple_ldap_to_kerr(ret);
}

krb5_error_code ipadb_simple_delete(struct ipadb_context *ipactx, char *dn)
{
    int ret;

    ret = ipadb_check_connection(ipactx);
    if (ret != 0)
        return ipadb_simple_ldap_to_kerr(ret);

    ret = ldap_delete_ext_s(ipactx->lcontext, dn, NULL, NULL);

    /* first test if we need to retry to connect */
    if (ret != 0 &&
        ipadb_need_retry(ipactx, ret)) {

        ret = ldap_delete_ext_s(ipactx->lcontext, dn, NULL, NULL);
    }

    return ipadb_simple_ldap_to_kerr(ret);
}

krb5_error_code ipadb_simple_add(struct ipadb_context *ipactx,
                                 char *dn, LDAPMod **mods)
{
    int ret;

    ret = ipadb_check_connection(ipactx);
    if (ret != 0)
        return ipadb_simple_ldap_to_kerr(ret);

    ret = ldap_add_ext_s(ipactx->lcontext, dn, mods, NULL, NULL);

    /* first test if we need to retry to connect */
    if (ret != 0 &&
        ipadb_need_retry(ipactx, ret)) {

        ret = ldap_add_ext_s(ipactx->lcontext, dn, mods, NULL, NULL);
    }

    return ipadb_simple_ldap_to_kerr(ret);
}

krb5_error_code ipadb_simple_modify(struct ipadb_context *ipactx,
                                    char *dn, LDAPMod **mods)
{
    int ret;

    ret = ipadb_check_connection(ipactx);
    if (ret != 0)
        return ipadb_simple_ldap_to_kerr(ret);

    ret = ldap_modify_ext_s(ipactx->lcontext, dn, mods, NULL, NULL);

    /* first test if we need to retry to connect */
    if (ret != 0 &&
        ipadb_need_retry(ipactx, ret)) {

        ret = ldap_modify_ext_s(ipactx->lcontext, dn, mods, NULL, NULL);
    }

    return ipadb_simple_ldap_to_kerr(ret);
}

krb5_error_code ipadb_simple_delete_val(struct ipadb_context *ipactx,
                                        char *dn, char *attr, char *value)
{
    krb5_error_code kerr;
    LDAPMod *mods[2];

    mods[0] = calloc(1, sizeof(LDAPMod));
    if (!mods[0]) {
        return ENOMEM;
    }
    mods[1] = NULL;

    mods[0]->mod_op = LDAP_MOD_DELETE;
    mods[0]->mod_type = strdup(attr);
    if (!mods[0]->mod_type) {
        kerr = ENOMEM;
        goto done;
    }
    mods[0]->mod_values = calloc(2, sizeof(char *));
    if (!mods[0]->mod_values) {
        kerr = ENOMEM;
        goto done;
    }
    mods[0]->mod_values[0] = strdup(value);
    if (!mods[0]->mod_values[0]) {
        kerr = ENOMEM;
        goto done;
    }

    kerr = ipadb_simple_modify(ipactx, dn, mods);

done:
    ldap_mods_free(mods, 0);
    return kerr;
}

krb5_error_code ipadb_deref_search(struct ipadb_context *ipactx,
                                   char *base_dn, int scope,
                                   char *filter,
                                   char **entry_attrs,
                                   char **deref_attr_names,
                                   char **deref_attrs,
                                   LDAPMessage **res)
{
    struct berval derefval = { 0, NULL };
    LDAPControl *ctrl[2] = { NULL, NULL };
    LDAPDerefSpec *ds;
    krb5_error_code kerr;
    int times;
    int ret;
    int c, i;
    bool retry;

    for (c = 0; deref_attr_names[c]; c++) {
        /* count */ ;
    }

    ds = calloc(c+1, sizeof(LDAPDerefSpec));
    if (!ds) {
        return ENOMEM;
    }

    for (i = 0; deref_attr_names[i]; i++) {
        ds[i].derefAttr = deref_attr_names[i];
        ds[i].attributes = deref_attrs;
    }
    ds[c].derefAttr = NULL;

    ret = ldap_create_deref_control_value(ipactx->lcontext, ds, &derefval);
    if (ret != LDAP_SUCCESS) {
        kerr = ENOMEM;
        goto done;
    }

    ret = ldap_control_create(LDAP_CONTROL_X_DEREF,
                              1, &derefval, 1, &ctrl[0]);
    if (ret != LDAP_SUCCESS) {
        kerr = ENOMEM;
        goto done;
    }

    /* retry once if connection errors (tot. max. 2 tries) */
    times = 2;
    ret = LDAP_SUCCESS;
    retry = true;
    while (retry) {
        times--;

        ret = ipadb_check_connection(ipactx);
        if (ret != 0)
            break;

        ret = ldap_search_ext_s(ipactx->lcontext, base_dn,
                                scope, filter,
                                entry_attrs, 0,
                                ctrl, NULL,
                                &std_timeout, LDAP_NO_LIMIT,
                                res);
        retry = ipadb_need_retry(ipactx, ret) && times > 0;

        if (retry) {
            /* Free result before next try */
            ldap_msgfree(*res);
        }
    }

    kerr = ipadb_simple_ldap_to_kerr(ret);

done:
    ldap_control_free(ctrl[0]);
    ldap_memfree(derefval.bv_val);
    free(ds);
    return kerr;
}

/* result extraction */

int ipadb_ldap_attr_to_int(LDAP *lcontext, LDAPMessage *le,
                           char *attrname, int *result)
{
    struct berval **vals;
    int ret = ENOENT;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (vals) {
        *result = atoi(vals[0]->bv_val);
        ret = 0;
        ldap_value_free_len(vals);
    }

    return ret;
}

int ipadb_ldap_attr_to_uint32(LDAP *lcontext, LDAPMessage *le,
                              char *attrname, uint32_t *result)
{
    struct berval **vals;
    long r;
    int ret = ENOENT;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (vals) {
        r = atol(vals[0]->bv_val);
        if (r < 0 || r > (uint32_t)-1) {
            ret = EINVAL;
        } else {
            *result = r;
            ret = 0;
        }
        ldap_value_free_len(vals);
    }

    return ret;
}

int ipadb_ldap_attr_to_str(LDAP *lcontext, LDAPMessage *le,
                           char *attrname, char **result)
{
    struct berval **vals;
    int ret = ENOENT;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (vals) {
        *result = strndup(vals[0]->bv_val, vals[0]->bv_len);
        if (!*result) {
            ret = ENOMEM;
        } else {
            ret = 0;
        }
        ldap_value_free_len(vals);
    }

    return ret;
}

int ipadb_ldap_attr_to_strlist(LDAP *lcontext, LDAPMessage *le,
                               char *attrname, char ***result)
{
    struct berval **vals = NULL;
    char **strlist = NULL;
    int ret;
    int i;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (!vals) {
        return ENOENT;
    }

    for (i = 0; vals[i]; i++) /* count */ ;

    strlist = calloc(i + 1, sizeof(char *));
    if (!strlist) {
        ret = ENOMEM;
        goto fail;
    }

    for (i = 0; vals[i]; i++) {
        strlist[i] = strndup(vals[i]->bv_val, vals[i]->bv_len);
        if (!strlist[i]) {
            ret = ENOMEM;
            goto fail;
        }
    }

    ldap_value_free_len(vals);
    *result = strlist;
    return 0;

fail:
    ldap_value_free_len(vals);
    for (i = 0; strlist && strlist[i]; i++) {
        free(strlist[i]);
    }
    free(strlist);
    return ret;
}

int ipadb_ldap_attr_to_bool(LDAP *lcontext, LDAPMessage *le,
                            char *attrname, bool *result)
{
    struct berval **vals;
    int ret = ENOENT;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (vals) {
        if (strcasecmp("TRUE", vals[0]->bv_val) == 0) {
            *result = true;
            ret = 0;
        } else if (strcasecmp("FALSE", vals[0]->bv_val) == 0) {
            *result = false;
            ret = 0;
        } else {
            ret = EINVAL;
        }
        ldap_value_free_len(vals);
    }

    return ret;
}

int ipadb_ldap_attr_to_time_t(LDAP *lcontext, LDAPMessage *le,
                              char *attrname, time_t *result)
{
    struct berval **vals;
    char *p;
    struct tm stm = { 0 };
    int ret = ENOENT;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (vals) {
        p = strptime(vals[0]->bv_val, "%Y%m%d%H%M%SZ", &stm);
        if (p && *p == '\0') {
            *result = timegm(&stm);
            ret = 0;
        } else {
            ret = EINVAL;
        }
        ldap_value_free_len(vals);
    }

    return ret;
}

int ipadb_ldap_attr_to_krb5_timestamp(LDAP *lcontext, LDAPMessage *le,
                                      char *attrname, krb5_timestamp *result)
{
    time_t res_time;
    long long res_long;

    int ret = ipadb_ldap_attr_to_time_t(lcontext, le,
                                        attrname, &res_time);
    if (ret) return ret;

    /* this will cast correctly maintaing sign to a 64bit variable */
    res_long = res_time;

    /* For dates beyond IPAPWD_END_OF_TIME, rest_time might oveflow
     * on 32-bit platforms. This does not apply for 64-bit platforms.
     * However, since krb5 uses 32-bit time representation, we need
     * to limit the result.*/

    if (res_long < 0 || res_long > IPAPWD_END_OF_TIME)  {
        *result = IPAPWD_END_OF_TIME; // 1 Jan 2038, 00:00 GMT
    } else {
        *result = (krb5_timestamp)res_long;
    }

    return 0;
}

int ipadb_ldap_attr_has_value(LDAP *lcontext, LDAPMessage *le,
                              char *attrname, const char *value)
{
    struct berval **vals;
    int ret = ENOENT;
    int i, result;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (vals) {
        for (i = 0; vals[i]; i++) {
            if (ulc_casecmp(vals[i]->bv_val, vals[i]->bv_len,
                            value, strlen(value),
                            NULL, NULL, &result) != 0) {
                ret = errno;
                break;
            }

            if (result == 0) {
                ret = 0;
                break;
            }
        }

        ldap_value_free_len(vals);
    }

    return ret;
}

int ipadb_ldap_deref_results(LDAP *lcontext, LDAPMessage *le,
                             LDAPDerefRes **results)
{
    LDAPControl **ctrls = NULL;
    LDAPControl *derefctrl = NULL;
    int ret;

    ret = ldap_get_entry_controls(lcontext, le, &ctrls);
    if (ret != LDAP_SUCCESS) {
        return EINVAL;
    }

    if (!ctrls) {
        return ENOENT;
    }

    derefctrl = ldap_control_find(LDAP_CONTROL_X_DEREF, ctrls, NULL);
    if (!derefctrl) {
        ret = ENOENT;
        goto done;
    }

    ret = ldap_parse_derefresponse_control(lcontext, derefctrl, results);
    if (ret) {
        ret = EINVAL;
        goto done;
    }

    ret = 0;

done:
    ldap_controls_free(ctrls);
    return ret;
}

struct ipadb_multires {
    LDAP *lcontext;
    LDAPMessage **res;
    LDAPMessage *next;
    ssize_t cursor;
    ssize_t count;
};

krb5_error_code ipadb_multires_init(LDAP *lcontext, struct ipadb_multires **r)
{
    *r = malloc(sizeof(struct ipadb_multires));
    if (!*r) return ENOMEM;
    (*r)->lcontext = lcontext;
    (*r)->res = NULL;
    (*r)->next = NULL;
    (*r)->cursor = -1;
    (*r)->count = 0;

    return 0;
}

void ipadb_multires_free(struct ipadb_multires *r)
{
    if (r != NULL) {
        for (int i = 0; i < r->count; i++) {
            ldap_msgfree(r->res[i]);
        }
        free(r);
    }
}

LDAPMessage *ipadb_multires_next_entry(struct ipadb_multires *r)
{
    if (r->count == 0) return NULL;

    if (r->next) {
        r->next = ldap_next_entry(r->lcontext, r->next);
    }
    if (r->next == NULL) {
        if (r->cursor >= r->count - 1) {
            return NULL;
        }
        r->cursor++;
        r->next = ldap_first_entry(r->lcontext, r->res[r->cursor]);
    }

    return r->next;
}

krb5_error_code ipadb_multibase_search(struct ipadb_context *ipactx,
                                       char **basedns, int scope,
                                       char *filter, char **attrs,
                                       struct ipadb_multires **res,
                                       bool any)
{
    int ret;

    ret = ipadb_multires_init(ipactx->lcontext, res);
    if (ret != 0) return ret;

    ret = ipadb_check_connection(ipactx);
    if (ret != 0) {
        ipadb_multires_free(*res);
        *res = NULL;
        return ipadb_simple_ldap_to_kerr(ret);
    }

    for (int b = 0; basedns[b]; b++) {
        LDAPMessage *r;
        ret = ldap_search_ext_s(ipactx->lcontext, basedns[b], scope,
                                filter, attrs, 0, NULL, NULL,
                                &std_timeout, LDAP_NO_LIMIT, &r);

        /* first test if we need to retry to connect */
        if (ret != 0 &&
            ipadb_need_retry(ipactx, ret)) {
            ldap_msgfree(r);
            ret = ldap_search_ext_s(ipactx->lcontext, basedns[b], scope,
                                    filter, attrs, 0, NULL, NULL,
                                    &std_timeout, LDAP_NO_LIMIT, &r);
        }

        if (ret != 0) break;

        if (ldap_count_entries(ipactx->lcontext, r) > 0) {
            void *tmp = realloc((*res)->res, (((*res)->count + 1) *
                                                sizeof(LDAPMessage *)));
            if (tmp == NULL) {
                ret = ENOMEM;
                break;
            }
            (*res)->res = tmp;
            (*res)->res[(*res)->count] = r;
            (*res)->count++;

            if (any) break;
        }
    }

    if (ret != 0) {
        ipadb_multires_free(*res);
        *res = NULL;
    }

    return ipadb_simple_ldap_to_kerr(ret);
}

