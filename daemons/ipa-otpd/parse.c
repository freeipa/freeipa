/*
 * FreeIPA 2FA companion daemon
 *
 * Authors: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2013  Nathaniel McCallum, Red Hat
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

/*
 * This file parses the user's configuration received from LDAP (see query.c).
 */

#define _GNU_SOURCE  /* for asprintf() */
#include "internal.h"
#include <asm-generic/errno-base.h>
#include <ctype.h>
#include <krb5/krb5.h>

#define DEFAULT_TIMEOUT 15
#define DEFAULT_RETRIES 3

/* Convert an LDAP entry into an allocated string. */
int get_string(LDAP *ldp, LDAPMessage *entry, const char *name,
               char **out)
{
    struct berval **vals;
    ber_len_t i;
    char *buf;

    vals = ldap_get_values_len(ldp, entry, name);
    if (vals == NULL)
        return ENOENT;

    buf = calloc(vals[0]->bv_len + 1, sizeof(char));
    if (buf == NULL) {
        ldap_value_free_len(vals);
        return ENOMEM;
    }

    for (i = 0; i < vals[0]->bv_len; i++) {
        if (!isprint(vals[0]->bv_val[i])) {
            free(buf);
            ldap_value_free_len(vals);
            return EINVAL;
        }

        buf[i] = vals[0]->bv_val[i];
    }

    if (*out != NULL)
        free(*out);
    *out = buf;
    ldap_value_free_len(vals);
    return 0;
}

/* Convert an LDAP entry into an allocated string array. */
int get_string_array(LDAP *ldp, LDAPMessage *entry, const char *name,
                     char ***out)
{
    struct berval **vals;
    ber_len_t i;
    char **buf = NULL;
    int tmp;
    size_t count;
    size_t c;
    int ret;

    vals = ldap_get_values_len(ldp, entry, name);
    if (vals == NULL)
        return ENOENT;

    tmp = ldap_count_values_len(vals);
    if (tmp < 0) {
        ret = ENOENT;
        goto done;
    }
    count = (size_t) tmp;

    buf = calloc(count + 1, sizeof(char *));
    if (buf == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; c < count; c++) {
        buf[c] = calloc(vals[c]->bv_len + 1, sizeof(char));
        if (buf[c] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < vals[c]->bv_len; i++) {
            if (!isprint(vals[c]->bv_val[i])) {
                ret = EINVAL;
                goto done;
            }

            buf[c][i] = vals[c]->bv_val[i];
        }
    }

    if (*out != NULL)
        free(*out);
    *out = buf;

    ret = 0;

done:
    if (ret != 0 && buf != NULL) {
        for (c = 0; buf[c] != NULL; c++) {
            free(buf[c]);
        }
        free(buf);
    }
    ldap_value_free_len(vals);
    return ret;
}

/* Convert an LDAP entry into an unsigned long. */
static int get_ulong(LDAP *ldp, LDAPMessage *entry, const char *name,
                     unsigned long *out)
{
    struct berval **vals;
    char buffer[32];

    vals = ldap_get_values_len(ldp, entry, name);
    if (vals == NULL)
        return ENOENT;

    if (vals[0]->bv_len > sizeof(buffer) - 1) {
        ldap_value_free_len(vals);
        return ERANGE;
    }

    memcpy(buffer, vals[0]->bv_val, vals[0]->bv_len);
    buffer[vals[0]->bv_len] = '\0';
    ldap_value_free_len(vals);

    *out = strtoul(buffer, NULL, 10);
    if (*out == ULONG_MAX)
        return errno;

    return 0;
}

/* Parse basic user configuration. */
const char *otpd_parse_user(LDAP *ldp, LDAPMessage *entry,
                            struct otpd_queue_item *item)
{
  int i, j;

  i = get_string(ldp, entry, "uid", &item->user.uid);
  if (i != 0)
      return strerror(i);

  i = get_string(ldp, entry, "ipatokenRadiusUserName",
                 &item->user.ipatokenRadiusUserName);
  if (i != 0 && i != ENOENT)
      return strerror(i);

  i = get_string(ldp, entry, "ipatokenRadiusConfigLink",
                 &item->user.ipatokenRadiusConfigLink);
  if (i != 0 && i != ENOENT)
      return strerror(i);

  i = get_string(ldp, entry, "ipaidpSub",
                 &item->user.ipaidpSub);
  if (i != 0 && i != ENOENT)
      return strerror(i);

  i = get_string(ldp, entry, "ipaidpConfigLink",
                 &item->user.ipaidpConfigLink);
  if (i != 0 && i != ENOENT)
      return strerror(i);

  i = get_string_array(ldp, entry, "ipaPassKey",
                       &item->user.ipaPassKey);
  if (i != 0 && i != ENOENT)
      return strerror(i);

  i = get_string_array(ldp, entry, "ipauserauthtype",
                       &item->user.ipauserauthtypes);
  if (i != 0 && i != ENOENT)
      return strerror(i);

  /* Get the DN. */
  item->user.dn = ldap_get_dn(ldp, entry);
  if (item->user.dn == NULL) {
      i = ldap_get_option(ldp, LDAP_OPT_RESULT_CODE, &j);
      return ldap_err2string(i == LDAP_OPT_SUCCESS ? j : i);
  }

  return NULL;
}

#define ENV_OIDC_CHILD_DEBUG_LEVEL "oidc_child_debug_level"
/* Parse the IdP configuration */
const char *otpd_parse_idp(LDAP *ldp, LDAPMessage *entry,
                              struct otpd_queue_item *item)
{
    int i;
    long dbg_lvl = 0;
    const char *dbg_env = NULL;
    char *endptr = NULL;

    item->idp.valid = FALSE;
    i = get_string(ldp, entry, "cn", &item->idp.name);
    if (i != 0) {
        return strerror(i);
    }

    i = get_string(ldp, entry, "ipaidpIssuerURL", &item->idp.ipaidpIssuerURL);
    if ((i != 0) && (i != ENOENT)) {
        return strerror(i);
    }

    /* We support either passing issuer URL or individual end-points */
    if (i == ENOENT) {
        i = get_string(ldp, entry, "ipaidpDevAuthEndpoint", &item->idp.ipaidpDevAuthEndpoint);
        if (i != 0) {
            return strerror(i);
        }

        i = get_string(ldp, entry, "ipaidpTokenEndpoint", &item->idp.ipaidpTokenEndpoint);
        if (i != 0) {
            return strerror(i);
        }

        i = get_string(ldp, entry, "ipaidpUserInfoEndpoint", &item->idp.ipaidpUserInfoEndpoint);
        if (i != 0) {
            return strerror(i);
        }

        /* JWKS end-point may be optional */
        i = get_string(ldp, entry, "ipaidpKeysEndpoint", &item->idp.ipaidpKeysEndpoint);
        if ((i != 0) && (i != ENOENT)) {
            return strerror(i);
        }
    }

    i = get_string(ldp, entry, "ipaidpClientID", &item->idp.ipaidpClientID);
    if (i != 0) {
        return strerror(i);
    }

    i = get_string(ldp, entry, "ipaidpClientSecret", &item->idp.ipaidpClientSecret);
    if ((i != 0) && (i != ENOENT)) {
        return strerror(i);
    }

    i = get_string(ldp, entry, "ipaidpScope", &item->idp.ipaidpScope);
    if ((i != 0) && (i != ENOENT)) {
        return strerror(i);
    }

    i = get_string(ldp, entry, "ipaidpSub", &item->idp.ipaidpSub);
    if ((i != 0) && (i != ENOENT)) {
        return strerror(i);
    }

    item->idp.ipaidpDebugLevelStr = NULL;
    item->idp.ipaidpDebugCurl = FALSE;
    dbg_env = getenv(ENV_OIDC_CHILD_DEBUG_LEVEL);
    if (dbg_env != NULL && *dbg_env != '\0') {
        errno = 0;
        dbg_lvl = strtoul(dbg_env, &endptr, 10);
        if (errno == 0 && *endptr == '\0') {
            if (dbg_lvl < 0) {
                dbg_lvl = 0;
            } else if (dbg_lvl > 10) {
                dbg_lvl = 10;
            }
            if (asprintf(&item->idp.ipaidpDebugLevelStr, "%ld", dbg_lvl) != -1) {
                if (dbg_lvl > 5) {
                    item->idp.ipaidpDebugCurl = TRUE;
                }
            } else {
                otpd_log_req(item->req, "Failed to copy debug level");
            }
        } else {
            otpd_log_req(item->req,
                         "Cannot parse value [%s] from environment variable [%s]",
                         dbg_env, ENV_OIDC_CHILD_DEBUG_LEVEL);
        }
    }

    item->idp.valid = TRUE;
    return NULL;
}

/* Parse the user's RADIUS configuration. */
const char *otpd_parse_radius(LDAP *ldp, LDAPMessage *entry,
                              struct otpd_queue_item *item)
{
  unsigned long l;
  int i;

  i = get_string(ldp, entry, "ipatokenRadiusServer",
                 &item->radius.ipatokenRadiusServer);
  if (i != 0)
      return strerror(i);

  i = get_string(ldp, entry, "ipatokenRadiusSecret",
                 &item->radius.ipatokenRadiusSecret);
  if (i != 0)
      return strerror(i);

  i = get_string(ldp, entry, "ipatokenUserMapAttribute",
                 &item->radius.ipatokenUserMapAttribute);
  if (i != 0 && i != ENOENT)
      return strerror(i);

  i = get_ulong(ldp, entry, "ipatokenRadiusTimeout", &l);
  if (i == ENOENT)
      l = DEFAULT_TIMEOUT;
  else if (i != 0)
      return strerror(i);
  item->radius.ipatokenRadiusTimeout = l * 1000;

  i = get_ulong(ldp, entry, "ipatokenRadiusRetries", &l);
  if (i == ENOENT)
      l = DEFAULT_RETRIES;
  else if (i != 0)
      return strerror(i);
  item->radius.ipatokenRadiusRetries = l;

  return NULL;
}

/* Parse the user's RADIUS username. */
const char *otpd_parse_radius_username(LDAP *ldp, LDAPMessage *entry,
                                       struct otpd_queue_item *item)
{
  int i;

  i = get_string(ldp, entry, item->radius.ipatokenUserMapAttribute,
                 &item->user.other);
  if (i != 0)
      return strerror(i);

  return NULL;
}
