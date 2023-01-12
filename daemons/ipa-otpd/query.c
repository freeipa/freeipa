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
 * This file receives requests (from stdio.c) and queries the LDAP server for
 * the user's configuration. When the user's configuration is received, it is
 * parsed (parse.c). Once the configuration is parsed, the request packet is
 * either forwarded to a third-party RADIUS server (forward.c) or authenticated
 * directly via an LDAP bind (bind.c) based on the configuration received.
 */

#define _GNU_SOURCE 1 /* for asprintf() */
#include "internal.h"
#include <ctype.h>
#include <stdbool.h>

#define DEFAULT_TIMEOUT 15
#define DEFAULT_RETRIES 3

/* To read passkey configuration and attributes from a different server than
 * FreeIPA you might have to the following two defines of the search filter
 * for the global configuration data and the attribute name where if passkey
 * information is stored in the user entry. Additionally otpd_parse_passkey()
 * might need some updates depending on how the global configuration is stored
 * in the configuration objects.
 */
#define PASSKEY_CONFIG_FILTER "(|(objectclass=ipapasskeyconfigobject)(&(objectclass=domain)(objectclass=domainRelatedObject)))"
#define PASSKEY_USER_ATTR "ipapasskey"

static char *user[] = {
    "uid",
    "ipatokenRadiusUserName",
    "ipatokenRadiusConfigLink",
    "ipaidpSub",
    "ipaidpConfigLink",
    "ipauserauthtype",
    PASSKEY_USER_ATTR,
    NULL
};

static char *radius[] = {
    "ipatokenRadiusServer",
    "ipatokenRadiusSecret",
    "ipatokenRadiusTimeout",
    "ipatokenRadiusRetries",
    "ipatokenUserMapAttribute",
    NULL
};

static char *idp[] = {
    "ipaidpClientID",
    "ipaidpClientSecret",
    "ipaidpIssuerURL",
    "ipaidpDevAuthEndpoint",
    "ipaidpTokenEndpoint",
    "ipaidpUserInfoEndpoint",
    "ipaidpKeysEndpoint",
    "ipaidpScope",
    "ipaidpSub",
    "cn",
    NULL
};

bool auth_type_is(char **auth_types, const char *check)
{
    size_t c;

    if (auth_types == NULL || check == NULL) {
        return false;
    }

    for(c = 0; auth_types[c] != NULL; c++) {
        if (strcasecmp(auth_types[c], check) == 0) {
            return true;
        }
    }

    return false;
}

/* Send queued LDAP requests to the server. */
static void on_query_writable(verto_ctx *vctx, verto_ev *ev)
{
    struct otpd_queue *push = &ctx.stdio.responses;
    const krb5_data *princ = NULL;
    char *filter = NULL, *attrs[2];
    int i = LDAP_SUCCESS;
    struct otpd_queue_item *item;
    (void)vctx;

    item = otpd_queue_pop(&ctx.query.requests);
    if (item == NULL) {
        verto_set_flags(ctx.query.io, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ);
        return;
    }

    if (item->user.dn == NULL) {
        princ = krad_packet_get_attr(item->req,
                                     krad_attr_name2num("User-Name"), 0);
        if (princ == NULL)
            goto error;

        otpd_log_req(item->req, "user query start");
        item->ldap_query = LDAP_QUERY_USER;

        if (asprintf(&filter, "(&(objectClass=Person)(krbPrincipalName=%*s))",
                     princ->length, princ->data) < 0)
            goto error;

        i = ldap_search_ext(verto_get_private(ev), ctx.query.base,
                            LDAP_SCOPE_SUBTREE, filter, user, 0, NULL,
                            NULL, NULL, 1, &item->msgid);
        free(filter);

    } else if (item->get_passkey_config) {
        otpd_log_req(item->req, "passkey config query start:");
        item->ldap_query = LDAP_QUERY_PASSKEY;

        i = ldap_search_ext(verto_get_private(ev), ctx.query.base,
                            LDAP_SCOPE_SUBTREE, PASSKEY_CONFIG_FILTER, NULL, 0, NULL,
                            NULL, NULL, 0, &item->msgid);

    } else if (auth_type_is(item->user.ipauserauthtypes, "idp")) {
        otpd_log_req(item->req, "idp query start: %s",
                item->user.ipaidpConfigLink);
        item->ldap_query = LDAP_QUERY_IDP;

        i = ldap_search_ext(verto_get_private(ev),
                            item->user.ipaidpConfigLink,
                            LDAP_SCOPE_BASE, NULL, idp, 0, NULL,
                            NULL, NULL, 1, &item->msgid);

    } else if (item->radius.ipatokenRadiusSecret == NULL) {
        otpd_log_req(item->req, "radius query start: %s",
                item->user.ipatokenRadiusConfigLink);
        item->ldap_query = LDAP_QUERY_RADIUS;

        i = ldap_search_ext(verto_get_private(ev),
                            item->user.ipatokenRadiusConfigLink,
                            LDAP_SCOPE_BASE, NULL, radius, 0, NULL,
                            NULL, NULL, 1, &item->msgid);

    } else if (item->radius.ipatokenUserMapAttribute != NULL) {
        otpd_log_req(item->req, "username query start: %s",
                item->radius.ipatokenUserMapAttribute);
        item->ldap_query = LDAP_QUERY_RADIUS_USERMAP;

        attrs[0] = item->radius.ipatokenUserMapAttribute;
        attrs[1] = NULL;
        i = ldap_search_ext(verto_get_private(ev), item->user.dn,
                            LDAP_SCOPE_BASE, NULL, attrs, 0, NULL,
                            NULL, NULL, 1, &item->msgid);
    }

    if (i == LDAP_SUCCESS) {
        push = &ctx.query.responses;
    }

error:
    otpd_queue_push(push, item);
}

static enum oauth2_state get_oauth2_state(enum ldap_query ldap_query,
                                          struct otpd_queue_item *item)
{
    const krb5_data *data_pwd;
    const krb5_data *data_state;
    enum oauth2_state oauth2_state = OAUTH2_NO;

    data_pwd = krad_packet_get_attr(item->req,
                                    krad_attr_name2num("User-Password"), 0);
    data_state = krad_packet_get_attr(item->req,
                                      krad_attr_name2num("Proxy-State"), 0);

    if (data_pwd == NULL && data_state == NULL) {
        oauth2_state = OAUTH2_GET_DEVICE_CODE;
    } else if (data_pwd == NULL && data_state != NULL) {
        oauth2_state = OAUTH2_GET_ACCESS_TOKEN;
    }

    /* Looks like caller does not expect oauth2 authentication */
    if (oauth2_state == OAUTH2_NO) {
        return oauth2_state;
    }

    if (ldap_query == LDAP_QUERY_USER) {
        /* Check the user entry for required attributes */
        if (item->user.ipaidpSub == NULL) {
            oauth2_state = OAUTH2_NO;
            otpd_log_req(item->req,
                         "OAuth2 not possible, Missing 'sub' in user entry");
        }
        if (item->user.ipaidpConfigLink == NULL) {
            oauth2_state = OAUTH2_NO;
            otpd_log_req(item->req,
                         "OAuth2 not possible, Missing issuer in user entry");
        }

        if (oauth2_state != OAUTH2_NO) {
            /* Next step is to lookup IdP data */
            oauth2_state = OAUTH2_GET_ISSUER;
        }
    } else if (ldap_query == LDAP_QUERY_IDP) {
        /* Check the idp entry for required attributes */
        if (item->idp.ipaidpIssuerURL == NULL) {
            if (item->idp.ipaidpDevAuthEndpoint == NULL) {
                oauth2_state = OAUTH2_NO;
                otpd_log_req(item->req,
                             "OAuth2 not possible, "
                             "Missing authentication end-point in idp entry");
            }
            if (item->idp.ipaidpTokenEndpoint == NULL) {
                oauth2_state = OAUTH2_NO;
                otpd_log_req(item->req,
                             "OAuth2 not possible, "
                             "Missing access token end-point in idp entry");
            }
            if (item->idp.ipaidpUserInfoEndpoint == NULL) {
                oauth2_state = OAUTH2_NO;
                otpd_log_req(item->req,
                             "OAuth2 not possible, "
                             "Missing userinfo end-point in idp entry");
            }
        }
        if (item->idp.ipaidpClientID == NULL) {
            oauth2_state = OAUTH2_NO;
            otpd_log_req(item->req,
                         "OAuth2 not possible, Missing client ID in idp entry");
        }
    }

    return oauth2_state;
}

/* Read LDAP responses from the server. */
static void on_query_readable(verto_ctx *vctx, verto_ev *ev)
{
    struct otpd_queue *push = &ctx.stdio.responses;
    verto_ev *event = ctx.stdio.writer;
    LDAPMessage *results, *entry;
    struct otpd_queue_item *item = NULL;
    const char *err;
    LDAP *ldp;
    int i;
    (void)vctx;
    enum oauth2_state oauth2_state;

    ldp = verto_get_private(ev);

    i = ldap_result(ldp, LDAP_RES_ANY, 0, NULL, &results);
    if (i != LDAP_RES_SEARCH_ENTRY && i != LDAP_RES_SEARCH_RESULT) {
        if (i <= 0)
            results = NULL;
        ldap_msgfree(results);
        otpd_log_err(EIO, "IO error received on query socket");
        verto_break(ctx.vctx);
        ctx.exitstatus = 1;
        return;
    }

    item = otpd_queue_pop_msgid(&ctx.query.responses, ldap_msgid(results));
    if (item == NULL)
        goto egress;

    if (i == LDAP_RES_SEARCH_ENTRY) {
        entry = ldap_first_entry(ldp, results);
        if (entry == NULL)
            goto egress;

        err = NULL;
        switch (item->ldap_query) {
        case LDAP_QUERY_USER:
            err = otpd_parse_user(ldp, entry, item);
            break;
        case LDAP_QUERY_RADIUS:
            err = otpd_parse_radius(ldp, entry, item);
            break;
        case LDAP_QUERY_RADIUS_USERMAP:
            err = otpd_parse_radius_username(ldp, entry, item);
            break;
        case LDAP_QUERY_IDP:
            err = otpd_parse_idp(ldp, entry, item);
            break;
        case LDAP_QUERY_PASSKEY:
            err = otpd_parse_passkey(ldp, entry, item);
            break;
        default:
            ldap_msgfree(entry);
            goto egress;
        }

        ldap_msgfree(entry);

        if (err != NULL) {
            if (item->error != NULL)
                free(item->error);
            item->error = strdup(err);
            if (item->error == NULL)
                goto egress;
        }

        otpd_queue_push_head(&ctx.query.responses, item);
        return;
    }

    item->msgid = -1;

    switch (item->ldap_query) {
    case LDAP_QUERY_USER:
        otpd_log_req(item->req, "user query end: %s",
                item->error == NULL ? item->user.dn : item->error);
        if (item->user.dn == NULL || item->user.uid == NULL)
            goto egress;
        break;
    case LDAP_QUERY_RADIUS:
        otpd_log_req(item->req, "radius query end: %s",
                item->error == NULL
                    ? item->radius.ipatokenRadiusServer
                    : item->error);
        if (item->radius.ipatokenRadiusServer == NULL ||
            item->radius.ipatokenRadiusSecret == NULL)
            goto egress;
        break;
    case LDAP_QUERY_RADIUS_USERMAP:
        otpd_log_req(item->req, "username query end: %s",
                item->error == NULL ? item->user.other : item->error);
        break;
    case LDAP_QUERY_IDP:
        otpd_log_req(item->req, "idp query end: %s",
                item->error == NULL ? item->idp.name : item->error);
        if (!item->idp.valid) {
            goto egress;
        }
        break;
    case LDAP_QUERY_PASSKEY:
        otpd_log_req(item->req, "passkey query end: %s",
                item->error == NULL ? "ok" : item->error);
        if (item->passkey == NULL) {
            goto egress;
        }
        break;
    default:
        goto egress;
    }

    /* Check for passkey */
    if (is_passkey(item)) {
        if (item->ldap_query == LDAP_QUERY_USER) {
            item->get_passkey_config = true;

            push = &ctx.query.requests;
            event = ctx.query.io;
            goto egress;
        }

        i = do_passkey(item);
        if (i != 0) {
            goto egress;
        }
        /* do_passkey will call ctx.stdio.writer, so we can return here */
        return;
    }

    /* Check for oauth2 */
    oauth2_state = get_oauth2_state(item->ldap_query, item);
    if (oauth2_state == OAUTH2_GET_ISSUER) {
        push = &ctx.query.requests;
        event = ctx.query.io;
        goto egress;
    } else if (oauth2_state != OAUTH2_NO) {
        i = oauth2(&item, oauth2_state);
        if (i != 0) {
            goto egress;
        } else {
            /* oauth2 will call ctx.stdio.writer, so we can return here */
            return;
        }
    }

    if (item->error != NULL)
        goto egress;

    if (item->ldap_query == LDAP_QUERY_USER &&
        item->user.ipatokenRadiusConfigLink != NULL) {

        push = &ctx.query.requests;
        event = ctx.query.io;
        goto egress;
    } else if (item->ldap_query == LDAP_QUERY_RADIUS &&
               item->radius.ipatokenUserMapAttribute != NULL &&
               item->user.ipatokenRadiusUserName == NULL) {
        push = &ctx.query.requests;
        event = ctx.query.io;
        goto egress;
    }

    /* Forward to RADIUS if necessary. */
    i = otpd_forward(&item);
    if (i != 0)
        goto egress;

    push = &ctx.bind.requests;
    event = ctx.bind.io;

egress:
    ldap_msgfree(results);
    otpd_queue_push(push, item);

    if (item != NULL)
        verto_set_flags(event, VERTO_EV_FLAG_PERSIST |
                               VERTO_EV_FLAG_IO_ERROR |
                               VERTO_EV_FLAG_IO_READ |
                               VERTO_EV_FLAG_IO_WRITE);
}

/* Handle the reading/writing of LDAP query requests asynchronously. */
void otpd_on_query_io(verto_ctx *vctx, verto_ev *ev)
{
    verto_ev_flag flags;

    flags = verto_get_fd_state(ev);
    if (flags & VERTO_EV_FLAG_IO_WRITE)
        on_query_writable(vctx, ev);
    if (flags & (VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_IO_ERROR))
        on_query_readable(vctx, ev);
}
