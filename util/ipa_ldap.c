/* Authors: Christian Heimes <cheimes@redhat.com>
 *          Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2018  Red Hat
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

#define _GNU_SOURCE

#include <stdio.h>

#include "ipa_ldap.h"

/** Initialize LDAP context
 *
 * Initializes an LDAP context for a given LDAP URI. LDAP protocol version
 * and SASL canonization are disabled.
 *
 */
int ipa_ldap_init(LDAP **ld, const char *ldap_uri)
{
    int ret = 0;
    int version = LDAP_VERSION3;
    ret = ldap_initialize(ld, ldap_uri);

    if (ret != LDAP_SUCCESS) {
        fprintf(
            stderr,
            _("Unable to initialize connection to ldap server %1$s: %2$s\n"),
            ldap_uri,
            ldap_err2string(ret)
        );
        return ret;
    }

    /* StartTLS and other features need LDAP protocol version 3 */
    ret = ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (ret != LDAP_SUCCESS) {
        fprintf(stderr, _("Unable to set LDAP_OPT_PROTOCOL_VERSION\n"));
        return ret;
    }

#ifdef LDAP_OPT_X_SASL_NOCANON
    /* Don't do DNS canonization */
    ret = ldap_set_option(*ld, LDAP_OPT_X_SASL_NOCANON, LDAP_OPT_ON);
    if (ret != LDAP_SUCCESS) {
        fprintf(stderr, _("Unable to set LDAP_OPT_X_SASL_NOCANON\n"));
        return ret;
    }
#endif

    return ret;
}

/** Configure TLS/SSL and perform StartTLS for ldap://
 *
 * The LDAP connection is configured for secure TLS.
 *
 */
int ipa_tls_ssl_init(LDAP *ld, const char *ldap_uri,
                     const char *ca_cert_file)
{
    int ret = LDAP_SUCCESS;
    int tls_demand = LDAP_OPT_X_TLS_DEMAND;
    int tlsv1_0 = LDAP_OPT_X_TLS_PROTOCOL_TLS1_0;
    int newctx = 0;  /* client context */

    if (strncmp(ldap_uri, SCHEMA_LDAPI, sizeof(SCHEMA_LDAPI) - 1) == 0) {
        /* Nothing to do for LDAPI */
        return ret;
    }

    ret = ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, ca_cert_file);
    if (ret != LDAP_OPT_SUCCESS) {
        fprintf(stderr, _("Unable to set LDAP_OPT_X_TLS_CACERTFILE\n"));
        return ret;
    }
    /* Require a valid certificate */
    ret = ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &tls_demand);
    if (ret != LDAP_OPT_SUCCESS) {
        fprintf(stderr, _("Unable to set LDAP_OPT_X_TLS_REQUIRE_CERT\n"));
        return ret;
    }
    /* Disable SSLv2 and SSLv3 */
    ret = ldap_set_option(ld, LDAP_OPT_X_TLS_PROTOCOL_MIN, &tlsv1_0);
    if (ret != LDAP_OPT_SUCCESS) {
        fprintf(stderr, _("Unable to set LDAP_OPT_X_TLS_PROTOCOL_MIN\n"));
        return ret;
    }
    /* Apply TLS settings and create new client context */
    ret = ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &newctx);
    if (ret != LDAP_OPT_SUCCESS) {
        fprintf(stderr, _("Unable to set LDAP_OPT_X_TLS_NEWCTX\n"));
        return ret;
    }

    if (strncmp(ldap_uri, SCHEMA_LDAP, sizeof(SCHEMA_LDAP) - 1) == 0) {
        ret = ldap_start_tls_s(ld, NULL, NULL);
        if (ret != LDAP_SUCCESS) {
            fprintf(stderr, _("Unable to initialize STARTTLS session\n"));
            return ret;
        }
    }
    return ret;
}
