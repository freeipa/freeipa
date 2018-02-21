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

#include <ldap.h>

#define DEFAULT_CA_CERT_FILE "/etc/ipa/ca.crt"

#define LDAP_SASL_EXTERNAL "EXTERNAL"
#define LDAP_SASL_GSSAPI "GSSAPI"

#define SCHEMA_LDAPI "ldapi://"
#define SCHEMA_LDAP "ldap://"
#define SCHEMA_LDAPS "ldaps://"

#ifndef _
#include <libintl.h>
#define _(STRING) gettext(STRING)
#endif

int ipa_ldap_init(LDAP **ld, const char *ldap_uri);
int ipa_tls_ssl_init(LDAP *ld, const char *ldap_uri,
                     const char *ca_cert_file);
