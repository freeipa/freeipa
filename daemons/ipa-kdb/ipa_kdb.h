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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <kdb.h>
#include <ldap.h>
#include <time.h>

struct ipadb_context {
    char *uri;
    char *base;
    char *realm;
    char *realm_base;
    LDAP *lcontext;
    krb5_context kcontext;
    krb5_key_salt_tuple *supp_encs;
    int n_supp_encs;
};

struct ipadb_context *ipadb_get_context(krb5_context kcontext);
int ipadb_get_connection(struct ipadb_context *ipactx);
