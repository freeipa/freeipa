/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
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
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "ldapmod.h"
#include "berval.h"

#include <limits.h>

long long
ldapmod_get_value(const LDAPMod *mod, long long def)
{
    long long v;

    if (mod == NULL)
        return def;

    if (mod->mod_bvalues == NULL)
        return def;

    if (mod->mod_bvalues[0] == NULL)
        return def;

    v = berval_to_longlong(mod->mod_bvalues[0]);
    if (v == LLONG_MIN || v == LLONG_MAX)
        return def;

    return v;
}

LDAPMod *
ldapmod_new_longlong(int op, const char *attr, long long value)
{
    LDAPMod *mod;

    mod = (LDAPMod*) slapi_ch_malloc(sizeof(LDAPMod));
    mod->mod_op = op | LDAP_MOD_BVALUES;
    mod->mod_type = slapi_ch_strdup(attr);
    mod->mod_bvalues = bervals_new_longlong(value);

    return mod;
}

void
ldapmod_convert_bvalues(LDAPMod *mod)
{
    if (mod == NULL || (mod->mod_op & LDAP_MOD_BVALUES))
        return;

    mod->mod_op |= LDAP_MOD_BVALUES;

    if (mod->mod_values == NULL) {
        mod->mod_bvalues = NULL;
        return;
    }

    for (size_t i = 0; mod->mod_values[i] != NULL; i++) {
        struct berval *bv;
        bv = (struct berval*) slapi_ch_malloc(sizeof(struct berval));
        bv->bv_val = mod->mod_values[i];
        bv->bv_len = strlen(bv->bv_val);
        mod->mod_bvalues[i] = bv;
    }
}

void
ldapmod_free(LDAPMod **mod)
{
    if (mod == NULL || *mod == NULL)
        return;

    bervals_free(&(*mod)->mod_bvalues);
    slapi_ch_free_string(&(*mod)->mod_type);
    slapi_ch_free((void **) mod);
}
