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

/**
 * The purpose of this plugin is to ensure that counter/watermark values:
 * 1. Have atomic operations.
 * 2. Never go backwards.
 * 3. Never get deleted.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "berval.h"
#include "ldapmod.h"
#include "util.h"

#include <limits.h>

#include <plstr.h>

#define COUNTER_UNSET LLONG_MIN

static void *plugin_id;

static long long
get_counter(Slapi_Entry *entry, const char *attr)
{
    Slapi_Attr *sattr = NULL;

    if (slapi_entry_attr_find(entry, attr, &sattr) == 0)
        return slapi_entry_attr_get_longlong(entry, attr);

    return COUNTER_UNSET;
}

/**
 * Determines the name of the counter or watermark attribute based
 * upon the objectClass of the entry.
 *
 * If no match is found, this function returns NULL indicating that
 * this entry is not a known token type.
 */
static const char *
find_counter_name(Slapi_Entry *entry)
{
    static struct {
        const char *clss;
        const char *attr;
    } table[] = {
        { "ipatokenHOTP", "ipatokenHOTPcounter" },
        { "ipatokenTOTP", "ipatokenTOTPwatermark" },
        { NULL, NULL }
    };

    const char *attr = NULL;
    char **clsses = NULL;

    clsses = slapi_entry_attr_get_charray(entry, "objectClass");
    if (clsses == NULL)
        return NULL;

    for (size_t i = 0; attr == NULL && clsses[i] != NULL; i++) {
        for (size_t j = 0; attr == NULL && table[j].clss != NULL; j++) {
            if (PL_strcasecmp(table[j].clss, clsses[i]) == 0)
                attr = table[j].attr;
        }
    }

    slapi_ch_array_free(clsses);
    return attr;
}

/**
 * Normalizes the input values of counter/watermark modifications.
 *
 * 1. All INCREMENT and REPLACE operations need to be replace by
 *    equivalent DELETE/ADD combination operations. This ensures
 *    atomicity.
 *
 * 2. Any incoming DELETE operations need to be sanity checked.
 *
 *    If no value is specified, the current counter value is added
 *    to the operation. Without this, we cannot guarantee that the
 *    operation will not causes a decrement.
 *
 * This function returns the size of the new LDAPMod* array or zero
 * if there are no counter/watermark operations.
 */
static size_t
normalize_input(LDAPMod ***mods, const char *attr, long long ctr)
{
    LDAPMod **tmp;
    size_t o; /* Counts the number of operations. */
    size_t c; /* Counts the number of counter operations. */
    size_t e; /* Counts the number of expansions. */

    /* Get the size of the mods when all expansions are performed. */
    for (o = c = e = 0; (*mods)[o] != NULL; o++) {
        if (PL_strcasecmp((*mods)[o]->mod_type, attr) != 0)
            continue;

        switch ((*mods)[o]->mod_op & LDAP_MOD_OP) {
        case LDAP_MOD_REPLACE:
        case LDAP_MOD_INCREMENT:
            e++;
            /* fall through */
        default:
            c++;
        }
    }

    if (c == 0)
        return 0;

    /* Filter the modify operations. */
    tmp = (LDAPMod **) slapi_ch_calloc(o + e + 1, sizeof(LDAPMod*));
    for (size_t i = 0, j = 0; (*mods)[i] != NULL; tmp[j++] = (*mods)[i++]) {
        LDAPMod *mod = (*mods)[i];

        if (PL_strcasecmp(mod->mod_type, attr) != 0)
            continue;

        /* This is not strictly needed, but simplifies the code. */
        ldapmod_convert_bvalues(mod);

        switch (mod->mod_op & LDAP_MOD_OP) {
        case LDAP_MOD_DELETE:
            /* Normalize input: if an empty array is allocated, free it. */
            if (mod->mod_bvalues != NULL && mod->mod_bvalues[0] == NULL)
                bervals_free(&mod->mod_bvalues);

            if (mod->mod_bvalues == NULL)
                mod->mod_bvalues = bervals_new_longlong(ctr);

            ctr = COUNTER_UNSET;
            break;

        case LDAP_MOD_INCREMENT:
            if (ctr != COUNTER_UNSET)
                tmp[j++] = ldapmod_new_longlong(LDAP_MOD_DELETE, attr, ctr);

            ctr += ldapmod_get_value(mod, 1);

            bervals_free(&mod->mod_bvalues);
            mod->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
            mod->mod_bvalues = bervals_new_longlong(ctr);
            break;

        case LDAP_MOD_REPLACE:
            if (ctr != COUNTER_UNSET)
                tmp[j++] = ldapmod_new_longlong(LDAP_MOD_DELETE, attr, ctr);

            mod->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;

            /* Fall through. */

        case LDAP_MOD_ADD:
            ctr = ldapmod_get_value(mod, 0);
            break;
        }
    }

    slapi_ch_free((void **) mods);
    *mods = tmp;
    return o + e;
}

/**
 * Simulates how the specified mods will impact the counter.
 */
static bool
simulate(LDAPMod **mods, const char *attr, long long ctr, long long *out)
{
    bool success = true;

    for (size_t i = 0; mods[i] != NULL; i++) {
        if (PL_strcasecmp(mods[i]->mod_type, attr) != 0)
            continue;

        switch (mods[i]->mod_op & LDAP_MOD_OP) {
        case LDAP_MOD_DELETE:
            if (ctr == COUNTER_UNSET)
                success = false;

            ctr = COUNTER_UNSET;
            break;

        case LDAP_MOD_INCREMENT:
            if (ctr == COUNTER_UNSET)
                success = false;

            ctr = ldapmod_get_value(mods[i], ctr + 1);
            break;

        case LDAP_MOD_ADD:
            if (ctr != COUNTER_UNSET)
                success = false;

            /* Fall through. */

        case LDAP_MOD_REPLACE:
            ctr = ldapmod_get_value(mods[i], 0);
            break;
        }
    }

    *out = ctr;
    return success;
}

/**
 * Modifies input to ensure correct counter behavior.
 *
 * For non-replication operations, we change all REPLACE and INCREMENT
 * operations into DELETE/ADD pair operations. We also sanity check
 * incoming DELETE operations. If the request would cause the counter to
 * decrement or delete, fail the operation.
 *
 * For replication operations, if the transaction would decrement the
 * counter, delete it or modify it to the same value, we remove all mods
 * related to the counter and let the replication request continue. In
 * the first two cases, this enforces correct behavior. In the last case,
 * this reduces write contention on the counter when a replica-set-wide
 * authentication collision has occurred.
 */
static int
preop_mod(Slapi_PBlock *pb)
{
    Slapi_Entry *epre = NULL;
    const char *attr = NULL;
    LDAPMod **mods = NULL;
    char *msg = NULL;
    long long cpost;
    long long cpre;
    int repl = 0;
    int rc = 0;

    rc |= slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &repl);
    rc |= slapi_pblock_get(pb, SLAPI_ENTRY_PRE_OP, &epre);
    rc |= slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
    if (rc != 0 || epre == NULL || mods == NULL)
        return 0;

    attr = find_counter_name(epre);
    if (attr == NULL)
        return 0; /* Not a token. */

    cpre = get_counter(epre, attr);

    if (repl == 0) {
        if (normalize_input(&mods, attr, cpre) != 0) {
            if (slapi_pblock_set(pb, SLAPI_MODIFY_MODS, mods)) {
                LOG_FATAL("slapi_pblock_set failed!\n");
                goto error;
            }
        }
    }

    if (!simulate(mods, attr, cpre, &cpost) && repl == 0) {
        msg = slapi_ch_smprintf("Invalid operation sequence on %s", attr);
        goto error;
    }

    if (cpost < cpre) {
        if (repl == 0) {
            msg = slapi_ch_smprintf("Will not %s %s",
                cpost == COUNTER_UNSET ? "delete" : "decrement", attr);
            goto error;
        }

        /* Remove counter attribute modifications. */
        for (size_t i = 0, j = 0 ; ; i++, j++) {
            mods[j] = mods[i];
            if (mods[j] == NULL)
                break;

            if (PL_strcasecmp(mods[j]->mod_type, attr) == 0)
                ldapmod_free(&mods[j--]);
        }
    }

    return 0;

error:
    rc = LDAP_UNWILLING_TO_PERFORM;
    slapi_send_ldap_result(pb, rc, NULL, msg, 0, NULL);
    if (slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc)) {
        LOG_FATAL("slapi_pblock_set failed!\n");
    }

    slapi_ch_free_string(&msg);
    return rc;
}

static void
writeback(Slapi_Entry *entry, const char *attr,
          long long cold, long long cnew)
{
    Slapi_PBlock *pb = NULL;
    char dbuf[32];
    char abuf[32];

    LDAPMod *mods[] = {
        &(LDAPMod) {
            LDAP_MOD_DELETE, (char *) attr,
            .mod_values = (char *[]) { dbuf, NULL }
        },
        &(LDAPMod) {
            LDAP_MOD_ADD, (char *) attr,
            .mod_values = (char *[]) { abuf, NULL }
        },
        NULL
    };

    snprintf(dbuf, sizeof(dbuf), "%lld", cold);
    snprintf(abuf, sizeof(abuf), "%lld", cnew);

    pb = slapi_pblock_new();
    slapi_modify_internal_set_pb(pb, slapi_entry_get_dn_const(entry),
                                 mods, NULL, NULL, plugin_id, 0);
    slapi_modify_internal_pb(pb);
    slapi_pblock_destroy(pb);
}

/**
 * Ensures replications receive the highest value seen.
 *
 * A replication request that arrives at the server may be internally
 * discarded, even if it has a higher counter value, because of a lower
 * CSN. However, we always want to record the highest value seen.
 *
 * We solve this problem by checking the value of the replication request
 * against the value of the entry after the replication. If the replication
 * request contained a higher value than what the entry contains, we create
 * a new modification to bump up the counter to the highest value.
 *
 * This check is only for replication operations.
 */
static int
postop_mod(Slapi_PBlock *pb)
{
    Slapi_Entry *epost = NULL;
    Slapi_Entry *epre = NULL;
    const char *attr = NULL;
    LDAPMod **mods = NULL;
    long long cpost;
    long long cpre;
    long long csim;
    int repl = 0;
    int rc = 0;

    rc |= slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &repl);
    rc |= slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &epost);
    rc |= slapi_pblock_get(pb, SLAPI_ENTRY_PRE_OP, &epre);
    rc |= slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
    if (rc != 0 || epost == NULL || epre == NULL || mods == NULL)
        return 0;

    if (repl == 0)
        return 0;

    attr = find_counter_name(epost);
    if (attr == NULL)
        return 0; /* Not a token. */

    cpost = get_counter(epost, attr);
    cpre = get_counter(epre, attr);

    if (simulate(mods, attr, cpre, &csim) && csim > cpost)
        writeback(epost, attr, cpost, csim);

    return 0;
}

static int
preop_init(Slapi_PBlock *pb)
{
    return slapi_pblock_set(pb, SLAPI_PLUGIN_BE_PRE_MODIFY_FN, preop_mod);
}

static int
postop_init(Slapi_PBlock *pb)
{
    return slapi_pblock_set(pb, SLAPI_PLUGIN_BE_POST_MODIFY_FN, postop_mod);
}

static int
start_fn(Slapi_PBlock *pb)
{
    return 0;
}

static int
close_fn(Slapi_PBlock *pb)
{
    return 0;
}

int
ipa_otp_counter_init(Slapi_PBlock *pb)
{
    static const Slapi_PluginDesc desc = {
        "ipa-otp-counter",
        "FreeIPA",
        "FreeIPA/1.0",
        "Ensure proper OTP token counter operation"
    };

    int ret = 0;

    ret |= slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_id);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *) &desc);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, start_fn);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN, close_fn);
    ret |= slapi_register_plugin("bepreoperation", 1, __func__, preop_init,
                                 "ipa-otp-counter bepreoperation", NULL,
                                 plugin_id);
    ret |= slapi_register_plugin("bepostoperation", 1, __func__, postop_init,
                                 "ipa-otp-counter bepostoperation", NULL,
                                 plugin_id);

    return ret;
}
