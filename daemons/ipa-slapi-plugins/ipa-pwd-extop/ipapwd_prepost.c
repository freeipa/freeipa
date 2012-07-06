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
 * Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2007-2010 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

/* strptime needs _XOPEN_SOURCE and endian.h needs __USE_BSD
 * _GNU_SOURCE imply both, and we use it elsewhere, so use this */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <dirsrv/slapi-plugin.h>
#include <lber.h>
#include <time.h>
#include <endian.h>

#include "ipapwd.h"
#include "util.h"

#define IPAPWD_OP_NULL 0
#define IPAPWD_OP_ADD 1
#define IPAPWD_OP_MOD 2

extern Slapi_PluginDesc ipapwd_plugin_desc;
extern void *ipapwd_plugin_id;
extern const char *ipa_realm_tree;

/* structure with information for each extension */
struct ipapwd_op_ext {
    char *object_name;   /* name of the object extended   */
    int object_type;     /* handle to the extended object */
    int handle;          /* extension handle              */
};
/*****************************************************************************
 * pre/post operations to intercept writes to userPassword
 ****************************************************************************/
static struct ipapwd_op_ext ipapwd_op_ext_list;

static void *ipapwd_op_ext_constructor(void *object, void *parent)
{
    struct ipapwd_operation *ext;

    ext = (struct ipapwd_operation *)slapi_ch_calloc(1, sizeof(struct ipapwd_operation));
    return ext;
}

static void ipapwd_op_ext_destructor(void *ext, void *object, void *parent)
{
    struct ipapwd_operation *pwdop = (struct ipapwd_operation *)ext;
    if (!pwdop)
        return;
    if (pwdop->pwd_op != IPAPWD_OP_NULL) {
        slapi_ch_free_string(&(pwdop->pwdata.dn));
        slapi_ch_free_string(&(pwdop->pwdata.password));
    }
    slapi_ch_free((void **)&pwdop);
}

int ipapwd_ext_init(void)
{
    int ret;

    ipapwd_op_ext_list.object_name = SLAPI_EXT_OPERATION;

    ret = slapi_register_object_extension(IPAPWD_PLUGIN_NAME,
                                          SLAPI_EXT_OPERATION,
                                          ipapwd_op_ext_constructor,
                                          ipapwd_op_ext_destructor,
                                          &ipapwd_op_ext_list.object_type,
                                          &ipapwd_op_ext_list.handle);

    return ret;
}


static char *ipapwd_getIpaConfigAttr(const char *attr)
{
    /* check if migrtion is enabled */
    Slapi_Entry *entry = NULL;
    const char *attrs_list[] = {attr, 0};
    char *value = NULL;
    char *dn = NULL;
    int ret;

    dn = slapi_ch_smprintf("cn=ipaconfig,cn=etc,%s", ipa_realm_tree);
    if (!dn) {
        LOG_OOM();
        goto done;
    }

    ret = ipapwd_getEntry(dn, &entry, (char **) attrs_list);
    if (ret) {
        LOG("failed to retrieve config entry: %s\n", dn);
        goto done;
    }

    value = slapi_entry_attr_get_charptr(entry, attr);

done:
    slapi_entry_free(entry);
    slapi_ch_free_string(&dn);
    return value;
}


/* PRE ADD Operation:
 * Gets the clean text password (fail the operation if the password came
 * pre-hashed, unless this is a replicated operation or migration mode is
 * enabled).
 * Check user is authorized to add it otherwise just returns, operation will
 * fail later anyway.
 * Run a password policy check.
 * Check if krb or smb hashes are required by testing if the krb or smb
 * objectclasses are present.
 * store information for the post operation
 */
static int ipapwd_pre_add(Slapi_PBlock *pb)
{
    struct ipapwd_krbcfg *krbcfg = NULL;
    char *errMesg = "Internal operations error\n";
    struct slapi_entry *e = NULL;
    char *userpw = NULL;
    char *dn = NULL;
    struct ipapwd_operation *pwdop = NULL;
    void *op;
    int is_repl_op, is_root, is_krb, is_smb, is_ipant;
    int ret;
    int rc = LDAP_SUCCESS;

    LOG_TRACE("=>\n");

    ret = slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &is_repl_op);
    if (ret != 0) {
        LOG_FATAL("slapi_pblock_get failed!?\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* pass through if this is a replicated operation */
    if (is_repl_op)
        return 0;

    /* retrieve the entry */
    slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &e);
    if (NULL == e)
        return 0;

    /* check this is something interesting for us first */
    userpw = slapi_entry_attr_get_charptr(e, SLAPI_USERPWD_ATTR);
    if (!userpw) {
	/* nothing interesting here */
	return 0;
    }

    /* Ok this is interesting,
     * Check this is a clear text password, or refuse operation */
    if ('{' == userpw[0]) {
        if (0 == strncasecmp(userpw, "{CLEAR}", strlen("{CLEAR}"))) {
            char *tmp = slapi_ch_strdup(&userpw[strlen("{CLEAR}")]);
            if (NULL == tmp) {
                LOG_OOM();
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }
            slapi_ch_free_string(&userpw);
            userpw = tmp;
        } else if (slapi_is_encoded(userpw)) {
            /* check if we have access to the unhashed user password */
            char *userpw_clear =
                slapi_entry_attr_get_charptr(e, "unhashed#user#password");

            /* unhashed#user#password doesn't always contain the clear text
             * password, therefore we need to check if its value isn't the same
             * as userPassword to make sure */
            if (!userpw_clear || (0 == strcmp(userpw, userpw_clear))) {
                rc = LDAP_CONSTRAINT_VIOLATION;
                slapi_ch_free_string(&userpw);
            } else {
                userpw = slapi_ch_strdup(userpw_clear);
            }

            slapi_ch_free_string(&userpw_clear);

            if (rc != LDAP_SUCCESS) {
                /* we don't have access to the clear text password;
                 * let it slide if migration is enabled, but don't
                 * generate kerberos keys */
                char *enabled = ipapwd_getIpaConfigAttr("ipamigrationenabled");
                if (NULL == enabled) {
                    LOG("no ipaMigrationEnabled in config, assuming FALSE\n");
                } else if (0 == strcmp(enabled, "TRUE")) {
                    return 0;
                }

                LOG("pre-hashed passwords are not valid\n");
                errMesg = "pre-hashed passwords are not valid\n";
                goto done;
            }
        }
    }

    rc = ipapwd_entry_checks(pb, e,
                             &is_root, &is_krb, &is_smb, &is_ipant,
                             NULL, SLAPI_ACL_ADD);
    if (rc != LDAP_SUCCESS) {
        goto done;
    }

    rc = ipapwd_gen_checks(pb, &errMesg, &krbcfg, IPAPWD_CHECK_DN);
    if (rc != LDAP_SUCCESS) {
        goto done;
    }

    /* Get target DN */
    ret = slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn);
    if (ret) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* time to get the operation handler */
    ret = slapi_pblock_get(pb, SLAPI_OPERATION, &op);
    if (ret != 0) {
        LOG_FATAL("slapi_pblock_get failed!?\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    pwdop = slapi_get_object_extension(ipapwd_op_ext_list.object_type,
                                       op, ipapwd_op_ext_list.handle);
    if (NULL == pwdop) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    pwdop->pwd_op = IPAPWD_OP_ADD;
    pwdop->pwdata.password = slapi_ch_strdup(userpw);

    if (is_root) {
        pwdop->pwdata.changetype = IPA_CHANGETYPE_DSMGR;
    } else {
        char *binddn;
        int i;

        pwdop->pwdata.changetype = IPA_CHANGETYPE_ADMIN;

        /* Check Bind DN */
        slapi_pblock_get(pb, SLAPI_CONN_DN, &binddn);

        /* if it is a passsync manager we also need to skip resets */
        for (i = 0; i < krbcfg->num_passsync_mgrs; i++) {
            if (strcasecmp(krbcfg->passsync_mgrs[i], binddn) == 0) {
                pwdop->pwdata.changetype = IPA_CHANGETYPE_DSMGR;
                break;
            }
        }
    }

    pwdop->pwdata.dn = slapi_ch_strdup(dn);
    pwdop->pwdata.timeNow = time(NULL);
    pwdop->pwdata.target = e;

    ret = ipapwd_CheckPolicy(&pwdop->pwdata);
    if (ret) {
        errMesg = ipapwd_error2string(ret);
        rc = LDAP_CONSTRAINT_VIOLATION;
        goto done;
    }

    if (is_krb || is_smb || is_ipant) {

        Slapi_Value **svals = NULL;
        Slapi_Value **ntvals = NULL;
        char *nt = NULL;
        char *lm = NULL;

        pwdop->is_krb = is_krb;

        rc = ipapwd_gen_hashes(krbcfg, &pwdop->pwdata,
                               userpw, is_krb, is_smb, is_ipant,
                               &svals, &nt, &lm, &ntvals, &errMesg);
        if (rc != LDAP_SUCCESS) {
            goto done;
        }

        if (svals) {
            /* add/replace values in existing entry */
            ret = slapi_entry_attr_replace_sv(e, "krbPrincipalKey", svals);
            if (ret) {
                LOG_FATAL("failed to set encoded values in entry\n");
                rc = LDAP_OPERATIONS_ERROR;
                ipapwd_free_slapi_value_array(&svals);
                goto done;
            }

            ipapwd_free_slapi_value_array(&svals);
        }

        if (lm && is_smb) {
            /* set value */
            slapi_entry_attr_set_charptr(e, "sambaLMPassword", lm);
            slapi_ch_free_string(&lm);
        }
        if (nt && is_smb) {
            /* set value */
            slapi_entry_attr_set_charptr(e, "sambaNTPassword", nt);
            slapi_ch_free_string(&nt);
        }

        if (ntvals && is_ipant) {
            slapi_entry_attr_replace_sv(e, "ipaNTHash", ntvals);
            ipapwd_free_slapi_value_array(&ntvals);
        }

        if (is_smb) {
            /* with samba integration we need to also set sambaPwdLastSet or
             * samba will decide the user has to change the password again */
            if (pwdop->pwdata.changetype == IPA_CHANGETYPE_ADMIN) {
                /* if it is an admin change instead we need to let know to
                * samba as well that the use rmust change its password */
                slapi_entry_attr_set_long(e, "sambaPwdLastset", 0L);
            } else {
                slapi_entry_attr_set_long(e, "sambaPwdLastset",
                                      (long)pwdop->pwdata.timeNow);
            }
        }
    }

    rc = LDAP_SUCCESS;

done:
    if (pwdop) pwdop->pwdata.target = NULL;
    free_ipapwd_krbcfg(&krbcfg);
    slapi_ch_free_string(&userpw);
    if (rc != LDAP_SUCCESS) {
        slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);
        return -1;
    }
    return 0;
}

#define NTHASH_REGEN_VAL "MagicRegen"
#define NTHASH_REGEN_LEN sizeof(NTHASH_REGEN_VAL)
static int ipapwd_regen_nthash(Slapi_PBlock *pb, Slapi_Mods *smods,
                               char *dn, struct slapi_entry *entry,
                               struct ipapwd_krbcfg *krbcfg);

/* PRE MOD Operation:
 * Gets the clean text password (fail the operation if the password came
 * pre-hashed, unless this is a replicated operation).
 * Check user is authorized to add it otherwise just returns, operation will
 * fail later anyway.
 * Check if krb or smb hashes are required by testing if the krb or smb
 * objectclasses are present.
 * Run a password policy check.
 * store information for the post operation
 */
static int ipapwd_pre_mod(Slapi_PBlock *pb)
{
    struct ipapwd_krbcfg *krbcfg = NULL;
    char *errMesg = NULL;
    LDAPMod **mods;
    LDAPMod *lmod;
    Slapi_Mods *smods = NULL;
    char *userpw = NULL;
    char *unhashedpw = NULL;
    char *dn = NULL;
    Slapi_DN *tmp_dn;
    struct slapi_entry *e = NULL;
    struct ipapwd_operation *pwdop = NULL;
    void *op;
    int is_repl_op, is_pwd_op, is_root, is_krb, is_smb, is_ipant;
    int has_krb_keys = 0;
    int has_history = 0;
    int gen_krb_keys = 0;
    int is_magic_regen = 0;
    int ret, rc;

    LOG_TRACE( "=>\n");

    ret = slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &is_repl_op);
    if (ret != 0) {
        LOG_FATAL("slapi_pblock_get failed!?\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* pass through if this is a replicated operation */
    if (is_repl_op) {
        rc = LDAP_SUCCESS;
        goto done;
    }

    /* grab the mods - we'll put them back later with
     * our modifications appended
     */
    slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
    smods = slapi_mods_new();
    slapi_mods_init_passin(smods, mods);

    /* In the first pass,
     * only check there is anything we are interested in */
    is_pwd_op = 0;
    lmod = slapi_mods_get_first_mod(smods);
    while (lmod) {
        struct berval *bv;

        if (slapi_attr_types_equivalent(lmod->mod_type, SLAPI_USERPWD_ATTR)) {
            /* check op filtering out LDAP_MOD_BVALUES */
            switch (lmod->mod_op & 0x0f) {
            case LDAP_MOD_ADD:
            case LDAP_MOD_REPLACE:
                is_pwd_op = 1;
            default:
                break;
            }
        } else if (slapi_attr_types_equivalent(lmod->mod_type, "ipaNTHash")) {
            /* check op filtering out LDAP_MOD_BVALUES */
            switch (lmod->mod_op & 0x0f) {
            case LDAP_MOD_ADD:
                if (!lmod->mod_bvalues ||
                    !lmod->mod_bvalues[0]) {
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                bv = lmod->mod_bvalues[0];
                if ((bv->bv_len >= NTHASH_REGEN_LEN -1) &&
                    (bv->bv_len <= NTHASH_REGEN_LEN) &&
                    (strncmp(NTHASH_REGEN_VAL,
                             bv->bv_val, bv->bv_len) == 0)) {
                    is_magic_regen = 1;
                    /* make sure the database will later ignore this mod */
                    slapi_mods_remove(smods);
                }
            default:
                break;
            }
        } else if (slapi_attr_types_equivalent(lmod->mod_type,
                                                "unhashed#user#password")) {
            /* we check for unahsehd password here so that we are sure to
             * catch them early, before further checks go on, this helps
             * checking LDAP_MOD_DELETE operations in some corner cases later.
             * We keep only the last one if multiple are provided for any
             * reason */
            if (!lmod->mod_bvalues ||
                !lmod->mod_bvalues[0]) {
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }
            bv = lmod->mod_bvalues[0];
            slapi_ch_free_string(&unhashedpw);
            unhashedpw = slapi_ch_malloc(bv->bv_len+1);
            if (!unhashedpw) {
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }
            memcpy(unhashedpw, bv->bv_val, bv->bv_len);
            unhashedpw[bv->bv_len] = '\0';
        }
        lmod = slapi_mods_get_next_mod(smods);
    }

    /* If userPassword is not modified check if this is a request to generate
     * NT hashes otherwise we are done here */
    if (!is_pwd_op && !is_magic_regen) {
        rc = LDAP_SUCCESS;
        goto done;
    }

    /* OK we have something interesting here, start checking for
     * pre-requisites */

    /* Get target DN */
    ret = slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn);
    if (ret) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    tmp_dn = slapi_sdn_new_dn_byref(dn);
    if (tmp_dn) {
        /* xxxPAR: Ideally SLAPI_MODIFY_EXISTING_ENTRY should be
         * available but it turns out that is only true if you are
         * a dbm backend pre-op plugin - lucky dbm backend pre-op
         * plugins.
         * I think that is wrong since the entry is useful for filter
         * tests and schema checks and this plugin shouldn't be limited
         * to a single backend type, but I don't want that fight right
         * now so we go get the entry here
         *
         slapi_pblock_get( pb, SLAPI_MODIFY_EXISTING_ENTRY, &e);
         */
        ret = slapi_search_internal_get_entry(tmp_dn, 0, &e, ipapwd_plugin_id);
        slapi_sdn_free(&tmp_dn);
        if (ret != LDAP_SUCCESS) {
            LOG("Failed to retrieve entry?!\n");
           rc = LDAP_NO_SUCH_OBJECT;
           goto done;
        }
    }

    rc = ipapwd_entry_checks(pb, e,
                             &is_root, &is_krb, &is_smb, &is_ipant,
                             SLAPI_USERPWD_ATTR, SLAPI_ACL_WRITE);
    if (rc) {
        goto done;
    }

    rc = ipapwd_gen_checks(pb, &errMesg, &krbcfg, IPAPWD_CHECK_DN);
    if (rc) {
        goto done;
    }

    if (!is_pwd_op) {
        /* This may be a magic op to ask us to generate the NT hashes */
        if (is_magic_regen) {
            /* Make sense to call only if this entry has krb keys to source
             * the nthash from */
            if (is_krb) {
                rc = ipapwd_regen_nthash(pb, smods, dn, e, krbcfg);
            } else {
                rc = LDAP_UNWILLING_TO_PERFORM;
            }
        } else {
            rc = LDAP_OPERATIONS_ERROR;
        }
        goto done;
    }

    /* run through the mods again and adjust flags if operations affect them */
    lmod = slapi_mods_get_first_mod(smods);
    while (lmod) {
        struct berval *bv;

        if (slapi_attr_types_equivalent(lmod->mod_type, SLAPI_USERPWD_ATTR)) {
            /* check op filtering out LDAP_MOD_BVALUES */
            switch (lmod->mod_op & 0x0f) {
            case LDAP_MOD_ADD:
                /* FIXME: should we try to track cases where we would end up
                 * with multiple userPassword entries ?? */
            case LDAP_MOD_REPLACE:
                is_pwd_op = 1;
                if (!lmod->mod_bvalues ||
                    !lmod->mod_bvalues[0]) {
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                bv = lmod->mod_bvalues[0];
                slapi_ch_free_string(&userpw);
                userpw = slapi_ch_malloc(bv->bv_len+1);
                if (!userpw) {
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                memcpy(userpw, bv->bv_val, bv->bv_len);
                userpw[bv->bv_len] = '\0';
                break;
            case LDAP_MOD_DELETE:
                /* reset only if we are deleting all values, or the exact
                 * same value previously set, otherwise we are just trying to
                 * add a new value and delete an existing one */
                if (!lmod->mod_bvalues ||
                    !lmod->mod_bvalues[0]) {
                    is_pwd_op = 0;
                } else {
                    bv = lmod->mod_bvalues[0];
                    if ((userpw &&
                         strncmp(userpw, bv->bv_val, bv->bv_len) == 0) ||
                        (unhashedpw &&
                         strncmp(unhashedpw, bv->bv_val, bv->bv_len) == 0)) {
                        is_pwd_op = 0;
                    }
                }
            default:
                break;
            }

        } else if (slapi_attr_types_equivalent(lmod->mod_type,
                                                SLAPI_ATTR_OBJECTCLASS)) {
            int i;
            /* check op filtering out LDAP_MOD_BVALUES */
            switch (lmod->mod_op & 0x0f) {
            case LDAP_MOD_REPLACE:
                /* if objectclasses are replaced we need to start clean with
                 * flags, so we sero them out and see if they get set again */
                is_krb = 0;
                is_smb = 0;
                is_ipant = 0;

            case LDAP_MOD_ADD:
                if (!lmod->mod_bvalues ||
                    !lmod->mod_bvalues[0]) {
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                for (i = 0; (bv = lmod->mod_bvalues[i]) != NULL; i++) {
                    if (strncasecmp("krbPrincipalAux",
                                    bv->bv_val, bv->bv_len) == 0) {
                        is_krb = 1;
                    } else if (strncasecmp("sambaSamAccount",
                                           bv->bv_val, bv->bv_len) == 0) {
                        is_smb = 1;
                    } else if (strncasecmp("ipaNTUserAttrs",
                                           bv->bv_val, bv->bv_len) == 0) {
                        is_ipant = 1;
                    }
                }

                break;

            case LDAP_MOD_DELETE:
                /* can this happen for objectclasses ? */
                is_krb = 0;
                is_smb = 0;
                is_ipant = 0;

            default:
                break;
            }

        } else if (slapi_attr_types_equivalent(lmod->mod_type,
                                               "krbPrincipalKey")) {

            /* if we are getting a krbPrincipalKey, also avoid regenerating
             * the keys, it means kadmin has alredy done the job and is simply
             * keeping userPassword and sambaXXPAssword in sync */

            /* we also check we have enough authority */
            if (is_root) {
                has_krb_keys = 1;
            }

        } else if (slapi_attr_types_equivalent(lmod->mod_type,
                                               "passwordHistory")) {

            /* if we are getting a passwordHistory, also avoid regenerating
             * the hashes, it means kadmin has alredy done the job and is
             * simply keeping userPassword and sambaXXPAssword in sync */

            /* we also check we have enough authority */
            if (is_root) {
                has_history = 1;
            }
        }

        lmod = slapi_mods_get_next_mod(smods);
    }

    if (is_krb) {
        if (has_krb_keys) {
            gen_krb_keys = 0;
        } else {
            gen_krb_keys = 1;
        }
    }

    /* It seem like we have determined that the end result will be deletion of
     * the userPassword attribute, so we have no more business here */
    if (! is_pwd_op) {
        rc = LDAP_SUCCESS;
        goto done;
    }

    /* Check this is a clear text password, or refuse operation (only if we need
     * to comput other hashes */
    if (! unhashedpw && (gen_krb_keys || is_smb || is_ipant)) {
        if ('{' == userpw[0]) {
            if (0 == strncasecmp(userpw, "{CLEAR}", strlen("{CLEAR}"))) {
                unhashedpw = slapi_ch_strdup(&userpw[strlen("{CLEAR}")]);
                if (NULL == unhashedpw) {
                    LOG_OOM();
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                slapi_ch_free_string(&userpw);

            } else if (slapi_is_encoded(userpw)) {

                LOG("Pre-Encoded passwords are not valid\n");
                errMesg = "Pre-Encoded passwords are not valid\n";
                rc = LDAP_CONSTRAINT_VIOLATION;
                goto done;
            }
        }
    }

    /* time to get the operation handler */
    ret = slapi_pblock_get(pb, SLAPI_OPERATION, &op);
    if (ret != 0) {
        LOG_FATAL("slapi_pblock_get failed!?\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    pwdop = slapi_get_object_extension(ipapwd_op_ext_list.object_type,
                                       op, ipapwd_op_ext_list.handle);
    if (NULL == pwdop) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    pwdop->is_krb = is_krb;
    pwdop->pwd_op = IPAPWD_OP_MOD;
    pwdop->pwdata.password = slapi_ch_strdup(unhashedpw);
    pwdop->pwdata.changetype = IPA_CHANGETYPE_NORMAL;
    pwdop->skip_history = has_history;
    pwdop->skip_keys = has_krb_keys;

    if (is_root) {
        pwdop->pwdata.changetype = IPA_CHANGETYPE_DSMGR;
    } else {
        char *binddn;
        Slapi_DN *bdn, *tdn;
        int i;

        /* Check Bind DN */
        slapi_pblock_get(pb, SLAPI_CONN_DN, &binddn);
        bdn = slapi_sdn_new_dn_byref(binddn);
        tdn = slapi_sdn_new_dn_byref(dn);

        /* if the change is performed by someone else,
         * it is an admin change that will require a new
         * password change immediately as per our IPA policy */
        if (slapi_sdn_compare(bdn, tdn)) {
            pwdop->pwdata.changetype = IPA_CHANGETYPE_ADMIN;

            /* if it is a passsync manager we also need to skip resets */
            for (i = 0; i < krbcfg->num_passsync_mgrs; i++) {
                if (strcasecmp(krbcfg->passsync_mgrs[i], binddn) == 0) {
                    pwdop->pwdata.changetype = IPA_CHANGETYPE_DSMGR;
                    break;
                }
            }

        }

        slapi_sdn_free(&bdn);
        slapi_sdn_free(&tdn);

    }

    pwdop->pwdata.dn = slapi_ch_strdup(dn);
    pwdop->pwdata.timeNow = time(NULL);
    pwdop->pwdata.target = e;

    /* if krb keys are being set by an external agent we assume password
     * policies have been properly checked already, so we check them only
     * if no krb keys are available */
    if (has_krb_keys == 0) {
        ret = ipapwd_CheckPolicy(&pwdop->pwdata);
        if (ret) {
            errMesg = ipapwd_error2string(ret);
            rc = LDAP_CONSTRAINT_VIOLATION;
            goto done;
        }
    }

    if (gen_krb_keys || is_smb || is_ipant) {

        Slapi_Value **svals = NULL;
        Slapi_Value **ntvals = NULL;
        char *nt = NULL;
        char *lm = NULL;

        rc = ipapwd_gen_hashes(krbcfg, &pwdop->pwdata, unhashedpw,
                               gen_krb_keys, is_smb, is_ipant,
                               &svals, &nt, &lm, &ntvals, &errMesg);
        if (rc) {
            goto done;
        }

        if (svals) {
            /* replace values */
            slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                      "krbPrincipalKey", svals);
            ipapwd_free_slapi_value_array(&svals);
        }

        if (lm && is_smb) {
            /* replace value */
            slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                  "sambaLMPassword", lm);
            slapi_ch_free_string(&lm);
        }
        if (nt && is_smb) {
            /* replace value */
            slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                  "sambaNTPassword", nt);
            slapi_ch_free_string(&nt);
        }

        if (ntvals && is_ipant) {
            slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                      "ipaNTHash", ntvals);
            ipapwd_free_slapi_value_array(&ntvals);
        }

        if (is_smb) {
            /* with samba integration we need to also set sambaPwdLastSet or
             * samba will decide the user has to change the password again */
            if (pwdop->pwdata.changetype == IPA_CHANGETYPE_ADMIN) {
                /* if it is an admin change instead we need to let know to
                * samba as well that the use rmust change its password */
                slapi_entry_attr_set_long(e, "sambaPwdLastset", 0L);
            } else {
                slapi_entry_attr_set_long(e, "sambaPwdLastset",
                                      (long)pwdop->pwdata.timeNow);
            }
        }
    }

    rc = LDAP_SUCCESS;

done:
    free_ipapwd_krbcfg(&krbcfg);
    slapi_ch_free_string(&userpw); /* just to be sure */
    slapi_ch_free_string(&unhashedpw); /* we copied it to pwdop  */
    if (e) slapi_entry_free(e); /* this is a copy in this function */
    if (pwdop) pwdop->pwdata.target = NULL;

    /* put back a, possibly modified, set of mods */
    if (smods) {
        mods = slapi_mods_get_ldapmods_passout(smods);
        if (slapi_pblock_set(pb, SLAPI_MODIFY_MODS, mods)) {
            LOG_FATAL("slapi_pblock_set failed!\n");
            rc = LDAP_OPERATIONS_ERROR;
        }
        slapi_mods_free(&smods);
    }

    if (rc != LDAP_SUCCESS) {
        slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);
        return -1;
    }

    return 0;
}

static int ipapwd_regen_nthash(Slapi_PBlock *pb, Slapi_Mods *smods,
                               char *dn, struct slapi_entry *entry,
                               struct ipapwd_krbcfg *krbcfg)
{
    Slapi_Attr *attr;
    Slapi_Value *value;
    const struct berval *val;
    struct berval *ntvals[2] = { NULL, NULL };
    struct berval bval;
    krb5_key_data *keys;
    int num_keys;
    int mkvno;
    int ret;
    int i;

    ret = slapi_entry_attr_find(entry, "ipaNTHash", &attr);
    if (ret == 0) {
        /* We refuse to regen if there is already a value */
        return LDAP_CONSTRAINT_VIOLATION;
    }

    /* ok let's see if we can find the RC4 hash in the keys */
    ret = slapi_entry_attr_find(entry, "krbPrincipalKey", &attr);
    if (ret) {
        return LDAP_UNWILLING_TO_PERFORM;
    }

    ret = slapi_attr_first_value(attr, &value);
    if (ret) {
        return LDAP_OPERATIONS_ERROR;
    }

    val = slapi_value_get_berval(value);
    if (!val) {
        return LDAP_OPERATIONS_ERROR;
    }

    ret = ber_decode_krb5_key_data((struct berval *)val,
                                    &mkvno, &num_keys, &keys);
    if (ret) {
        return LDAP_OPERATIONS_ERROR;
    }

    ret = LDAP_UNWILLING_TO_PERFORM;

    for (i = 0; i < num_keys; i++) {
        char nthash[16];
        krb5_enc_data cipher;
        krb5_data plain;
        krb5_int16 t;

        if (keys[i].key_data_type[0] != ENCTYPE_ARCFOUR_HMAC) {
            continue;
        }

        memcpy(&t, keys[i].key_data_contents[0], 2);
        plain.length = le16toh(t);
        if (plain.length != 16) {
            continue;
        }
        plain.data = nthash;

        memset(&cipher, 0, sizeof(krb5_enc_data));
        cipher.enctype = krbcfg->kmkey->enctype;
        cipher.ciphertext.length = keys[i].key_data_length[0] - 2;
        cipher.ciphertext.data = ((char *)keys[i].key_data_contents[0]) + 2;

        ret = krb5_c_decrypt(krbcfg->krbctx, krbcfg->kmkey,
                             0, NULL, &cipher, &plain);
        if (ret) {
            ret = LDAP_OPERATIONS_ERROR;
            break;
        }

        bval.bv_val = nthash;
        bval.bv_len = 16;
        ntvals[0] = &bval;

        slapi_mods_add_modbvps(smods, LDAP_MOD_ADD, "ipaNTHash", ntvals);

        ret = LDAP_SUCCESS;
        break;
    }

    ipa_krb5_free_key_data(keys, num_keys);

    return ret;
}

static int ipapwd_post_op(Slapi_PBlock *pb)
{
    void *op;
    struct ipapwd_operation *pwdop = NULL;
    Slapi_Mods *smods;
    Slapi_Value **pwvals;
    struct tm utctime;
    char timestr[GENERALIZED_TIME_LENGTH+1];
    int ret;
    char *errMsg = "Internal operations error\n";
    struct ipapwd_krbcfg *krbcfg = NULL;
    char *principal = NULL;
    Slapi_Value *ipahost;

    LOG_TRACE("=>\n");

    /* time to get the operation handler */
    ret = slapi_pblock_get(pb, SLAPI_OPERATION, &op);
    if (ret != 0) {
        LOG_FATAL("slapi_pblock_get failed!?\n");
        return 0;
    }

    pwdop = slapi_get_object_extension(ipapwd_op_ext_list.object_type,
                                       op, ipapwd_op_ext_list.handle);
    if (NULL == pwdop) {
        LOG_FATAL("Internal error, couldn't find pluginextension ?!\n");
        return 0;
    }

    /* not interesting */
    if (IPAPWD_OP_NULL == pwdop->pwd_op)
        return 0;

    if ( ! (pwdop->is_krb)) {
        LOG("Not a kerberos user, ignore krb attributes\n");
        return 0;
    }

    if (pwdop->skip_keys && pwdop->skip_history) {
        /* nothing to do, caller already set all interesting attributes */
        return 0;
    }

    ret = ipapwd_gen_checks(pb, &errMsg, &krbcfg, 0);
    if (ret != 0) {
        LOG_FATAL("ipapwd_gen_checks failed!?\n");
        return 0;
    }

    /* prepare changes that can be made only as root */
    smods = slapi_mods_new();

    /* This was a mod operation on an existing entry, make sure we also update
     * the password history based on the entry we saved from the pre-op */
    if (IPAPWD_OP_MOD == pwdop->pwd_op && !pwdop->skip_history) {
        Slapi_DN *tmp_dn = slapi_sdn_new_dn_byref(pwdop->pwdata.dn);
        if (tmp_dn) {
            ret = slapi_search_internal_get_entry(tmp_dn, 0,
                                                  &pwdop->pwdata.target,
                                                  ipapwd_plugin_id);
            slapi_sdn_free(&tmp_dn);
            if (ret != LDAP_SUCCESS) {
                LOG("Failed to retrieve entry?!\n");
                goto done;
            }
        }
        pwvals = ipapwd_setPasswordHistory(smods, &pwdop->pwdata);
        if (pwvals) {
            slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                      "passwordHistory", pwvals);
        }
    }

    /* we assume that krb attributes are properly updated too if keys were
     * passed in */
    if (!pwdop->skip_keys) {
        /* Don't set a last password change or expiration on host passwords.
         * krbLastPwdChange is used to tell whether we have a valid keytab.
         * If we set it on userPassword it confuses enrollment.
         * If krbPasswordExpiration is set on a host entry then the keytab
         * will appear to be expired.
         *
         * When a host is issued a keytab these attributes get set properly by
         * ipapwd_setkeytab().
         */
        ipahost = slapi_value_new_string("ipaHost");
        if (!pwdop->pwdata.target ||
            (slapi_entry_attr_has_syntax_value(pwdop->pwdata.target,
                                    SLAPI_ATTR_OBJECTCLASS, ipahost)) == 0) {
            /* set Password Expiration date */
            if (!gmtime_r(&(pwdop->pwdata.expireTime), &utctime)) {
                LOG_FATAL("failed to parse expiration date (buggy gmtime_r ?)\n");
                goto done;
            }
            strftime(timestr, GENERALIZED_TIME_LENGTH+1,
                     "%Y%m%d%H%M%SZ", &utctime);
            slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                  "krbPasswordExpiration", timestr);

            /* change Last Password Change field with the current date */
            if (!gmtime_r(&(pwdop->pwdata.timeNow), &utctime)) {
                LOG_FATAL("failed to parse current date (buggy gmtime_r ?)\n");
                slapi_value_free(&ipahost);
                goto done;
            }
            strftime(timestr, GENERALIZED_TIME_LENGTH+1,
                     "%Y%m%d%H%M%SZ", &utctime);
            slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                  "krbLastPwdChange", timestr);
        }
        slapi_value_free(&ipahost);
    }

    ret = ipapwd_apply_mods(pwdop->pwdata.dn, smods);
    if (ret)
        LOG("Failed to set additional password attributes in the post-op!\n");

    if (!pwdop->skip_keys) {
        if (pwdop->pwdata.changetype == IPA_CHANGETYPE_NORMAL) {
            principal = slapi_entry_attr_get_charptr(pwdop->pwdata.target,
                                                     "krbPrincipalName");
        } else {
            principal = slapi_ch_smprintf("root/admin@%s", krbcfg->realm);
        }
        ipapwd_set_extradata(pwdop->pwdata.dn, principal, pwdop->pwdata.timeNow);
    }

done:
    if (pwdop && pwdop->pwdata.target) slapi_entry_free(pwdop->pwdata.target);
    slapi_mods_free(&smods);
    slapi_ch_free_string(&principal);
    free_ipapwd_krbcfg(&krbcfg);
    return 0;
}

/* PRE BIND Operation:
 * Used for password migration from DS to IPA.
 * Gets the clean text password, authenticates the user and generates
 * a kerberos key if missing.
 * Person to blame if anything blows up: Pavel Zuna <pzuna@redhat.com>
 */
static int ipapwd_pre_bind(Slapi_PBlock *pb)
{
    struct ipapwd_krbcfg *krbcfg = NULL;
    struct ipapwd_data pwdata;
    struct berval *credentials; /* bind credentials */
    Slapi_Entry *entry = NULL;
    Slapi_Value **pwd_values = NULL; /* values of userPassword attribute */
    Slapi_Value *value = NULL;
    Slapi_Attr *attr = NULL;
    struct tm expire_tm;
    char *errMesg = "Internal operations error\n"; /* error message */
    char *expire = NULL; /* passwordExpirationTime attribute value */
    char *dn = NULL; /* bind DN */
    Slapi_Value *objectclass;
    int method; /* authentication method */
    int ret = 0;
    char *principal = NULL;

    LOG_TRACE("=>\n");

    /* get BIND parameters */
    ret |= slapi_pblock_get(pb, SLAPI_BIND_TARGET, &dn);
    ret |= slapi_pblock_get(pb, SLAPI_BIND_METHOD, &method);
    ret |= slapi_pblock_get(pb, SLAPI_BIND_CREDENTIALS, &credentials);
    if (ret) {
        LOG_FATAL("slapi_pblock_get failed!?\n");
        goto done;
    }

    /* we're only interested in simple authentication */
    if (method != LDAP_AUTH_SIMPLE)
        goto done;

    /* list of attributes to retrieve */
    const char *attrs_list[] = {SLAPI_USERPWD_ATTR, "krbprincipalkey", "uid",
                                "krbprincipalname", "objectclass",
                                "passwordexpirationtime",  "passwordhistory",
                                NULL};

    /* retrieve user entry */
    ret = ipapwd_getEntry(dn, &entry, (char **) attrs_list);
    if (ret) {
        LOG("failed to retrieve user entry: %s\n", dn);
        goto done;
    }

    /* check the krbPrincipalName attribute is present */
    ret = slapi_entry_attr_find(entry, "krbprincipalname", &attr);
    if (ret) {
        LOG("no krbPrincipalName in user entry: %s\n", dn);
        goto done;
    }

    /* we aren't interested in host principals */
    objectclass = slapi_value_new_string("ipaHost");
    if ((slapi_entry_attr_has_syntax_value(entry, SLAPI_ATTR_OBJECTCLASS, objectclass)) == 1) {
        slapi_value_free(&objectclass);
        goto done;
    }
    slapi_value_free(&objectclass);

    /* check the krbPrincipalKey attribute is NOT present */
    ret = slapi_entry_attr_find(entry, "krbprincipalkey", &attr);
    if (!ret) {
        LOG("kerberos key already present in user entry: %s\n", dn);
        goto done;
    }

    /* retrieve userPassword attribute */
    ret = slapi_entry_attr_find(entry, SLAPI_USERPWD_ATTR, &attr);
    if (ret) {
        LOG("no " SLAPI_USERPWD_ATTR " in user entry: %s\n", dn);
        goto done;
    }

    /* get the number of userPassword values and allocate enough memory */
    slapi_attr_get_numvalues(attr, &ret);
    ret = (ret + 1) * sizeof (Slapi_Value *);
    pwd_values = (Slapi_Value **) slapi_ch_malloc(ret);
    if (!pwd_values) {
        /* probably not required: should terminate the server anyway */
        LOG_OOM();
        goto done;
    }
    /* zero-fill the allocated memory; we need the array ending with NULL */
    memset(pwd_values, 0, ret);

    /* retrieve userPassword values */
    ret = slapi_attr_first_value(attr, &value);
    while (ret != -1) {
        pwd_values[ret] = value;
        ret = slapi_attr_next_value(attr, ret, &value);
    }

    /* check if BIND password and userPassword match */
    value = slapi_value_new_berval(credentials);
    ret = slapi_pw_find_sv(pwd_values, value);

    /* free before checking ret; we might not get a chance later */
    slapi_ch_free((void **) &pwd_values);
    slapi_value_free(&value);

    if (ret) {
        LOG("invalid BIND password for user entry: %s\n", dn);
        goto done;
    }

    /* general checks */
    ret = ipapwd_gen_checks(pb, &errMesg, &krbcfg, IPAPWD_CHECK_DN);
    if (ret) {
        LOG_FATAL("Generic checks failed: %s", errMesg);
        goto done;
    }

    /* delete userPassword - a new one will be generated later */
    /* this is needed, otherwise ipapwd_CheckPolicy will think
     * we're changing the password to its previous value
     * and force a password change on next login  */
    ret = slapi_entry_attr_delete(entry, SLAPI_USERPWD_ATTR);
    if (ret) {
        LOG_FATAL("failed to delete " SLAPI_USERPWD_ATTR "\n");
        goto done;
    }

    /* prepare data for kerberos key generation */
    memset(&pwdata, 0, sizeof (pwdata));
    pwdata.dn = dn;
    pwdata.target = entry;
    pwdata.password = credentials->bv_val;
    pwdata.timeNow = time(NULL);
    pwdata.changetype = IPA_CHANGETYPE_NORMAL;

    /* keep password expiration time from DS, if possible */
    expire = slapi_entry_attr_get_charptr(entry, "passwordexpirationtime");
    if (expire) {
        memset(&expire_tm, 0, sizeof (expire_tm));
        if (strptime(expire, "%Y%m%d%H%M%SZ", &expire_tm))
            pwdata.expireTime = mktime(&expire_tm);
    }

    /* check password policy */
    ret = ipapwd_CheckPolicy(&pwdata);
    if (ret) {
        /* Password fails to meet IPA password policy,
         * force user to change his password next time he logs in. */
        LOG("password policy check failed on user entry: %s"
            " (force password change on next login)\n", dn);
        pwdata.expireTime = time(NULL);
    }

    /* generate kerberos keys */
    ret = ipapwd_SetPassword(krbcfg, &pwdata, 1);
    if (ret) {
        LOG("failed to set kerberos key for user entry: %s\n", dn);
        goto done;
    }

    /* we need to make sure the ExtraData is set, otherwise kadmin
     * will not like the object */
    principal = slapi_entry_attr_get_charptr(entry, "krbPrincipalName");
    if (!principal) {
        LOG_OOM();
        goto done;
    }
    ipapwd_set_extradata(pwdata.dn, principal, pwdata.timeNow);

    LOG("kerberos key generated for user entry: %s\n", dn);

done:
    slapi_ch_free_string(&principal);
    slapi_ch_free_string(&expire);
    if (entry)
        slapi_entry_free(entry);
    free_ipapwd_krbcfg(&krbcfg);

    return 0;
}



/* Init pre ops */
int ipapwd_pre_init(Slapi_PBlock *pb)
{
    int ret;

    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&ipapwd_plugin_desc);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN, (void *)ipapwd_pre_bind);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ADD_FN, (void *)ipapwd_pre_add);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODIFY_FN, (void *)ipapwd_pre_mod);

    return ret;
}

/* Init post ops */
int ipapwd_post_init(Slapi_PBlock *pb)
{
    int ret;

    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&ipapwd_plugin_desc);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN, (void *)ipapwd_post_op);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN, (void *)ipapwd_post_op);

    return ret;
}

