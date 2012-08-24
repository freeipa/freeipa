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

#include <stdio.h>
#include <string.h>
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
#include "ipa_krb5.h"

/* krbTicketFlags */
#define KTF_DISALLOW_POSTDATED        0x00000001
#define KTF_DISALLOW_FORWARDABLE      0x00000002
#define KTF_DISALLOW_TGT_BASED        0x00000004
#define KTF_DISALLOW_RENEWABLE        0x00000008
#define KTF_DISALLOW_PROXIABLE        0x00000010
#define KTF_DISALLOW_DUP_SKEY         0x00000020
#define KTF_DISALLOW_ALL_TIX          0x00000040
#define KTF_REQUIRES_PRE_AUTH         0x00000080
#define KTF_REQUIRES_HW_AUTH          0x00000100
#define KTF_REQUIRES_PWCHANGE         0x00000200
#define KTF_DISALLOW_SVR              0x00001000
#define KTF_PWCHANGE_SERVICE          0x00002000

/* ascii hex output of bytes in "in"
 * out len is 32 (preallocated)
 * in len is 16 */
static const char hexchars[] = "0123456789ABCDEF";
static void hexbuf(char *out, const uint8_t *in)
{
    int i;

    for (i = 0; i < 16; i++) {
        out[i*2] = hexchars[in[i] >> 4];
        out[i*2+1] = hexchars[in[i] & 0x0f];
    }
}

void ipapwd_keyset_free(struct ipapwd_keyset **pkset)
{
    struct ipapwd_keyset *kset = *pkset;
    int i;

    if (!kset) return;

    for (i = 0; i < kset->num_keys; i++) {
        free(kset->keys[i].key_data_contents[0]);
        free(kset->keys[i].key_data_contents[1]);
    }
    free(kset->keys);
    free(kset);
    *pkset = NULL;
}

static Slapi_Value **encrypt_encode_key(struct ipapwd_krbcfg *krbcfg,
                                        struct ipapwd_data *data,
                                        char **errMesg)
{
    krb5_context krbctx;
    char *krbPrincipalName = NULL;
    int kvno;
    struct berval *bval = NULL;
    Slapi_Value **svals = NULL;
    krb5_principal princ = NULL;
    krb5_error_code krberr;
    krb5_data pwd;
    struct ipapwd_keyset *kset = NULL;

    krbctx = krbcfg->krbctx;

    svals = (Slapi_Value **)calloc(2, sizeof(Slapi_Value *));
    if (!svals) {
        LOG_OOM();
        return NULL;
    }

    kvno = ipapwd_get_cur_kvno(data->target);

    krbPrincipalName = slapi_entry_attr_get_charptr(data->target,
                                                    "krbPrincipalName");
    if (!krbPrincipalName) {
        *errMesg = "no krbPrincipalName present in this entry\n";
        LOG_FATAL("%s", *errMesg);
        goto enc_error;
    }

    krberr = krb5_parse_name(krbctx, krbPrincipalName, &princ);
    if (krberr) {
        LOG_FATAL("krb5_parse_name failed [%s]\n",
                  krb5_get_error_message(krbctx, krberr));
        goto enc_error;
    }

    pwd.data = (char *)data->password;
    pwd.length = strlen(data->password);

    kset = malloc(sizeof(struct ipapwd_keyset));
    if (!kset) {
        LOG_OOM();
        goto enc_error;
    }

    /* this encoding assumes all keys have the same kvno */
    /* major-vno = 1 and minor-vno = 1 */
    kset->major_vno = 1;
    kset->minor_vno = 1;
    /* increment kvno (will be 1 if this is a new entry) */
    kvno += 1;
    kset->mkvno = krbcfg->mkvno;

    krberr = ipa_krb5_generate_key_data(krbctx, princ,
                                        pwd, kvno, krbcfg->kmkey,
                                        krbcfg->num_pref_encsalts,
                                        krbcfg->pref_encsalts,
                                        &kset->num_keys, &kset->keys);
    if (krberr != 0) {
        LOG_FATAL("generating kerberos keys failed [%s]\n",
                  krb5_get_error_message(krbctx, krberr));
        goto enc_error;
    }

    krberr = ber_encode_krb5_key_data(kset->keys, kset->num_keys,
                                      kset->mkvno, &bval);
    if (krberr != 0) {
        LOG_FATAL("encoding krb5_key_data failed\n");
        goto enc_error;
    }

    svals[0] = slapi_value_new_berval(bval);
    if (!svals[0]) {
        LOG_FATAL("Converting berval to Slapi_Value\n");
        goto enc_error;
    }

    ipapwd_keyset_free(&kset);
    krb5_free_principal(krbctx, princ);
    slapi_ch_free_string(&krbPrincipalName);
    ber_bvfree(bval);
    return svals;

enc_error:
    *errMesg = "key encryption/encoding failed\n";
    if (kset) ipapwd_keyset_free(&kset);
    krb5_free_principal(krbctx, princ);
    slapi_ch_free_string(&krbPrincipalName);
    if (bval) ber_bvfree(bval);
    free(svals);
    return NULL;
}

int ipapwd_gen_hashes(struct ipapwd_krbcfg *krbcfg,
                      struct ipapwd_data *data, char *userpw,
                      int is_krb, int is_smb, int is_ipant, Slapi_Value ***svals,
                      char **nthash, char **lmhash, Slapi_Value ***ntvals,
                      char **errMesg)
{
    int rc;
    char *userpw_uc = NULL;

    *svals = NULL;
    *nthash = NULL;
    *lmhash = NULL;
    *errMesg = NULL;

    if (is_krb) {

        *svals = encrypt_encode_key(krbcfg, data, errMesg);

        if (!*svals) {
            /* errMesg should have been set in encrypt_encode_key() */
            LOG_FATAL("key encryption/encoding failed\n");
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
    }

    if (is_smb || is_ipant) {
        char lm[33], nt[33];
        struct ntlm_keys ntlm;
        int ret;

        userpw_uc = (char *) slapi_utf8StrToUpper((unsigned char *) userpw);
        if (!userpw_uc) {
            *errMesg = "Failed to generate upper case password\n";
            LOG_FATAL("%s", *errMesg);
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        ret = encode_ntlm_keys(userpw,
                               userpw_uc,
                               krbcfg->allow_lm_hash,
                               krbcfg->allow_nt_hash,
                               &ntlm);
        memset(userpw_uc, 0, strlen(userpw_uc));
        slapi_ch_free_string(&userpw_uc);
        if (ret) {
            *errMesg = "Failed to generate NT/LM hashes\n";
            LOG_FATAL("%s", *errMesg);
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
        if (krbcfg->allow_lm_hash) {
            hexbuf(lm, ntlm.lm);
            lm[32] = '\0';
            *lmhash = slapi_ch_strdup(lm);
        }
        if (krbcfg->allow_nt_hash) {
            hexbuf(nt, ntlm.nt);
            nt[32] = '\0';
            *nthash = slapi_ch_strdup(nt);
        }

        if (is_ipant) {
            *ntvals = (Slapi_Value **)calloc(2, sizeof(Slapi_Value *));
            if (!*ntvals) {
                LOG_OOM();
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }
            (*ntvals)[0] = slapi_value_new();
            if (slapi_value_set((*ntvals)[0], ntlm.nt, 16) == NULL) {
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }
        }
    }

    rc = LDAP_SUCCESS;

done:

    /* when error, free possibly allocated output parameters */
    if (rc) {
        ipapwd_free_slapi_value_array(svals);
        ipapwd_free_slapi_value_array(ntvals);
    }

    return rc;
}

