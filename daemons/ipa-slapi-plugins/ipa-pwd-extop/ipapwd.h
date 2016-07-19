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

#include "../libotp/otp_token.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <prio.h>
#include <ssl.h>
#include <krb5.h>
#include <kdb.h>
#include <lber.h>
#include <time.h>
#include <iconv.h>
#include <openssl/des.h>
#include <openssl/md4.h>

#include "ipa_krb5.h"
#include "ipa_pwd.h"

#define IPAPWD_PLUGIN_NAME   "ipa-pwd-extop"
#define IPAPWD_FEATURE_DESC  "IPA Password Manager"
#define IPAPWD_PLUGIN_DESC   "IPA Password Extended Operation plugin"

#define IPA_PLUGIN_NAME IPAPWD_PLUGIN_NAME

#define IPAPWD_CHECK_CONN_SECURE    0x00000001
#define IPAPWD_CHECK_DN             0x00000002

#define IPA_CHANGETYPE_NORMAL 0
#define IPA_CHANGETYPE_ADMIN 1
#define IPA_CHANGETYPE_DSMGR 2

struct ipapwd_data {
    Slapi_Entry *target;
    char *dn;
    char *password;
    time_t timeNow;
    time_t expireTime;
    int changetype;
    struct ipapwd_policy policy;
};

struct ipapwd_operation {
    struct ipapwd_data pwdata;
    int pwd_op;
    int is_krb;
    int skip_keys;
    int skip_history;
};

#define GENERALIZED_TIME_LENGTH 15

/* from common.c */
struct ipapwd_krbcfg {
    krb5_context krbctx;
    char *realm;
    int mkvno;
    krb5_keyblock *kmkey;
    int num_supp_encsalts;
    krb5_key_salt_tuple *supp_encsalts;
    int num_pref_encsalts;
    krb5_key_salt_tuple *pref_encsalts;
    char **passsync_mgrs;
    int num_passsync_mgrs;
    bool allow_nt_hash;
};

int ipapwd_entry_checks(Slapi_PBlock *pb, struct slapi_entry *e,
                        int *is_root, int *is_krb, int *is_smb, int *is_ipant,
                        char *attr, int access);
int ipapwd_gen_checks(Slapi_PBlock *pb, char **errMesg,
                      struct ipapwd_krbcfg **config, int check_flags);
int ipapwd_CheckPolicy(struct ipapwd_data *data);
int ipapwd_getEntry(const char *dn, Slapi_Entry **e2, char **attrlist);
int ipapwd_get_cur_kvno(Slapi_Entry *target);
int ipapwd_setdate(Slapi_Entry *source, Slapi_Mods *smods, const char *attr,
                   time_t date, bool remove);
int ipapwd_SetPassword(struct ipapwd_krbcfg *krbcfg,
                       struct ipapwd_data *data, int is_krb);
Slapi_Value **ipapwd_setPasswordHistory(Slapi_Mods *smods,
                                        struct ipapwd_data *data);
int ipapwd_apply_mods(const char *dn, Slapi_Mods *mods);
int ipapwd_set_extradata(const char *dn,
                         const char *principal,
                         time_t unixtime);
void ipapwd_free_slapi_value_array(Slapi_Value ***svals);
void free_ipapwd_krbcfg(struct ipapwd_krbcfg **cfg);

/* from encoding.c */
struct ipapwd_keyset {
    uint16_t major_vno;
    uint16_t minor_vno;
    uint32_t mkvno;
    krb5_key_data *keys;
    int num_keys;
};

void ipapwd_keyset_free(struct ipapwd_keyset **pkset);

Slapi_Value **ipapwd_encrypt_encode_key(struct ipapwd_krbcfg *krbcfg,
                                        struct ipapwd_data *data,
                                        char *preferred_principal,
                                        int num_encsalts,
                                        krb5_key_salt_tuple *encsalts,
                                        char **errMesg);

int ipapwd_gen_hashes(struct ipapwd_krbcfg *krbcfg,
                      struct ipapwd_data *data, char *userpw,
                      int is_krb, int is_smb, int is_ipant,
                      Slapi_Value ***svals, char **nthash,
                      Slapi_Value ***ntvals, char **errMesg);

/* from prepost.c */
int ipapwd_ext_init(void);
int ipapwd_pre_init(Slapi_PBlock *pb);
int ipapwd_post_init(Slapi_PBlock *pb);
int ipapwd_intpost_init(Slapi_PBlock *pb);
int ipapwd_pre_init_betxn(Slapi_PBlock *pb);
int ipapwd_post_init_betxn(Slapi_PBlock *pb);

/* from ipa_pwd_extop.c */
void *ipapwd_get_plugin_id(void);
