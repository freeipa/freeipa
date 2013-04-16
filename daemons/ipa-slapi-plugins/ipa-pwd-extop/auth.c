/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 3 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * In addition, as a special exception, Red Hat, Inc. gives You the additional
 * right to link the code of this Program with code not covered under the GNU
 * General Public License ("Non-GPL Code") and to distribute linked combinations
 * including the two, subject to the limitations in this paragraph. Non-GPL Code
 * permitted under this exception must only link to the code of this Program
 * through those well defined interfaces identified in the file named EXCEPTION
 * found in the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline functions from
 * the Approved Interfaces without causing the resulting work to be covered by
 * the GNU General Public License. Only Red Hat, Inc. may make changes or
 * additions to the list of Approved Interfaces. You must obey the GNU General
 * Public License in all respects for all of the Program code and other code used
 * in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * provide this exception without modification, you must delete this exception
 * statement from your version and license this file solely under the GPL without
 * exception.
 *
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "ipapwd.h"

#define IPA_OTP_TOKEN_TOTP_OC "ipaTokenTOTP"
#define IPA_OTP_DEFAULT_TOKEN_ALGORITHM "sha1"
#define IPA_OTP_DEFAULT_TOKEN_OFFSET 0
#define IPA_OTP_DEFAULT_TOKEN_STEP 30

/*
 * From otp.c
 */
bool ipapwd_hotp(const uint8_t *key, size_t len, const char *algo, int digits,
                 uint64_t counter, uint32_t *out);

bool ipapwd_totp(const uint8_t *key, size_t len, const char *algo, int digits,
                 time_t time, int offset, unsigned int step, uint32_t *out);

/* From ipa_pwd_extop.c */
extern void *ipapwd_plugin_id;

/* Data types. */
struct token {
    struct {
        uint8_t *data;
        size_t len;
    } key;
    char *algo;
    int len;
    union {
        struct {
            uint64_t counter;
        } hotp;
        struct {
            unsigned int step;
            int offset;
        } totp;
    };
    bool (*auth)(const struct token *token, uint32_t otp);
};

struct credentials {
    struct token token;
    Slapi_Value *ltp;
    uint32_t otp;
};

static const char *valid_algos[] = { "sha1", "sha256", "sha384",
                                     "sha512", NULL };

static inline bool is_algo_valid(const char *algo)
{
    int i, ret;

    for (i = 0; valid_algos[i]; i++) {
        ret = strcasecmp(algo, valid_algos[i]);
        if (ret == 0)
            return true;
    }

    return false;
}

static const struct berval *entry_attr_get_berval(const Slapi_Entry* e,
                                                  const char *type)
{
    Slapi_Attr* attr = NULL;
    Slapi_Value *v;
    int ret;

    ret = slapi_entry_attr_find(e, type, &attr);
    if (ret != 0 || attr == NULL)
        return NULL;

    ret = slapi_attr_first_value(attr, &v);
    if (ret < 0)
        return NULL;

    return slapi_value_get_berval(v);
}

/* Authenticate a totp token. Return zero on success. */
static bool auth_totp(const struct token *token, uint32_t otp)
{
    time_t times[5];
    uint32_t val;
    int i;

    /* Get the token value for now and two steps in either direction. */
    times[0] = time(NULL);
    times[1] = times[0] + token->totp.step * 1;
    times[2] = times[0] - token->totp.step * 1;
    times[3] = times[0] + token->totp.step * 2;
    times[4] = times[0] - token->totp.step * 2;
    if (times[0] == -1)
        return false;

    /* Check all the times for a match. */
    for (i = 0; i < sizeof(times) / sizeof(times[0]); i++) {
        if (!ipapwd_totp(token->key.data, token->key.len, token->algo,
                         token->len, times[i], token->totp.offset,
                         token->totp.step, &val)) {
            return false;
        }

        if (val == otp) {
            return true;
        }
    }

    return false;
}

static void token_free_contents(struct token *token)
{
    if (token == NULL)
        return;

    slapi_ch_free_string(&token->algo);
    slapi_ch_free((void **) &token->key.data);
}

/* Decode an OTP token entry. Return zero on success. */
static bool token_decode(Slapi_Entry *te, struct token *token)
{
    const struct berval *tmp;

    /* Get key. */
    tmp = entry_attr_get_berval(te, IPA_OTP_TOKEN_KEY_TYPE);
    if (tmp == NULL) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "token_decode: key not set for token \"%s\".\n",
                        slapi_entry_get_ndn(te));
        return false;
    }
    token->key.len = tmp->bv_len;
    token->key.data = (void *) slapi_ch_malloc(token->key.len);
    memcpy(token->key.data, tmp->bv_val, token->key.len);

    /* Get length. */
    token->len = slapi_entry_attr_get_int(te, IPA_OTP_TOKEN_LENGTH_TYPE);
    if (token->len < 6 || token->len > 10) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "token_decode: %s is not defined or invalid "
                        "for token \"%s\".\n", IPA_OTP_TOKEN_LENGTH_TYPE,
                        slapi_entry_get_ndn(te));
        token_free_contents(token);
        return false;
    }

    /* Get algorithm. */
    token->algo = slapi_entry_attr_get_charptr(te,
                                               IPA_OTP_TOKEN_ALGORITHM_TYPE);
    if (token->algo == NULL)
        token->algo = slapi_ch_strdup(IPA_OTP_DEFAULT_TOKEN_ALGORITHM);
    if (!is_algo_valid(token->algo)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "token_decode: invalid token algorithm "
                        "specified for token \"%s\".\n",
                        slapi_entry_get_ndn(te));
        token_free_contents(token);
        return false;
    }

    /* Currently, we only support TOTP. */
    token->auth = auth_totp;

    /* Get offset. */
    token->totp.offset = slapi_entry_attr_get_int(te,
                                                  IPA_OTP_TOKEN_OFFSET_TYPE);
    if (token->totp.offset == 0)
        token->totp.offset = IPA_OTP_DEFAULT_TOKEN_OFFSET;

    /* Get step. */
    token->totp.step = slapi_entry_attr_get_uint(te, IPA_OTP_TOKEN_STEP_TYPE);
    if (token->totp.step == 0)
        token->totp.step = IPA_OTP_DEFAULT_TOKEN_STEP;

    return true;
}

static void credentials_free_contents(struct credentials *credentials)
{
    if (!credentials)
        return;

    token_free_contents(&credentials->token);
    slapi_value_free(&credentials->ltp);
}

/* Parse credentials and token entry. Return zero on success. */
static bool credentials_parse(Slapi_Entry *te, struct berval *creds,
                              struct credentials *credentials)
{
    char *tmp;
    int len;

    if (!token_decode(te, &credentials->token))
        return false;

    /* Is the credential too short?  If so, error. */
    if (credentials->token.len >= creds->bv_len) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "credentials_parse: supplied credential is less "
                        "than or equal to %s for token \"%s\".\n",
                        IPA_OTP_TOKEN_LENGTH_TYPE, slapi_entry_get_ndn(te));
        token_free_contents(&credentials->token);
        return false;
    }

    /* Extract the password from the supplied credential.  We hand the
     * memory off to a Slapi_Value, so we don't want to directly free the
     * string. */
    len = creds->bv_len - credentials->token.len;
    tmp = slapi_ch_calloc(len + 1, sizeof(char));
    strncpy(tmp, creds->bv_val, len);
    credentials->ltp = slapi_value_new_string_passin(tmp);

    /* Extract the token value as a (minimum) 32-bit unsigned integer. */
    tmp = slapi_ch_calloc(credentials->token.len + 1, sizeof(char));
    strncpy(tmp, creds->bv_val + len, credentials->token.len);
    credentials->otp = strtoul(tmp, NULL, 10);
    slapi_ch_free_string(&tmp);

    return true;
}

/*
 * Attempts to perform OTP authentication for the passed in bind entry using
 * the passed in credentials.
 */
bool ipapwd_do_otp_auth(Slapi_Entry *bind_entry, struct berval *creds)
{
    Slapi_PBlock *search_pb = NULL;
    Slapi_Value **pwd_vals = NULL;
    Slapi_Attr *pwd_attr = NULL;
    Slapi_Entry **tokens = NULL;
    Slapi_DN *base_sdn = NULL;
    Slapi_Backend *be = NULL;
    char *user_dn = NULL;
    char *filter = NULL;
    int pwd_numvals = 0;
    bool ret = false;
    int result = 0;
    int hint = 0;
    int i = 0;

    search_pb = slapi_pblock_new();

    /* Fetch the user DN. */
    user_dn = slapi_entry_get_ndn(bind_entry);
    if (user_dn == NULL) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "ipapwd_do_otp_auth: error retrieving bind DN.\n");
        goto done;
    }

    /* Search for TOTP tokens associated with this user.  We search for
     * tokens who list this user as the owner in the same backend where
     * the user entry is located. */
    filter = slapi_ch_smprintf("(&(%s=%s)(%s=%s))", SLAPI_ATTR_OBJECTCLASS,
                               IPA_OTP_TOKEN_TOTP_OC, IPA_OTP_TOKEN_OWNER_TYPE,
                               user_dn);

    be = slapi_be_select(slapi_entry_get_sdn(bind_entry));
    if (be != NULL) {
        base_sdn = (Slapi_DN *) slapi_be_getsuffix(be, 0);
    }
    if (base_sdn == NULL) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "ipapwd_do_otp_auth: error determining the search "
                        "base for user \"%s\".\n",
                        user_dn);
    }

    slapi_search_internal_set_pb(search_pb, slapi_sdn_get_ndn(base_sdn),
                                 LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL,
                                 NULL, ipapwd_plugin_id, 0);

    slapi_search_internal_pb(search_pb);
    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &result);

    if (LDAP_SUCCESS != result) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "ipapwd_do_otp_auth: error searching for tokens "
                        "associated with user \"%s\" (err=%d).\n",
                        user_dn, result);
        goto done;
    }

    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &tokens);

    if (tokens == NULL) {
        /* This user has no associated tokens, so just bail out. */
        goto done;
    }

    /* Fetch the userPassword values so we can perform the password checks
     * when processing tokens below. */
    if (slapi_entry_attr_find(bind_entry, SLAPI_USERPWD_ATTR, &pwd_attr) != 0 ||
        slapi_attr_get_numvalues(pwd_attr, &pwd_numvals) != 0) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "ipapwd_do_otp_auth: no passwords are set for user "
                        "\"%s\".\n", user_dn);
        goto done;
    }

    /* We need to create a Slapi_Value  array of the present password values
     * for the compare function.  There's no nicer way of doing this. */
    pwd_vals = (Slapi_Value **) slapi_ch_calloc(pwd_numvals,
                                                sizeof(Slapi_Value *));

    for (hint = slapi_attr_first_value(pwd_attr, &pwd_vals[i]); hint != -1;
         hint = slapi_attr_next_value(pwd_attr, hint, &pwd_vals[i])) {
        ++i;
    }

    /* Loop through each token and attempt to authenticate. */
    for (i = 0; tokens && tokens[i]; i++) {
        struct credentials credentials;

        /* Parse the token entry and the credentials. */
        if (!credentials_parse(tokens[i], creds, &credentials))
            continue;

        /* Check if the password portion of the credential is correct. */
        i = slapi_pw_find_sv(pwd_vals, credentials.ltp);
        if (i != 0) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "ipapwd_do_otp_auth: password check failed when "
                            "processing token \"%s\" for user \"%s\".\n",
                            slapi_entry_get_ndn(tokens[i]), user_dn);
            credentials_free_contents(&credentials);
            continue;
        }

        /* Attempt to perform OTP authentication for this token. */
        if (!credentials.token.auth(&credentials.token, credentials.otp)) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "ipapwd_do_otp_auth: OTP auth failed when "
                            "processing token \"%s\" for user \"%s\".\n",
                            slapi_entry_get_ndn(tokens[i]), user_dn);
            credentials_free_contents(&credentials);
            continue;
        }

        /* Authentication successful! */
        credentials_free_contents(&credentials);
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "ipapwd_do_otp_auth: successfully "
                        "authenticated user \"%s\" using token "
                        "\"%s\".\n",
                        user_dn, slapi_entry_get_ndn(tokens[i]));
        ret = true;
        break;
    }

done:
    slapi_ch_free_string(&filter);
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);
    return ret;
}
