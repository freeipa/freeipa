/*
 * Password related utils for FreeIPA
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
#define _GNU_SOURCE
#endif
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#if defined(USE_PWQUALITY)
#include <pwquality.h>
#endif
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "ipa_pwd.h"

#define GENERALIZED_TIME_LENGTH 15
#define DEFAULT_HASH_TYPE "{SHA512}"

/**
* @brief Calculate utf8 string length
*
* @param str        The string
* @param blength    Integer into which returns the length in bytes
*
* @return   Returns the number of utf8 characters, optionally if blength
*           is not NULL it will contain the legth in bytes too.
*/
static int strlen_utf8(char *str, int *blength)
{
    int i, j = 0;

    for (i = 0; str[i]; i++) {
        if ((str[i] & 0xC0) != 0x80) {
            j++;
        }
    }

    if (blength) {
        *blength = i;
    }

    return j;
}

/**
* @brief        Get the next utf8 code point
*
* @param cp     The utf8 string
*
* @return       ther pointer to the next code point or NULL
*/
static char *utf8_next(char *cp)
{
    int t, c, i;
    int ct = (unsigned char)*cp;

    if (ct == 0) {
        return NULL;
    }

    if (ct < 0x80) {
        return cp + 1;
    }

    t = 0xE0;
    c = 2;
    while (t != 0xFF) {
        if (ct < t) {
            for (i = 0; i < c && cp[i]; i++) ;
            if (i != c) {
                return NULL;
            }
            return cp + c;
        }
        t = (t >> 1) | 0x80;
        c++;
    }

    return NULL;
}

static bool utf8_isdigit(char *p)
{
    if (*p & 0x80) {
        return false;
    }
    return isdigit(*p);
}

static bool utf8_isalpha(char *p)
{
    if (*p & 0x80) {
        return false;
    }
    return isalpha(*p);
}

/**
* @brief Get a string in generalize time format and returns time_t
*
* @param timestr    The input string
*
* @return the time represented by the string or 0 on error
*/
time_t ipapwd_gentime_to_time_t(char *timestr)
{
    struct tm tm;
    time_t rtime = 0;
    int ret;

    if (timestr != NULL) {

        memset(&tm, 0, sizeof(struct tm));
        ret = sscanf(timestr, "%04u%02u%02u%02u%02u%02u",
                     &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                     &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

        if (ret == 6) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;

            rtime = timegm(&tm);
        }
    }

    return rtime;
}

static int ipapwd_gentime_cmp(const void *p1, const void *p2)
{
    /* generalized time can be compared directly as ASCII codes
     * are ordered numerically so a higher char value corresponds to
     * a higher letter or number */

    /* return youngest first by inverting terms */
    return memcmp(*(void * const *)p2, *(void * const *)p1, GENERALIZED_TIME_LENGTH);
}

#define SHA_SALT_LENGTH 8

static int ipapwd_hash_type_to_alg(const char *hash_type,
                                   char **hash_alg_sn)
{
    if (strncmp("{SSHA}", hash_type, 6) == 0) {
        *hash_alg_sn = SN_sha1;
        return 0;
    }
    if (strncmp("{SHA256}", hash_type, 8) == 0) {
        *hash_alg_sn = SN_sha256;
        return 0;
    }
    if (strncmp("{SHA384}", hash_type, 8) == 0) {
        *hash_alg_sn = SN_sha384;
        return 0;
    }
    if (strncmp("{SHA512}", hash_type, 8) == 0) {
        *hash_alg_sn = SN_sha512;
        return 0;
    }

    return -1;
}

/**
* @brief    Hashes a password using the hash_type requested
*
* @param password       The cleartext password to hash
* @param psalt          An 8 byte salt, if NULL a random one is used
* @param hash_type      The hash type ({SSHA}, {SHA256}, {SHA384}, {SHA512})
* @param full_hash      The resulting hash with the salt appended
*
* @return 0 on success, -1 on error.
*/
int ipapwd_hash_password(char *password,
                                const char *hash_type,
                                unsigned char *salt,
                                unsigned char **full_hash,
                                unsigned int *full_hash_len)
{
    unsigned char *fh = NULL;
    unsigned int fhl = 0;
    unsigned char *pwd = (unsigned char *)password;
    unsigned int pwdlen = strlen(password);
    unsigned char saltbuf[SHA_SALT_LENGTH];
    unsigned char hash[EVP_MAX_MD_SIZE] = { 0 };
    unsigned int hash_len;

    int ret;

    EVP_MD_CTX *ctx = NULL;
    char *hash_alg_sn = NULL;
    const EVP_MD* hash_alg = NULL;

    if (!salt) {
        RAND_bytes(saltbuf, SHA_SALT_LENGTH);
        salt = saltbuf;
    }

    ret = ipapwd_hash_type_to_alg(hash_type, &hash_alg_sn);
    if (ret) {
        return -1;
    }

    hash_alg = EVP_get_digestbyname(hash_alg_sn);
    if (!hash_alg) {
        return -1;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    ret = EVP_DigestInit_ex(ctx, hash_alg, NULL);
    if (ret) {
        ret = EVP_DigestUpdate(ctx, pwd, pwdlen);
    }
    if (ret) {
        ret = EVP_DigestUpdate(ctx, salt, SHA_SALT_LENGTH);
    }
    if (ret) {
        ret = EVP_DigestFinal_ex(ctx, hash, &hash_len);
    }
    if (!ret) {
        ret = -1;
        goto done;
    }
    else
        ret = 0;

    if (hash_len != (unsigned int) EVP_MD_CTX_size(ctx)) {
        ret = -1;
        goto done;
    }

    fhl = hash_len + SHA_SALT_LENGTH;
    fh = malloc(fhl + 1);
    if (!fh) {
        ret = -1;
        goto done;
    }
    memcpy(fh, hash, hash_len);
    memcpy(fh + hash_len, salt, SHA_SALT_LENGTH);
    memset(fh + fhl, '\0', 1);

done:
    EVP_MD_CTX_free(ctx);
    *full_hash = fh;
    *full_hash_len = fhl;
    return ret;
}

/**
* @brief    Compares the provided password with a history element
*
* @param password       A cleartext password
* @param historyString  A history element.
*
* A history element is a base64 string of a hash+salt buffer, prepended
* by the hash type enclosed within curly braces.
*
* @return   0 if password matches, 1 if it doesn't and -1 on errors.
*/
static int ipapwd_cmp_password(char *password, char *historyString)
{
    char *hash_type;
    char *b64part;
    size_t b64_len;
    unsigned char *salt;
    unsigned char *hash = NULL;
    unsigned int hash_len;
    int ret;

    hash_type = historyString;
    b64part = strchr(historyString, '}');
    if (!b64part) {
        return -1;
    }
    b64part++;
    b64_len = strlen(b64part);

    unsigned char *item_data = (unsigned char *) OPENSSL_malloc(sizeof(char) * b64_len);
    if (!item_data) {
        return -1;
    }

    size_t item_len = EVP_DecodeBlock(item_data, (unsigned char *) b64part, b64_len);
    if (item_len <= SHA_SALT_LENGTH) {
        ret = -1;
        goto done;
    }

    salt = item_data + (item_len - SHA_SALT_LENGTH);
    ret = ipapwd_hash_password(password, hash_type, salt, &hash, &hash_len);
    if (ret != 0) {
        goto done;
    }

    if (hash_len != item_len) {
        ret = 1;
        goto done;
    }

    if (CRYPTO_memcmp(item_data, hash, hash_len)) {
        ret = 1;
        goto done;
    }

    ret = 0;

done:
    if (item_data)
        OPENSSL_clear_free(item_data, sizeof(char) * b64_len);

    free(hash);
    return ret;
}

/**
* @brief    Returns a history element string
*
* A history element is a base64 string of a hash+salt buffer, prepended
* by the hash type enclosed within curly braces.
*
* @param hash_time      The time at which the hash has been created
* @param hash_type      The hash type ({SSHA}, {SHA256}, {SHA384}, {SHA512})
* @param hash           A binary buffer containing hash+salt
* @param hash_len       The length of the hash binary buffer
*
* @return   A history element string or NULL on error.
*/
static char *ipapwd_hash_to_history(time_t hash_time,
                                    char *hash_type,
                                    unsigned char *hash,
                                    unsigned int hash_len)
{
    struct tm utctime;
    char timestr[GENERALIZED_TIME_LENGTH+1];
    unsigned char *encoded = NULL;
    char *history = NULL;
    int ret;

    if (!gmtime_r(&hash_time, &utctime))
        goto cleanup;

    strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);

    encoded = (unsigned char *) malloc(4 * (hash_len * sizeof(*encoded) / 3) + 1);
    if (!encoded)
        goto cleanup;

    ret = EVP_EncodeBlock(encoded, hash, hash_len);
    if (ret < 1)
        goto cleanup;

    ret = asprintf(&history, "%s%s%s", timestr, hash_type, encoded);
    if (ret == -1) {
        history = NULL;
        goto cleanup;
    }

cleanup:
    if (encoded)
        free(encoded);

    return history;
}

/**
* @brief Funtion used to check password policies on a password change.
*
* @param policy             The policy to check against
* @param password           The new password
* @param cur_time           The current time, usually set to time(NULL)
* @param acct_expiration    Account expiration
* @param pwd_expiration     Password expiration
* @param last_pwd_change    Last Password change
* @param pwd_history        Password history (must include current password)
*
* @return 0 if ok, or appropriate IPAPWD error otherwise.
*/
int ipapwd_check_policy(struct ipapwd_policy *policy,
                        char *password,
                        char *user,
                        time_t cur_time,
                        time_t acct_expiration,
                        time_t pwd_expiration,
                        time_t last_pwd_change,
                        char **pwd_history)
{
    int pwdlen, blen;
    int ret;
#if defined(USE_PWQUALITY)
    pwquality_settings_t *pwq;
    int check_pwquality = 0;
    int entropy = 0;
    char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
    void *auxerror;
#endif

    if (!policy || !password) {
        return IPAPWD_POLICY_ERROR;
    }

    /* check account is not expired. Ignore unixtime = 0 (Jan 1 1970) */
    if (acct_expiration != 0) {
        /* if expiration date is set check it */
        if (cur_time > acct_expiration) {
            return IPAPWD_POLICY_ACCOUNT_EXPIRED;
        }
    }

    if (policy->min_pwd_life != 0) {
        /* check for reset cases */
        if (last_pwd_change != 0 && pwd_expiration != last_pwd_change) {
            /* Expiration and last change time are the same or
             * missing this happens only when a password is reset
             * by an admin or the account is new or no expiration
             * policy is set */

            if (cur_time < last_pwd_change + policy->min_pwd_life) {
                return IPAPWD_POLICY_PWD_TOO_YOUNG;
            }
        }
    }

    pwdlen = strlen_utf8(password, &blen);

    if (policy->min_pwd_length) {
        if (pwdlen < policy->min_pwd_length) {
            return IPAPWD_POLICY_PWD_TOO_SHORT;
        }
    }

    if (policy->min_complexity) {
        int num_digits = 0;
        int num_alphas = 0;
        int num_uppers = 0;
        int num_lowers = 0;
        int num_specials = 0;
        int num_8bit = 0;
        int num_repeated = 0;
        int max_repeated = 0;
        int num_categories = 0;
        char *p, *n;
        int size, len;

        /* we want the actual length in bytes here */
        len = blen;

        p = password;
        while (p && *p) {
            if (utf8_isdigit(p)) {
                num_digits++;
            /* alpha/lower/upper, is checked only for pure ASCII chars */
            } else if (utf8_isalpha(p)) {
                num_alphas++;
                if (islower(*p)) {
                    num_lowers++;
                } else {
                    num_uppers++;
                }
            } else {
                if (*p & 0x80) {
                    num_8bit++;
                } else {
                    num_specials++;
                }
            }

            n = utf8_next(p);
            if (n != NULL) {
                size = n - p;
                len -= size;
                if ((len > size) && (memcmp(p, n, size) == 0)) {
                    num_repeated++;
                    if (max_repeated < num_repeated) {
                        max_repeated = num_repeated;
                    }
                } else {
                    num_repeated = 0;
                }
            }
            p = n;
        }

        /* tally up the number of character categories */
        if (num_digits > 0) {
            num_categories++;
        }
        if (num_uppers > 0) {
            num_categories++;
        }
        if (num_lowers > 0) {
            num_categories++;
        }
        if (num_specials > 0) {
            num_categories++;
        }
        if (num_8bit > 0) {
            num_categories++;
        }
        if (max_repeated > 1) {
            num_categories--;
        }

        if (num_categories < policy->min_complexity) {
            return IPAPWD_POLICY_PWD_COMPLEXITY;
        }
    }

#if defined(USE_PWQUALITY)
    /* Only call into libpwquality if at least one setting is made
     * because there are a number of checks that don't have knobs
     * so preserve the previous behavior.
     */
    check_pwquality = policy->max_repeat + policy->max_sequence + policy->dictcheck + policy->usercheck;

    if (check_pwquality > 0) {
        /* Call libpwquality */
        openlog(NULL, LOG_CONS | LOG_NDELAY, LOG_DAEMON);
        pwq = pwquality_default_settings();
        if (pwq == NULL) {
            syslog(LOG_ERR, "Not able to set pwquality defaults\n");
            return IPAPWD_POLICY_ERROR;
        }
        if (policy->min_pwd_length < 6)
            syslog(LOG_WARNING, "password policy min length is < 6. Will be enforced as 6\n");
        pwquality_set_int_value(pwq, PWQ_SETTING_MIN_LENGTH, policy->min_pwd_length);
        pwquality_set_int_value(pwq, PWQ_SETTING_MAX_REPEAT, policy->max_repeat);
        pwquality_set_int_value(pwq, PWQ_SETTING_MAX_SEQUENCE, policy->max_sequence);
        pwquality_set_int_value(pwq, PWQ_SETTING_DICT_CHECK, policy->dictcheck);
        pwquality_set_int_value(pwq, PWQ_SETTING_USER_CHECK, policy->usercheck);

        entropy = pwquality_check(pwq, password, NULL, user, &auxerror);
        pwquality_free_settings(pwq);

#ifdef TEST
        if (user != NULL) {
            fprintf(stderr, "Checking password for %s\n", user);
        } else {
            fprintf(stderr, "No user provided\n");
        }

        fprintf(stderr, "min length %d\n", policy->min_pwd_length);
        fprintf(stderr, "max repeat %d\n", policy->max_repeat);
        fprintf(stderr, "max sequence %d\n", policy->max_sequence);
        fprintf(stderr, "dict check %d\n", policy->dictcheck);
        fprintf(stderr, "user check %d\n", policy->usercheck);
#endif

        if (entropy < 0) {
#ifdef TEST
            fprintf(stderr, "Bad password '%s': %s\n", password, pwquality_strerror(buf, sizeof(buf), entropy, auxerror));
#endif
            syslog(LOG_ERR, "Password is rejected with error %d: %s\n", entropy, pwquality_strerror(buf, sizeof(buf), entropy, auxerror));
            switch (entropy) {
            case PWQ_ERROR_MIN_LENGTH:
                return IPAPWD_POLICY_PWD_TOO_SHORT;
            case PWQ_ERROR_PALINDROME:
                return IPAPWD_POLICY_PWD_PALINDROME;
            case PWQ_ERROR_MAX_CONSECUTIVE:
                return IPAPWD_POLICY_PWD_CONSECUTIVE;
            case PWQ_ERROR_MAX_SEQUENCE:
                return IPAPWD_POLICY_PWD_SEQUENCE;
            case PWQ_ERROR_CRACKLIB_CHECK:
                return IPAPWD_POLICY_PWD_DICT_WORD;
            case PWQ_ERROR_USER_CHECK:
                return IPAPWD_POLICY_PWD_USER;
            default:
                return IPAPWD_POLICY_PWD_COMPLEXITY;
            }
 
#ifdef TEST
        } else {
            fprintf(stderr, "Password '%s' is ok, entropy is %d\n", password, entropy);
#endif
        }
    }
#endif /* USE_PWQUALITY */

    if (pwd_history) {
        char *hash;
        int i;

        for (i = 0; pwd_history[i]; i++) {
            hash = pwd_history[i] + GENERALIZED_TIME_LENGTH;

            ret = ipapwd_cmp_password(password, hash);
            if (ret == 0) {
                return IPAPWD_POLICY_PWD_IN_HISTORY;
            }
        }
    }

    return IPAPWD_POLICY_OK;
}

char * IPAPWD_ERROR_STRINGS[] = {
    "Password is OK",
    "Account expired",
    "Too soon to change password",
    "Password is too short",
    "Password reuse not permitted",
    "Password is too simple",
    "Password has too many consecutive characters",
    "Password contains a monotonic sequence",
    "Password is based on a dictionary word",
    "Password is a palindrone",
    "Password contains username"
};

char * IPAPWD_ERROR_STRING_GENERAL = "Password does not meet the policy requirements";

char * ipapwd_error2string(enum ipapwd_error err) {
   if (err < 0 || err > IPAPWD_POLICY_PWD_USER) {
       /* IPAPWD_POLICY_ERROR or out of boundary, return general error */
       return IPAPWD_ERROR_STRING_GENERAL;
   }

   return IPAPWD_ERROR_STRINGS[err];
}

/**
* @brief    Generate a new password history using the new password
*
* @param password           Clear text password
* @param cur_time           Current time, usually time(NULL)
* @param history_length     The history max length
* @param pwd_history        The current password history array (can be NULL)
* @param new_pwd_history    The new password history array (must be freed by
*                           caller)
*
* @return   0 on success, IPAPWD_POLICY_ERROR on error.
*/
int ipapwd_generate_new_history(char *password,
                                time_t cur_time,
                                int history_length,
                                char **pwd_history,
                                char ***new_pwd_history,
                                int *new_pwd_hlen)
{
    unsigned char *hash = NULL;
    unsigned int hash_len;
    char *new_element;
    char **ordered = NULL;
    int c, i, n;
    int len;
    int ret;

    if (history_length == 0) {
        return EINVAL;
    }

    /* hardcode best hash we know about for now */
    ret = ipapwd_hash_password(password, DEFAULT_HASH_TYPE, NULL,
                               &hash, &hash_len);
    if (ret != 0) {
        return IPAPWD_POLICY_ERROR;
    }

    new_element = ipapwd_hash_to_history(cur_time, DEFAULT_HASH_TYPE,
                                         hash, hash_len);
    if (!new_element) {
        ret = IPAPWD_POLICY_ERROR;
        goto done;
    }

    for (c = 0; pwd_history && pwd_history[c]; c++) /* count */ ;

    if (c < history_length) {
        c = history_length;
    }

    ordered = calloc(c + 1, sizeof(char *));
    if (!ordered) {
        ret = IPAPWD_POLICY_ERROR;
        goto done;
    }

    for (i = 0, n = 0; pwd_history && pwd_history[i]; i++) {
        len = strlen(pwd_history[i]);
        if (len < GENERALIZED_TIME_LENGTH) {
            /* garbage, ignore */
            continue;
        }
        ordered[n] = strdup(pwd_history[i]);
        if (!ordered[n]) {
            ret = IPAPWD_POLICY_ERROR;
            goto done;
        }
        n++;
    }

    if (n) {
        qsort(ordered, n, sizeof(char *), ipapwd_gentime_cmp);
    }

    if (n >= history_length) {
        for (i = history_length; i < n; i++) {
            free(ordered[i]);
        }
        n = history_length;
    } else {
        n++;
    }
    ordered[n - 1] = new_element;
    ordered[n] = NULL;

    *new_pwd_history = ordered;
    *new_pwd_hlen = n;
    ordered = NULL;
    ret = IPAPWD_POLICY_OK;

done:
    free(ordered);
    free(hash);
    return ret;
}

#define PROC_SYS_FIPS "/proc/sys/crypto/fips_enabled"

bool ipapwd_fips_enabled(void)
{
    int fd;
    ssize_t len;
    char buf[8];

    fd = open(PROC_SYS_FIPS, O_RDONLY);
    if (fd != -1) {
        len = read(fd, buf, sizeof(buf));
        close(fd);
        /* Assume FIPS in enabled if PROC_SYS_FIPS contains a non-0 value
         * similar to the is_fips_enabled() check in
         * ipaplatform/redhat/tasks.py */
        if (!(len == 2 && buf[0] == '0' && buf[1] == '\n')) {
            return true;
        }
    }

    return false;
}
