/*
 * Copyright (C) 2020  FreeIPA Contributors see COPYING for license
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ipa_pwd.h"

static void
set_policy(struct ipapwd_policy *policy,
               int min_pwd_length, int min_diff_chars, int max_repeat,
               int max_sequence, int max_class_repeat, int dict_check,
               int user_check, int dcredit, int ucredit, int lcredit,
               int ocredit)
               
{
    /* defaults for things we aren't testing */
    policy->min_pwd_life = 0;
    policy->max_pwd_life = 0;
    policy->history_length = 0;

    /* Note: min password length in libpwqualty is hardcoded at 6 */
    policy->min_pwd_length = min_pwd_length;
    policy->min_complexity = min_diff_chars;
    policy->max_repeat = max_repeat;
    policy->max_sequence = max_sequence;
    policy->max_classrepeat = max_class_repeat;
    policy->dictcheck = dict_check;
    policy->usercheck = user_check;
    policy->dcredit = dcredit;
    policy->ucredit = ucredit;
    policy->lcredit = lcredit;
    policy->ocredit = ocredit;
}

int main(int argc, const char *argv[]) {
    (void) argc;
    (void) argv;

    struct ipapwd_policy policy = {0}; 

    /* No policy applied */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "Secret123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    assert(ipapwd_check_policy(&policy, "password", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    assert(ipapwd_check_policy(&policy, "abcddcba", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);

    /* Check that with no policy the IPA minimum is in force */
    assert(ipapwd_check_policy(&policy, "abc", NULL, 3, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);

    /* Max repeats of 1 */
    set_policy(&policy, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "password", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_CONSECUTIVE);
    assert(ipapwd_check_policy(&policy, "Assembly", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_CONSECUTIVE);

    /* Minimum length lower than libpwquality allows (6) */
    assert(ipapwd_check_policy(&policy, "abc", NULL, 3, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_TOO_SHORT);

    /* Max repeats of 2 */
    set_policy(&policy, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "password", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    assert(ipapwd_check_policy(&policy, "Assembly", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    assert(ipapwd_check_policy(&policy, "permisssive", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_CONSECUTIVE);

    /* Max sequence of 1 */
    set_policy(&policy, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "abacab", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_SEQUENCE);
    assert(ipapwd_check_policy(&policy, "AbacAb", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_SEQUENCE);

    /* Max sequence of 2 */
    set_policy(&policy, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "AbacAb", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    assert(ipapwd_check_policy(&policy, "abacabc", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_SEQUENCE);

    /* Palindrone */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);  /* Note there is no policy */
    assert(ipapwd_check_policy(&policy, "password", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    assert(ipapwd_check_policy(&policy, "abccba", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0);  /* Set anything */
    assert(ipapwd_check_policy(&policy, "abccba", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_PALINDROME);

    /* Dictionary check */
    set_policy(&policy, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "password", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_DICT_WORD);
    assert(ipapwd_check_policy(&policy, "Secret123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_DICT_WORD);

    /* User check */
    assert(ipapwd_check_policy(&policy, "userPDQ123", "user", 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "userPDQ123", "user", 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_USER);

    /* Digit check.
     * Negative == minimum # of digits required
     * Zero == skip check
     * Positive == amount to add towards min length
     */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "Secret123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, -19, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "Secret123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_MIN_DIGITS);

    /* dcredit > 0 gives a "credit" to a shorter password for having
     * complexity so allows a shorter than minimum length password.
     * Reminder that with libpwquality the minimum password len is 
     * hardcoded at 6.
     */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "abcd1", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "ab21", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);

    /* Verify that no credits are added automatically. We need to set some
     * pwquality option in order to validate it, so set length.
     */
    set_policy(&policy, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "abcd1", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_TOO_SHORT);

    /* Upper check.
     * Negative == minimum # of uppers required
     * Zero == skip check
     * Positive == amount to add towards min length
     */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0);
    assert(ipapwd_check_policy(&policy, "Secret123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, -19, 0, 0);
    assert(ipapwd_check_policy(&policy, "Secret123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_MIN_UPPERS);

    /* ucredit > 0 gives a "credit" to a shorter password for having
     * complexity so allows a shorter than minimum length password.
     * Reminder that with libpwquality the minimum password len is 
     * hardcoded at 6.
     */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0);
    assert(ipapwd_check_policy(&policy, "abcdE", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0);
    assert(ipapwd_check_policy(&policy, "abDE", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);

    /* Verify that no credits are added automatically. We need to set some
     * pwquality option in order to validate it, so set length.
     */
    set_policy(&policy, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "abcdE", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_TOO_SHORT);

    /* Lower check.
     * Negative == minimum # of uppers required
     * Zero == skip check
     * Positive == amount to add towards min length
     */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0);
    assert(ipapwd_check_policy(&policy, "SECREt123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, 0, -19, 0);
    assert(ipapwd_check_policy(&policy, "SECREt123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_MIN_LOWERS);

    /* lcredit > 0 gives a "credit" to a shorter password for having
     * complexity so allows a shorter than minimum length password.
     * Reminder that with libpwquality the minimum password len is 
     * hardcoded at 6.
     */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0);
    assert(ipapwd_check_policy(&policy, "ABCEe", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0);
    assert(ipapwd_check_policy(&policy, "ABcd", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);

    /* Verify that no credits are added automatically. We need to set some
     * pwquality option in order to validate it, so set length.
     */
    set_policy(&policy, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert(ipapwd_check_policy(&policy, "ABCDE", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_TOO_SHORT);

    /* Mixed credit checks */
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, -2, -2, -2, 0);
    assert(ipapwd_check_policy(&policy, "SecreT123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_OK);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, -2, -2, -2, 0);
    assert(ipapwd_check_policy(&policy, "SECREt123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_MIN_LOWERS);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, -2, -2, -2, 0);
    assert(ipapwd_check_policy(&policy, "Secret123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_MIN_UPPERS);
    set_policy(&policy, 0, 0, 0, 0, 0, 0, 0, -1, -1, -1, -1);
    assert(ipapwd_check_policy(&policy, "SecreT123", NULL, 0, 0, 0, 0, NULL) == IPAPWD_POLICY_PWD_MIN_OTHERS);

    return 0;
}
