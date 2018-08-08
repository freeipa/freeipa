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

#pragma once

#include <stdint.h>
#include <time.h> /* for time_t */

/* 90 days default pwd max lifetime */
#define IPAPWD_DEFAULT_PWDLIFE (90 * 24 *3600)
#define IPAPWD_DEFAULT_MINLEN 0

/* 1 Jan 2038, 00:00 GMT */
#define IPAPWD_END_OF_TIME 2145916800

/*
 * IMPORTANT: please update error string table in ipa_pwd.c if you change this
 * error code table.
 */
enum ipapwd_error {
    IPAPWD_POLICY_ERROR = -1,
    IPAPWD_POLICY_OK = 0,
    IPAPWD_POLICY_ACCOUNT_EXPIRED = 1,
    IPAPWD_POLICY_PWD_TOO_YOUNG = 2,
    IPAPWD_POLICY_PWD_TOO_SHORT = 3,
    IPAPWD_POLICY_PWD_IN_HISTORY = 4,
    IPAPWD_POLICY_PWD_COMPLEXITY = 5
};

struct ipapwd_policy {
    int min_pwd_life;
    int max_pwd_life;
    int min_pwd_length;
    int history_length;
    int min_complexity;
    int max_fail;
    int failcnt_interval;
    int lockout_duration;
};

time_t ipapwd_gentime_to_time_t(char *timestr);

int ipapwd_check_policy(struct ipapwd_policy *policy,
                        char *password,
                        time_t cur_time,
                        time_t acct_expiration,
                        time_t pwd_expiration,
                        time_t last_pwd_change,
                        char **pwd_history);

char * ipapwd_error2string(enum ipapwd_error err);

int ipapwd_generate_new_history(char *password,
                                time_t cur_time,
                                int history_length,
                                char **pwd_history,
                                char ***new_pwd_history,
                                int *new_pwd_hlen);

int encode_nt_key(char *newPasswd, uint8_t *nt_key);

bool ipapwd_fips_enabled(void);
