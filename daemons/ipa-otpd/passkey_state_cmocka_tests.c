/*
 * FreeIPA 2FA companion daemon - passkey state tests
 *
 * Copyright (C) 2026  FreeIPA Contributors
 * see file 'COPYING' for use and warranty information
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

#include "passkey_state.h"

#define TEST_PRINCIPAL "user@EXAMPLE.TEST"
#define TEST_CHALLENGE "dGVzdC1jaGFsbGVuZ2U="

static int setup(void **state)
{
    char *dir = strdup("/tmp/ipa-otpd-state-XXXXXX");

    assert_non_null(dir);
    assert_non_null(mkdtemp(dir));
    *state = dir;
    return 0;
}

static int teardown(void **state)
{
    char *dir = *state;
    struct dirent *entry;
    DIR *stream;
    char path[PATH_MAX];

    stream = opendir(dir);
    assert_non_null(stream);
    while ((entry = readdir(stream)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        assert_true(snprintf(path, sizeof(path), "%s/%s", dir,
                             entry->d_name) < (int)sizeof(path));
        assert_int_equal(unlink(path), 0);
    }
    closedir(stream);
    assert_int_equal(rmdir(dir), 0);
    free(dir);
    return 0;
}

static char *issue_state(const char *dir)
{
    char *state = NULL;
    int ret;

    ret = passkey_state_issue(dir, TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                              TEST_CHALLENGE, &state);
    assert_int_equal(ret, 0);
    assert_non_null(state);
    assert_int_equal(strlen(state), 64);
    return state;
}

static void test_state_is_single_use(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    int ret;

    ret = passkey_state_consume(dir, token, TEST_PRINCIPAL,
                                strlen(TEST_PRINCIPAL), TEST_CHALLENGE);
    assert_int_equal(ret, 0);

    ret = passkey_state_consume(dir, token, TEST_PRINCIPAL,
                                strlen(TEST_PRINCIPAL), TEST_CHALLENGE);
    assert_int_equal(ret, ENOENT);
    free(token);
}

static void test_state_is_bound_to_challenge(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    int ret;

    ret = passkey_state_consume(dir, token, TEST_PRINCIPAL,
                                strlen(TEST_PRINCIPAL), "wrong-challenge");
    assert_int_equal(ret, EACCES);

    ret = passkey_state_consume(dir, token, TEST_PRINCIPAL,
                                strlen(TEST_PRINCIPAL), TEST_CHALLENGE);
    assert_int_equal(ret, 0);
    free(token);
}

static void test_state_is_bound_to_principal(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    int ret;

    ret = passkey_state_consume(dir, token, "other@EXAMPLE.TEST",
                                strlen("other@EXAMPLE.TEST"), TEST_CHALLENGE);
    assert_int_equal(ret, EACCES);

    ret = passkey_state_consume(dir, token, TEST_PRINCIPAL,
                                strlen(TEST_PRINCIPAL), TEST_CHALLENGE);
    assert_int_equal(ret, 0);
    free(token);
}

static void test_expired_state_is_rejected(void **state)
{
    const char *dir = *state;
    char path[PATH_MAX];
    char *token = issue_state(dir);
    struct timespec times[2];
    int ret;

    assert_true(snprintf(path, sizeof(path), "%s/%s", dir, token) <
                (int)sizeof(path));
    times[0].tv_sec = time(NULL) - PASSKEY_STATE_TTL - 1;
    times[0].tv_nsec = 0;
    times[1] = times[0];
    assert_int_equal(utimensat(AT_FDCWD, path, times, 0), 0);

    ret = passkey_state_consume(dir, token, TEST_PRINCIPAL,
                                strlen(TEST_PRINCIPAL), TEST_CHALLENGE);
    assert_int_equal(ret, EACCES);
    assert_int_equal(access(path, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    free(token);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_state_is_single_use,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_state_is_bound_to_challenge,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_state_is_bound_to_principal,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_expired_state_is_rejected,
                                        setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
