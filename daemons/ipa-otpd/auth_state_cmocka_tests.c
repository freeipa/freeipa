/*
 * FreeIPA 2FA companion daemon - authentication state tests
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

#include "auth_state.h"

#define TEST_METHOD "passkey"
#define TEST_PRINCIPAL "user@EXAMPLE.TEST"
#define TEST_PAYLOAD "dGVzdC1jaGFsbGVuZ2U="
#define TEST_TTL 300

static const unsigned char test_magic[] = {
    'I', 'P', 'A', 'A', 'U', 'T', 'H', 2
};

struct test_state_header {
    unsigned char magic[sizeof(test_magic)];
    uint32_t method_len;
    uint32_t principal_len;
    uint32_t payload_len;
    uint32_t ttl;
};

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
    struct dirent *state_entry;
    DIR *stream;
    DIR *state_stream;
    char path[PATH_MAX];
    char state_path[PATH_MAX];

    stream = opendir(dir);
    assert_non_null(stream);
    while ((entry = readdir(stream)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        assert_true(snprintf(path, sizeof(path), "%s/%s", dir,
                             entry->d_name) < (int)sizeof(path));
        state_stream = opendir(path);
        assert_non_null(state_stream);
        while ((state_entry = readdir(state_stream)) != NULL) {
            if (state_entry->d_name[0] == '.') {
                continue;
            }
            assert_true(snprintf(state_path, sizeof(state_path), "%s/%s",
                                 path, state_entry->d_name) <
                        (int)sizeof(state_path));
            assert_int_equal(unlink(state_path), 0);
        }
        closedir(state_stream);
        assert_int_equal(rmdir(path), 0);
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

    ret = auth_state_issue(dir, TEST_METHOD,
                           TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                           TEST_PAYLOAD, strlen(TEST_PAYLOAD), TEST_TTL,
                           &state);
    assert_int_equal(ret, 0);
    assert_non_null(state);
    assert_int_equal(strlen(state), 64);
    return state;
}

static void build_state_path(char path[PATH_MAX], const char *dir,
                             const char *token)
{
    int ret;

    ret = snprintf(path, PATH_MAX, "%s/%.2s/%s", dir, token, token);
    assert_true(ret > 0 && ret < PATH_MAX);
}

static void set_state_mtime(const char *dir, const char *token, time_t mtime)
{
    char path[PATH_MAX];
    struct timespec times[2];

    build_state_path(path, dir, token);
    times[0].tv_sec = mtime;
    times[0].tv_nsec = 0;
    times[1] = times[0];
    assert_int_equal(utimensat(AT_FDCWD, path, times, 0), 0);
}

static void assert_state_removed(const char *dir, const char *token)
{
    char path[PATH_MAX];

    build_state_path(path, dir, token);
    assert_int_equal(access(path, F_OK), -1);
    assert_int_equal(errno, ENOENT);
}

static void test_state_is_single_use(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    int ret;

    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, 0);
    assert_int_equal(payload_len, strlen(TEST_PAYLOAD));
    assert_memory_equal(payload, TEST_PAYLOAD, payload_len);
    auth_state_free(payload, payload_len);

    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, ENOENT);
    free(token);
}

static void test_concurrent_consume_has_one_winner(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    int gate[2];
    int statuses[2];
    pid_t children[2];
    int i;

    if (pipe(gate) != 0) {
        fail_msg("pipe failed: %s", strerror(errno));
    }
    for (i = 0; i < 2; i++) {
        children[i] = fork();
        if (children[i] < 0) {
            fail_msg("fork failed: %s", strerror(errno));
        }
        if (children[i] == 0) {
            unsigned char start;
            void *payload = NULL;
            size_t payload_len = 0;
            int ret;

            close(gate[1]);
            if (read(gate[0], &start, 1) != 1) {
                _exit(2);
            }
            ret = auth_state_consume(dir, token, TEST_METHOD,
                                     TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                                     &payload, &payload_len);
            auth_state_free(payload, payload_len);
            _exit(ret == 0 ? 0 : 1);
        }
    }

    close(gate[0]);
    assert_int_equal(write(gate[1], "xx", 2), 2);
    close(gate[1]);
    for (i = 0; i < 2; i++) {
        assert_int_equal(waitpid(children[i], &statuses[i], 0), children[i]);
        assert_true(WIFEXITED(statuses[i]));
    }
    assert_int_equal(WEXITSTATUS(statuses[0]) + WEXITSTATUS(statuses[1]), 1);
    free(token);
}

static void test_binary_payload_round_trip(void **state)
{
    const char *dir = *state;
    const unsigned char expected[] = { 0x41, 0x00, 0x42, 0xff };
    char *token = NULL;
    void *payload = NULL;
    size_t payload_len = 0;
    int ret;

    ret = auth_state_issue(dir, TEST_METHOD,
                           TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                           expected, sizeof(expected), TEST_TTL, &token);
    assert_int_equal(ret, 0);
    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, 0);
    assert_int_equal(payload_len, sizeof(expected));
    assert_memory_equal(payload, expected, sizeof(expected));
    auth_state_free(payload, payload_len);
    free(token);
}

static void test_long_ttl_round_trip(void **state)
{
    const char *dir = *state;
    char *token = NULL;
    void *payload = NULL;
    size_t payload_len = 0;
    int ret;

    ret = auth_state_issue(dir, TEST_METHOD,
                           TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                           TEST_PAYLOAD, strlen(TEST_PAYLOAD), 7200, &token);
    assert_int_equal(ret, 0);
    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, 0);
    assert_memory_equal(payload, TEST_PAYLOAD, payload_len);
    auth_state_free(payload, payload_len);
    free(token);
}

static void test_state_is_bound_to_method(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    int ret;

    ret = auth_state_consume(dir, token, "idp",
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, EACCES);
    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, 0);
    auth_state_free(payload, payload_len);
    free(token);
}

static void test_state_is_bound_to_principal(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    int ret;

    ret = auth_state_consume(dir, token, TEST_METHOD,
                             "other@EXAMPLE.TEST", strlen("other@EXAMPLE.TEST"),
                             &payload, &payload_len);
    assert_int_equal(ret, EACCES);
    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, 0);
    auth_state_free(payload, payload_len);
    free(token);
}

static void test_invalid_tokens_are_rejected(void **state)
{
    const char *dir = *state;
    const char *non_hex =
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    void *payload = NULL;
    size_t payload_len = 0;

    assert_int_equal(auth_state_consume(
                         dir, "short", TEST_METHOD,
                         TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                         &payload, &payload_len), EINVAL);
    assert_int_equal(auth_state_consume(
                         dir, non_hex, TEST_METHOD,
                         TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                         &payload, &payload_len), EINVAL);
}

static void test_expired_state_is_removed(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    int ret;

    set_state_mtime(dir, token, time(NULL) - TEST_TTL - 1);
    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, EACCES);
    assert_state_removed(dir, token);
    free(token);
}

static void test_ttl_boundary_is_accepted(void **state)
{
    const char *dir = *state;
    struct timespec now;
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    int ret;

    assert_int_equal(clock_gettime(CLOCK_REALTIME, &now), 0);
    if (now.tv_nsec > 500000000) {
        struct timespec delay = { 0, 1000000000 - now.tv_nsec + 10000000 };
        assert_int_equal(nanosleep(&delay, NULL), 0);
    }
    set_state_mtime(dir, token, time(NULL) - TEST_TTL);
    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, 0);
    auth_state_free(payload, payload_len);
    free(token);
}

static void test_future_state_is_removed(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    int ret;

    set_state_mtime(dir, token, time(NULL) + TEST_TTL + 1);
    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, EACCES);
    assert_state_removed(dir, token);
    free(token);
}

static void test_malformed_state_is_removed(void **state)
{
    const char *dir = *state;
    struct test_state_header header = { 0 };
    char path[PATH_MAX];
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    int fd;
    int ret;

    memcpy(header.magic, test_magic, sizeof(test_magic));
    header.method_len = strlen(TEST_METHOD);
    header.principal_len = strlen(TEST_PRINCIPAL);
    header.payload_len = 0;
    header.ttl = TEST_TTL;
    build_state_path(path, dir, token);
    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        fail_msg("open failed: %s", strerror(errno));
    }
    assert_int_equal(write(fd, &header, sizeof(header)), sizeof(header));
    assert_int_equal(close(fd), 0);

    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, EACCES);
    assert_state_removed(dir, token);
    free(token);
}

static void test_bad_magic_is_removed(void **state)
{
    const char *dir = *state;
    char path[PATH_MAX];
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    unsigned char bad_magic = 0;
    int fd;
    int ret;

    build_state_path(path, dir, token);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        fail_msg("open failed: %s", strerror(errno));
    }
    assert_int_equal(write(fd, &bad_magic, 1), 1);
    assert_int_equal(close(fd), 0);

    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, EACCES);
    assert_state_removed(dir, token);
    free(token);
}

static void test_trailing_data_is_rejected(void **state)
{
    const char *dir = *state;
    char path[PATH_MAX];
    char *token = issue_state(dir);
    void *payload = NULL;
    size_t payload_len = 0;
    unsigned char trailing = 0;
    int fd;
    int ret;

    build_state_path(path, dir, token);
    fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        fail_msg("open failed: %s", strerror(errno));
    }
    assert_int_equal(write(fd, &trailing, 1), 1);
    assert_int_equal(close(fd), 0);

    ret = auth_state_consume(dir, token, TEST_METHOD,
                             TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                             &payload, &payload_len);
    assert_int_equal(ret, EACCES);
    assert_state_removed(dir, token);
    free(token);
}

static void test_issue_validation_and_missing_dir(void **state)
{
    const char *dir = *state;
    char *token = NULL;

    assert_int_equal(auth_state_issue(
                         dir, NULL, TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                         TEST_PAYLOAD, strlen(TEST_PAYLOAD), TEST_TTL,
                         &token), EINVAL);
    assert_int_equal(auth_state_issue(
                         dir, TEST_METHOD, NULL, strlen(TEST_PRINCIPAL),
                         TEST_PAYLOAD, strlen(TEST_PAYLOAD), TEST_TTL,
                         &token), EINVAL);
    assert_int_equal(auth_state_issue(
                         dir, TEST_METHOD, TEST_PRINCIPAL, 0,
                         TEST_PAYLOAD, strlen(TEST_PAYLOAD), TEST_TTL,
                         &token), EINVAL);
    assert_int_equal(auth_state_issue(
                         dir, TEST_METHOD, TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                         NULL, strlen(TEST_PAYLOAD), TEST_TTL, &token), EINVAL);
    assert_int_equal(auth_state_issue(
                         dir, TEST_METHOD, TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                         TEST_PAYLOAD, 0, TEST_TTL, &token), EINVAL);
    assert_int_equal(auth_state_issue(
                         dir, TEST_METHOD, TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                         TEST_PAYLOAD, strlen(TEST_PAYLOAD), 0, &token), EINVAL);
    assert_int_equal(rmdir(dir), 0);
    assert_int_equal(auth_state_issue(
                         dir, TEST_METHOD, TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                         TEST_PAYLOAD, strlen(TEST_PAYLOAD), TEST_TTL,
                         &token), ENOENT);
    assert_int_equal(mkdir(dir, 0700), 0);
}

static void test_discard_is_idempotent(void **state)
{
    const char *dir = *state;
    char *token = issue_state(dir);

    auth_state_discard(dir, "invalid");
    auth_state_discard(dir, token);
    assert_state_removed(dir, token);
    auth_state_discard(dir, token);
    free(token);
}

static void test_store_is_bounded(void **state)
{
    const char *dir = *state;
    struct dirent *entry;
    struct dirent *state_entry;
    DIR *stream;
    DIR *state_stream;
    char path[PATH_MAX];
    char *token = NULL;
    size_t shard_count;
    size_t total = 0;
    size_t issued = 0;
    int ret = 0;

    while (issued <= AUTH_STATE_TOTAL_MAX) {
        ret = auth_state_issue(dir, TEST_METHOD,
                               TEST_PRINCIPAL, strlen(TEST_PRINCIPAL),
                               TEST_PAYLOAD, strlen(TEST_PAYLOAD), TEST_TTL,
                               &token);
        if (ret == ENOSPC) {
            break;
        }
        assert_int_equal(ret, 0);
        free(token);
        token = NULL;
        issued++;
    }
    assert_int_equal(ret, ENOSPC);
    assert_true(issued <= AUTH_STATE_TOTAL_MAX);

    stream = opendir(dir);
    assert_non_null(stream);
    while ((entry = readdir(stream)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        assert_true(snprintf(path, sizeof(path), "%s/%s", dir,
                             entry->d_name) < (int)sizeof(path));
        state_stream = opendir(path);
        assert_non_null(state_stream);
        shard_count = 0;
        while ((state_entry = readdir(state_stream)) != NULL) {
            if (state_entry->d_name[0] != '.') {
                shard_count++;
            }
        }
        closedir(state_stream);
        assert_true(shard_count <= AUTH_STATE_SHARD_MAX);
        total += shard_count;
    }
    closedir(stream);
    assert_int_equal(total, issued);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_state_is_single_use,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(
                                        test_concurrent_consume_has_one_winner,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_binary_payload_round_trip,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_long_ttl_round_trip,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_state_is_bound_to_method,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_state_is_bound_to_principal,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_invalid_tokens_are_rejected,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_expired_state_is_removed,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_ttl_boundary_is_accepted,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_future_state_is_removed,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_malformed_state_is_removed,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_bad_magic_is_removed,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_trailing_data_is_rejected,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_issue_validation_and_missing_dir,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_discard_is_idempotent,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_store_is_bounded,
                                        setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
