/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

    Extdom tests

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <sys/types.h>
#include <pwd.h>


#include "ipa_extdom.h"

#define MAX_BUF (1024*1024*1024)

void test_getpwnam_r_wrapper(void **state)
{
    int ret;
    struct passwd pwd;
    char *buf;
    size_t buf_len;

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getpwnam_r_wrapper(MAX_BUF, "non_exisiting_user", &pwd, &buf,
                             &buf_len);
    assert_int_equal(ret, ENOENT);

    ret = getpwnam_r_wrapper(MAX_BUF, "user", &pwd, &buf, &buf_len);
    assert_int_equal(ret, 0);
    assert_string_equal(pwd.pw_name, "user");
    assert_string_equal(pwd.pw_passwd, "x");
    assert_int_equal(pwd.pw_uid, 12345);
    assert_int_equal(pwd.pw_gid, 23456);
    assert_string_equal(pwd.pw_gecos, "gecos");
    assert_string_equal(pwd.pw_dir, "/home/user");
    assert_string_equal(pwd.pw_shell, "/bin/shell");
    free(buf);

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getpwnam_r_wrapper(MAX_BUF, "user_big", &pwd, &buf, &buf_len);
    assert_int_equal(ret, 0);
    assert_string_equal(pwd.pw_name, "user_big");
    assert_string_equal(pwd.pw_passwd, "x");
    assert_int_equal(pwd.pw_uid, 12346);
    assert_int_equal(pwd.pw_gid, 23457);
    assert_int_equal(strlen(pwd.pw_gecos), 4000 * strlen("gecos"));
    assert_string_equal(pwd.pw_dir, "/home/user_big");
    assert_string_equal(pwd.pw_shell, "/bin/shell");
    free(buf);

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getpwnam_r_wrapper(1024, "user_big", &pwd, &buf, &buf_len);
    assert_int_equal(ret, ERANGE);
    free(buf);
}

void test_getpwuid_r_wrapper(void **state)
{
    int ret;
    struct passwd pwd;
    char *buf;
    size_t buf_len;

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getpwuid_r_wrapper(MAX_BUF, 99999, &pwd, &buf, &buf_len);
    assert_int_equal(ret, ENOENT);

    ret = getpwuid_r_wrapper(MAX_BUF, 12345, &pwd, &buf, &buf_len);
    assert_int_equal(ret, 0);
    assert_string_equal(pwd.pw_name, "user");
    assert_string_equal(pwd.pw_passwd, "x");
    assert_int_equal(pwd.pw_uid, 12345);
    assert_int_equal(pwd.pw_gid, 23456);
    assert_string_equal(pwd.pw_gecos, "gecos");
    assert_string_equal(pwd.pw_dir, "/home/user");
    assert_string_equal(pwd.pw_shell, "/bin/shell");
    free(buf);

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getpwuid_r_wrapper(MAX_BUF, 12346, &pwd, &buf, &buf_len);
    assert_int_equal(ret, 0);
    assert_string_equal(pwd.pw_name, "user_big");
    assert_string_equal(pwd.pw_passwd, "x");
    assert_int_equal(pwd.pw_uid, 12346);
    assert_int_equal(pwd.pw_gid, 23457);
    assert_int_equal(strlen(pwd.pw_gecos), 4000 * strlen("gecos"));
    assert_string_equal(pwd.pw_dir, "/home/user_big");
    assert_string_equal(pwd.pw_shell, "/bin/shell");
    free(buf);

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getpwuid_r_wrapper(1024, 12346, &pwd, &buf, &buf_len);
    assert_int_equal(ret, ERANGE);
    free(buf);
}

void test_getgrnam_r_wrapper(void **state)
{
    int ret;
    struct group grp;
    char *buf;
    size_t buf_len;

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getgrnam_r_wrapper(MAX_BUF, "non_exisiting_group", &grp, &buf, &buf_len);
    assert_int_equal(ret, ENOENT);

    ret = getgrnam_r_wrapper(MAX_BUF, "group", &grp, &buf, &buf_len);
    assert_int_equal(ret, 0);
    assert_string_equal(grp.gr_name, "group");
    assert_string_equal(grp.gr_passwd, "x");
    assert_int_equal(grp.gr_gid, 11111);
    assert_string_equal(grp.gr_mem[0], "member0001");
    assert_string_equal(grp.gr_mem[1], "member0002");
    assert_null(grp.gr_mem[2]);
    free(buf);

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getgrnam_r_wrapper(MAX_BUF, "group_big", &grp, &buf, &buf_len);
    assert_int_equal(ret, 0);
    assert_string_equal(grp.gr_name, "group_big");
    assert_string_equal(grp.gr_passwd, "x");
    assert_int_equal(grp.gr_gid, 22222);
    assert_string_equal(grp.gr_mem[0], "member0001");
    assert_string_equal(grp.gr_mem[1], "member0002");
    free(buf);

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getgrnam_r_wrapper(1024, "group_big", &grp, &buf, &buf_len);
    assert_int_equal(ret, ERANGE);
    free(buf);
}

void test_getgrgid_r_wrapper(void **state)
{
    int ret;
    struct group grp;
    char *buf;
    size_t buf_len;

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getgrgid_r_wrapper(MAX_BUF, 99999, &grp, &buf, &buf_len);
    assert_int_equal(ret, ENOENT);

    ret = getgrgid_r_wrapper(MAX_BUF, 11111, &grp, &buf, &buf_len);
    assert_int_equal(ret, 0);
    assert_string_equal(grp.gr_name, "group");
    assert_string_equal(grp.gr_passwd, "x");
    assert_int_equal(grp.gr_gid, 11111);
    assert_string_equal(grp.gr_mem[0], "member0001");
    assert_string_equal(grp.gr_mem[1], "member0002");
    assert_null(grp.gr_mem[2]);
    free(buf);

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getgrgid_r_wrapper(MAX_BUF, 22222, &grp, &buf, &buf_len);
    assert_int_equal(ret, 0);
    assert_string_equal(grp.gr_name, "group_big");
    assert_string_equal(grp.gr_passwd, "x");
    assert_int_equal(grp.gr_gid, 22222);
    assert_string_equal(grp.gr_mem[0], "member0001");
    assert_string_equal(grp.gr_mem[1], "member0002");
    free(buf);

    ret = get_buffer(&buf_len, &buf);
    assert_int_equal(ret, 0);

    ret = getgrgid_r_wrapper(1024, 22222, &grp, &buf, &buf_len);
    assert_int_equal(ret, ERANGE);
    free(buf);
}

void test_get_user_grouplist(void **state)
{
    int ret;
    size_t ngroups;
    gid_t *groups;
    size_t c;

    /* This is a bit odd behaviour of getgrouplist() it does not check if the
     * user exists, only if memberships of the user can be found. */
    ret = get_user_grouplist("non_exisiting_user", 23456, &ngroups, &groups);
    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(ngroups, 1);
    assert_int_equal(groups[0], 23456);
    free(groups);

    ret = get_user_grouplist("member0001", 23456, &ngroups, &groups);
    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(ngroups, 3);
    assert_int_equal(groups[0], 23456);
    assert_int_equal(groups[1], 11111);
    assert_int_equal(groups[2], 22222);
    free(groups);

    ret = get_user_grouplist("member0003", 23456, &ngroups, &groups);
    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(ngroups, 2);
    assert_int_equal(groups[0], 23456);
    assert_int_equal(groups[1], 22222);
    free(groups);

    ret = get_user_grouplist("user_big", 23456, &ngroups, &groups);
    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(ngroups, 1001);
    assert_int_equal(groups[0], 23456);
    for (c = 1; c < ngroups; c++) {
        assert_int_equal(groups[c], 29999 + c);
    }
    free(groups);
}

struct test_data {
    struct extdom_req *req;
    struct ipa_extdom_ctx *ctx;
};

void extdom_req_setup(void **state)
{
    struct test_data *test_data;

    test_data = calloc(sizeof(struct test_data), 1);
    assert_non_null(test_data);

    test_data->req = calloc(sizeof(struct extdom_req), 1);
    assert_non_null(test_data->req);

    test_data->ctx = calloc(sizeof(struct ipa_extdom_ctx), 1);
    assert_non_null(test_data->req);

    *state = test_data;
}

void extdom_req_teardown(void **state)
{
    struct test_data *test_data;

    test_data = (struct test_data *) *state;

    free_req_data(test_data->req);
    free(test_data->ctx);
    free(test_data);
}

void test_set_err_msg(void **state)
{
    struct extdom_req *req;
    struct test_data *test_data;

    test_data = (struct test_data *) *state;
    req = test_data->req;

    assert_null(req->err_msg);

    set_err_msg(NULL, NULL);
    assert_null(req->err_msg);

    set_err_msg(req, NULL);
    assert_null(req->err_msg);

    set_err_msg(req, "Test [%s][%d].", "ABCD", 1234);
    assert_non_null(req->err_msg);
    assert_string_equal(req->err_msg, "Test [ABCD][1234].");

    set_err_msg(req, "2nd Test [%s][%d].", "ABCD", 1234);
    assert_non_null(req->err_msg);
    assert_string_equal(req->err_msg, "Test [ABCD][1234].");
}

#define TEST_SID "S-1-2-3-4"
#define TEST_DOMAIN_NAME "DOMAIN"

char res_sid[] = {0x30, 0x0e, 0x0a, 0x01, 0x01, 0x04, 0x09, 0x53, 0x2d, 0x31, \
                  0x2d, 0x32, 0x2d, 0x33, 0x2d, 0x34};
char res_nam[] = {0x30, 0x13, 0x0a, 0x01, 0x02, 0x30, 0x0e, 0x04, 0x06, 0x44, \
                  0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x04, 0x04, 0x74, 0x65, 0x73, \
                  0x74};
char res_uid[] = {0x30, 0x1c, 0x0a, 0x01, 0x03, 0x30, 0x17, 0x04, 0x06, 0x44, \
                  0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x04, 0x04, 0x74, 0x65, 0x73, \
                  0x74, 0x02, 0x02, 0x30, 0x39, 0x02, 0x03, 0x00, 0xd4, 0x31};
char res_gid[] = {0x30, 0x1e, 0x0a, 0x01, 0x04, 0x30, 0x19, 0x04, 0x06, 0x44, \
                  0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x04, 0x0a, 0x74, 0x65, 0x73, \
                  0x74, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x02, 0x03, 0x00, \
                  0xd4, 0x31};

void test_encode(void **state)
{
    int ret;
    struct berval *resp_val;
    struct ipa_extdom_ctx *ctx;
    struct test_data *test_data;

    test_data = (struct test_data *) *state;
    ctx = test_data->ctx;

    ctx->max_nss_buf_size = (128*1024*1024);

    ret = pack_ber_sid(TEST_SID, &resp_val);
    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(sizeof(res_sid), resp_val->bv_len);
    assert_memory_equal(res_sid, resp_val->bv_val, resp_val->bv_len);
    ber_bvfree(resp_val);

    ret = pack_ber_name(TEST_DOMAIN_NAME, "test", &resp_val);
    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(sizeof(res_nam), resp_val->bv_len);
    assert_memory_equal(res_nam, resp_val->bv_val, resp_val->bv_len);
    ber_bvfree(resp_val);

    ret = pack_ber_user(ctx, RESP_USER, TEST_DOMAIN_NAME, "test", 12345, 54321,
                        NULL, NULL, NULL, NULL, &resp_val);
    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(sizeof(res_uid), resp_val->bv_len);
    assert_memory_equal(res_uid, resp_val->bv_val, resp_val->bv_len);
    ber_bvfree(resp_val);

    ret = pack_ber_group(RESP_GROUP, TEST_DOMAIN_NAME, "test_group", 54321,
                         NULL, NULL, &resp_val);
    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(sizeof(res_gid), resp_val->bv_len);
    assert_memory_equal(res_gid, resp_val->bv_val, resp_val->bv_len);
    ber_bvfree(resp_val);
}

char req_sid[] = {0x30, 0x11, 0x0a, 0x01, 0x01, 0x0a, 0x01, 0x01, 0x04, 0x09, \
                  0x53, 0x2d, 0x31, 0x2d, 0x32, 0x2d, 0x33, 0x2d, 0x34};
char req_nam[] = {0x30, 0x16, 0x0a, 0x01, 0x02, 0x0a, 0x01, 0x01, 0x30, 0x0e, \
                  0x04, 0x06, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x04, 0x04, \
                  0x74, 0x65, 0x73, 0x74};
char req_uid[] = {0x30, 0x14, 0x0a, 0x01, 0x03, 0x0a, 0x01, 0x01, 0x30, 0x0c, \
                  0x04, 0x06, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x02, 0x02, \
                  0x30, 0x39};
char req_gid[] = {0x30, 0x15, 0x0a, 0x01, 0x04, 0x0a, 0x01, 0x01, 0x30, 0x0d, \
                  0x04, 0x06, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x02, 0x03, \
                  0x00, 0xd4, 0x31};

void test_decode(void **state)
{
    struct berval req_val;
    struct extdom_req *req;
    int ret;

    req_val.bv_val = req_sid;
    req_val.bv_len = sizeof(req_sid);

    ret = parse_request_data(&req_val, &req);

    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(req->input_type, INP_SID);
    assert_int_equal(req->request_type, REQ_SIMPLE);
    assert_string_equal(req->data.sid, "S-1-2-3-4");
    free_req_data(req);

    req_val.bv_val = req_nam;
    req_val.bv_len = sizeof(req_nam);

    ret = parse_request_data(&req_val, &req);

    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(req->input_type, INP_NAME);
    assert_int_equal(req->request_type, REQ_SIMPLE);
    assert_string_equal(req->data.name.domain_name, "DOMAIN");
    assert_string_equal(req->data.name.object_name, "test");
    free_req_data(req);

    req_val.bv_val = req_uid;
    req_val.bv_len = sizeof(req_uid);

    ret = parse_request_data(&req_val, &req);

    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(req->input_type, INP_POSIX_UID);
    assert_int_equal(req->request_type, REQ_SIMPLE);
    assert_string_equal(req->data.posix_uid.domain_name, "DOMAIN");
    assert_int_equal(req->data.posix_uid.uid, 12345);
    free_req_data(req);

    req_val.bv_val = req_gid;
    req_val.bv_len = sizeof(req_gid);

    ret = parse_request_data(&req_val, &req);

    assert_int_equal(ret, LDAP_SUCCESS);
    assert_int_equal(req->input_type, INP_POSIX_GID);
    assert_int_equal(req->request_type, REQ_SIMPLE);
    assert_string_equal(req->data.posix_gid.domain_name, "DOMAIN");
    assert_int_equal(req->data.posix_gid.gid, 54321);
    free_req_data(req);
}

int main(int argc, const char *argv[])
{
    const UnitTest tests[] = {
        unit_test(test_getpwnam_r_wrapper),
        unit_test(test_getpwuid_r_wrapper),
        unit_test(test_getgrnam_r_wrapper),
        unit_test(test_getgrgid_r_wrapper),
        unit_test(test_get_user_grouplist),
        unit_test_setup_teardown(test_set_err_msg,
                                 extdom_req_setup, extdom_req_teardown),
        unit_test_setup_teardown(test_encode,
                                 extdom_req_setup, extdom_req_teardown),
        unit_test(test_decode),
    };

    return run_tests(tests);
}
