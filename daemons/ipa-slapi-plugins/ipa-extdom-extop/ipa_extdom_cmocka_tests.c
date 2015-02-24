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

int main(int argc, const char *argv[])
{
    const UnitTest tests[] = {
        unit_test(test_getpwnam_r_wrapper),
        unit_test(test_getpwuid_r_wrapper),
        unit_test(test_getgrnam_r_wrapper),
        unit_test(test_getgrgid_r_wrapper),
    };

    return run_tests(tests);
}
