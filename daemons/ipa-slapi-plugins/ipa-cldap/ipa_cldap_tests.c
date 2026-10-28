/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

    Tests for FreeIPA CLDAP plugin

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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ipa_cldap.h"

void test_make_netbios_name(void **state)
{
    char *r;
    size_t c;

    struct test_data {
        char *i;
        char *o;
    } d[] = {
        {"abc", "ABC"},
        {"long-host-name-12345", "LONGHOSTNAME123"},
        {"abc.def.123", "ABC"},
        {"####", NULL},
        {NULL, NULL}
    };

    r = make_netbios_name(NULL, NULL);
    assert_null(r);

    for (c = 0; d[c].i != NULL; c++) {
        r = make_netbios_name(NULL, d[c].i);
        if (d[c].o != NULL) {
            assert_string_equal(r, d[c].o);
        } else {
            assert_null(r);
        }
    }
}

int main(int argc, const char *argv[])
{

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_make_netbios_name),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

