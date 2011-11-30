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
 * Sumit Bose <sbose@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include <check.h>

#include "ipa_extdom.h"
#include "util.h"

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

char res_sid[] = {0x30, 0x0e, 0x0a, 0x01, 0x01, 0x04, 0x09, 0x53, 0x2d, 0x31, \
                  0x2d, 0x32, 0x2d, 0x33, 0x2d, 0x34};
char res_nam[] = {0x30, 0x13, 0x0a, 0x01, 0x02, 0x30, 0x0e, 0x04, 0x06, 0x44, \
                  0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x04, 0x04, 0x74, 0x65, 0x73, \
                  0x74};
char res_uid[] = {0x30, 0x17, 0x0a, 0x01, 0x03, 0x30, 0x12, 0x04, 0x06, 0x44, \
                  0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x04, 0x04, 0x74, 0x65, 0x73, \
                  0x74, 0x02, 0x02, 0x30, 0x39};
char res_gid[] = {0x30, 0x1e, 0x0a, 0x01, 0x04, 0x30, 0x19, 0x04, 0x06, 0x44, \
                  0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x04, 0x0a, 0x74, 0x65, 0x73, \
                  0x74, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x02, 0x03, 0x00, \
                  0xd4, 0x31};

#define TEST_SID "S-1-2-3-4"
#define TEST_DOMAIN_NAME "DOMAIN"

START_TEST(test_encode)
{
    int ret;
    struct extdom_res res;
    struct berval *resp_val;

    res.response_type = RESP_SID;
    res.data.sid = TEST_SID;

    ret = pack_response(&res, &resp_val);

    fail_unless(ret == LDAP_SUCCESS, "pack_response() failed.");
    fail_unless(sizeof(res_sid) == resp_val->bv_len &&
                memcmp(res_sid, resp_val->bv_val, resp_val->bv_len) == 0,
                "Unexpected BER blob.");
    ber_memfree(resp_val);

    res.response_type = RESP_NAME;
    res.data.name.domain_name = TEST_DOMAIN_NAME;
    res.data.name.object_name = "test";

    ret = pack_response(&res, &resp_val);

    fail_unless(ret == LDAP_SUCCESS, "pack_response() failed.");
    fail_unless(sizeof(res_nam) == resp_val->bv_len &&
                memcmp(res_nam, resp_val->bv_val, resp_val->bv_len) == 0,
                "Unexpected BER blob.");
    ber_memfree(resp_val);
}
END_TEST

START_TEST(test_decode)
{
    struct berval req_val;
    struct extdom_req *req;
    int ret;

    req_val.bv_val = req_sid;
    req_val.bv_len = sizeof(req_sid);

    ret = parse_request_data(&req_val, &req);

    fail_unless(ret == LDAP_SUCCESS, "parse_request_data() failed.");
    fail_unless(req->input_type == INP_SID,
                "parse_request_data() returned unexpected input type");
    fail_unless(req->request_type == REQ_SIMPLE,
                "parse_request_data() returned unexpected request type");
    fail_unless(strcmp(req->data.sid, "S-1-2-3-4") == 0,
                "parse_request_data() returned unexpected sid");
    free(req);

    req_val.bv_val = req_nam;
    req_val.bv_len = sizeof(req_nam);

    ret = parse_request_data(&req_val, &req);

    fail_unless(ret == LDAP_SUCCESS,
                "parse_request_data() failed.");
    fail_unless(req->input_type == INP_NAME,
                "parse_request_data() returned unexpected input type");
    fail_unless(req->request_type == REQ_SIMPLE,
                "parse_request_data() returned unexpected request type");
    fail_unless(strcmp(req->data.name.domain_name, "DOMAIN") == 0,
                "parse_request_data() returned unexpected domain name");
    fail_unless(strcmp(req->data.name.object_name, "test") == 0,
                "parse_request_data() returned unexpected object name");
    free(req);

    req_val.bv_val = req_uid;
    req_val.bv_len = sizeof(req_uid);

    ret = parse_request_data(&req_val, &req);

    fail_unless(ret == LDAP_SUCCESS,
                "parse_request_data() failed.");
    fail_unless(req->input_type == INP_POSIX_UID,
                "parse_request_data() returned unexpected input type");
    fail_unless(req->request_type == REQ_SIMPLE,
                "parse_request_data() returned unexpected request type");
    fail_unless(strcmp(req->data.posix_uid.domain_name, "DOMAIN") == 0,
                "parse_request_data() returned unexpected domain name");
    fail_unless(req->data.posix_uid.uid == 12345,
                "parse_request_data() returned unexpected uid [%d]",
                req->data.posix_uid.uid);
    free(req);

    req_val.bv_val = req_gid;
    req_val.bv_len = sizeof(req_gid);

    ret = parse_request_data(&req_val, &req);

    fail_unless(ret == LDAP_SUCCESS,
                "parse_request_data() failed.");
    fail_unless(req->input_type == INP_POSIX_GID,
                "parse_request_data() returned unexpected input type");
    fail_unless(req->request_type == REQ_SIMPLE,
                "parse_request_data() returned unexpected request type");
    fail_unless(strcmp(req->data.posix_gid.domain_name, "DOMAIN") == 0,
                "parse_request_data() returned unexpected domain name");
    fail_unless(req->data.posix_gid.gid == 54321,
                "parse_request_data() returned unexpected gid [%d]",
                req->data.posix_gid.gid);
    free(req);
}
END_TEST

Suite * ipa_extdom_suite(void)
{
    Suite *s = suite_create("IPA extdom");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_decode);
    tcase_add_test(tc_core, test_encode);
    /* TODO: add test for create_response() */
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;

    Suite *s = ipa_extdom_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
