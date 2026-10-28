#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

from ipatests.test_integration.base import IntegrationTest
import textwrap

API_INIT = """
    from ipalib import api, errors
    api.bootstrap_with_global_options(context="server")
    api.finalize()
    api.Backend.ldap2.connect()
    """

CERT = (
    b"MIIEkDCCAvigAwIBAgIBCzANBgkqhkiG9w0BAQsFADA5MRcwFQYDVQQKD\n"
    b"A5URVNUUkVBTE0uVEVTVDEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG\n"
    b"9yaXR5MB4XDTIzMDcyODE3MTIxOVoXDTI1MDcyODE3MTIxOVowKjEXMBU\n"
    b"GA1UECgwOVEVTVFJFQUxNLlRFU1QxDzANBgNVBAMMBmpzbWl0aDCCASIw\n"
    b"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOF0XFrdVXmKp95AVZW5o\n"
    b"BWcij6vJPqeU3UpzTLbM+fROhNaKMX9S+yXrJHifOmhCOuNA8TtptKVJx\n"
    b"CIDZ1/5KwPBk4vrnwOBtVMCftHj87MabBqV/nmQQrCiKTcJu4aQEDI9Qh\n"
    b"yza09EJKvG8KkpnyuShtkP2LgkUxIqkjBg4DLV7grO+I+aG17QTuQxUTy\n"
    b"icfYDBnzD4hTKPLf7d9KNyG+sEeyN0gceLFMUYaQ4lyapcSzYJwOSAc2B\n"
    b"EU73tLaJlQORHL7HmhxrjD1IgZyxFjp/ofLVZFFoJAqjz2FWzOxmQw+bc\n"
    b"0WTzQjeSTGx+l3htj7MmhIRBMqr3Um6zXkLKMCAwEAAaOCATAwggEsMB8\n"
    b"GA1UdIwQYMBaAFCIXu6QtsiBVo1yZQZ7MMHTl5Wj6MEAGCCsGAQUFBwEB\n"
    b"BDQwMjAwBggrBgEFBQcwAYYkaHR0cDovL2lwYS1jYS50ZXN0cmVhbG0ud\n"
    b"GVzdC9jYS9vY3NwMA4GA1UdDwEB/wQEAwIE8DAdBgNVHSUEFjAUBggrBg\n"
    b"EFBQcDAQYIKwYBBQUHAwIweQYDVR0fBHIwcDBuoDagNIYyaHR0cDovL2l\n"
    b"wYS1jYS50ZXN0cmVhbG0udGVzdC9pcGEvY3JsL01hc3RlckNSTC5iaW6i\n"
    b"NKQyMDAxDjAMBgNVBAoMBWlwYWNhMR4wHAYDVQQDDBVDZXJ0aWZpY2F0Z\n"
    b"SBBdXRob3JpdHkwHQYDVR0OBBYEFNwQNQAG8MsKQPwMFyGzRiMzRAa5MA\n"
    b"0GCSqGSIb3DQEBCwUAA4IBgQB2g0mS8XAPI+aRBa5q7Vbp1245CvMP0Eq\n"
    b"Cz6gvCNwtxW0UDKnB++d/YQ13ft+x9Xj3rB/M2YXxdxTpQnQQv34CUcyh\n"
    b"PQKJthAsbKBpdusCGrbS54zKFR0MjxwOwIIDHuI6eu2AoSpsmYs5UGzQm\n"
    b"oCfQhbImK7iGLy0rOHaON1cWAFmC6lzJ2TFELc4N3eLYGVZy2ZtyZTgA3\n"
    b"l97rBCwbDDFF1JWoOByIq8Ij99ksyMXws++sNUpo/1l8Jt0Gn6RBiidZB\n"
    b"ef4+kJN+t6RAAwRQ / 3cmEggXcFoV13KZ70PeMXeX6CKMwXIwt3q7A78\n"
    b"Wc/0OIBREZLhXpkmogCzWCuatdzeBIhMhx0vDEzaxlhf32ZWfN5pFMpgq\n"
    b"wLZsdwMf6J65kGbE5Pg3Yxk7OiByxZJnR8UlvbU3r6RhMWutD6C0aqqNt\n"
    b"o3us5gTmfRc8Mf1l/BUgDqkBKOTU8FHREGemG1HoklBym/Pbua0VMUA+s\n"
    b"0nECR4LLM/o9PCJ2Y3QPBZy8Hg=\n"
)


class TestAPIScenario(IntegrationTest):
    """
    Tests for IDM API scenarios
    """

    topology = "line"

    def create_and_run_script(self, filename, user_code_script):
        self.master.put_file_contents(filename, user_code_script)
        self.master.run_command(["python3", filename])
        self.master.run_command(["rm", filename])

    def test_idm_user_add(self):
        """
        This test checks that ipa user using api.Command["user_add"]
        and then checks that user is displayed using
        api.Command["user_show"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    api.Command["user_add"]("jsmith", givenname="John", sn="Smith",
    ipauserauthtype="otp")
    cmd = api.Command["user_show"]("jsmith", all=True)["result"]
    assert 'otp' in cmd['ipauserauthtype']
    assert 'John Smith' in cmd['cn']
        """
        )
        self.create_and_run_script(
            "/tmp/user_add.py", user_code_script
        )

    def test_idm_user_find(self):
        """
        This test checks that user is displayed
        using api.Command["user_find"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["user_find"]("jsmith")
    assert '1 user matched' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/user_find.py", user_code_script
        )

    def test_idm_user_mod(self):
        """
        This test checks that user attribute is modified
        using api.Command["user_mod"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["user_mod"]("jsmith",
    mail="jsmith@example.org")["result"]
    assert 'jsmith@example.org' in cmd['mail']
        """
        )
        self.create_and_run_script(
            "/tmp/user_mod.py", user_code_script
        )

    def test_disable_user(self):
        """
        This test checks that user is disabled
        using api.Command["user_disable"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["user_disable"]("jsmith")
    assert 'Disabled user account "jsmith"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/disable_user.py", user_code_script
        )

    def test_enable_user(self):
        """
        This test checks that user is enabled
        using api.Command["user_enable"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["user_enable"]("jsmith")
    assert 'Enabled user account "jsmith"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/enable_user.py", user_code_script
        )

    def test_create_ipa_group(self):
        """
        This test checks that group is created
        using api.Command["group_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["group_add"]("developers", gidnumber=500,
    description="Developers")
    assert 'Added group "developers"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/create_group.py", user_code_script
        )

    def test_show_ipa_group(self):
        """
        This test checks that group is displayed
        using api.Command["group_show"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["group_show"]("developers")
    assert 'developers' in cmd['result']['cn']
        """
        )
        self.create_and_run_script(
            "/tmp/group_show.py", user_code_script
        )

    def test_ipa_group_mod(self):
        """
        This test checks that group description is modified
        using api.Command["group_mod"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["group_mod"]("developers", description='developer')
    ["result"]
    assert 'Modified group "developers"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/group_mod.py", user_code_script
        )

    def test_add_members_to_ipa_group(self):
        """
        This test checks that member is added to group
        using api.Command["group_add_member"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["group_add_member"]("developers",
    user='jsmith')["result"]
    assert 'jsmith' in cmd['member_user']
        """
        )
        self.create_and_run_script(
            "/tmp/create_group_members.py", user_code_script
        )

    def test_ipa_group_find(self):
        """
        This test checks that group is displayed
        using api.Command["group_find"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["group_find"]("developers")
    assert '1 group matched' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/group_find.py", user_code_script
        )

    def test_remove_member_group(self):
        """
        This test checks that group member is removed
        using api.Command["group_remove_member"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["group_remove_member"]("developers",
    user="jsmith")
    assert 'member_user' not in cmd
        """
        )
        self.create_and_run_script(
            "/tmp/remove_member_group.py", user_code_script
        )

    def test_add_permission(self):
        """
        This test checks that permission is added
        using api.Command["permission_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
        {API_INIT}
    cmd = api.Command["permission_add"]("Create users",
    ipapermright='add', type='user')
    assert 'Added permission "Create users"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/add_perm.py", user_code_script
        )

    def test_create_hbac_rule(self):
        """
        This test checks that hbac rule is added
        using api.Command["hbacrule_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["hbacrule_add"]("sshd_rule")
    assert 'Added HBAC rule "sshd_rule"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/add_hbac_rule.py", user_code_script
        )

    def test_add_hbac_service(self):
        """
        This test checks that hbac service is added using
        api.Command["hbacsvc_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["hbacsvc_add"]("chronyd")
    assert 'Added HBAC service "chronyd"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/add_hbac_svc.py", user_code_script
        )

    def test_enable_hbac_rule(self):
        """
        This test checks that hbac rule is enabled using
        api.Command["hbacrule_enable"]
        """
        user_code_script = textwrap.dedent(
            f"""
        {API_INIT}
    cmd = api.Command["hbacrule_enable"]("sshd_rule")
    assert 'Enabled HBAC rule "sshd_rule"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/enable_hbacrule.py", user_code_script
        )

    def test_create_sudo_rule(self):
        """
        This test checks that sudo rule is created using
        api.Command["sudorule_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
        {API_INIT}
    cmd = api.Command["sudorule_add"]("timechange")
    assert 'Added Sudo Rule "timechange"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/create_sudos.py", user_code_script
        )

    def test_add_user_certificate(self):
        """
        This test checks user certificate is added using
        api.Command["user_add_cert"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    msg = 'Added certificates to user "jsmith"'
    cmd = api.Command["user_add_cert"]("jsmith", usercertificate={CERT})
    assert msg in cmd["summary"]
        """
        )
        self.create_and_run_script(
            "/tmp/add_cert.py", user_code_script
        )

    def test_remove_user_certificate(self):
        """
        This test checks that user certificate is removed
        using api.Command["user_remove_cert"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    msg = 'Removed certificates from user "jsmith"'
    cmd = api.Command["user_remove_cert"]("jsmith", usercertificate={CERT})
    assert msg in cmd["summary"]
        """
        )
        self.create_and_run_script(
            "/tmp/remove_cert.py", user_code_script
        )

    def test_certmaprule_add(self):
        """
        This test checks that certmap rule is added using
        api.Command["certmaprule_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    msg = ('Added Certificate Identity Mapping Rule "testrule"')
    cmd = api.Command["certmaprule_add"]("testrule")
    assert msg in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/certmap_rule_add.py", user_code_script
        )

    def test_certmaprule_enable(self):
        """
        This test checks that certmap rule is enabled
        using api.Command["certmaprule_enable"]
        """
        user_code_script = textwrap.dedent(
            f"""
        {API_INIT}
    msg = ('Enabled Certificate Identity Mapping Rule "testrule"')
    cmd = api.Command["certmaprule_enable"]("testrule")
    assert msg in cmd["summary"]
        """
        )
        self.create_and_run_script(
            "/tmp/certmap_rule_enable.py", user_code_script
        )

    def test_certmaprule_disable(self):
        """
        This test checks that certmap rule is disabled using
        api.Command["certmaprule_disable"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    msg = ('Disabled Certificate Identity Mapping Rule "testrule"')
    cmd = api.Command["certmaprule_disable"]("testrule")
    assert msg in cmd["summary"]
        """
        )
        self.create_and_run_script(
            "/tmp/certmap_rule_disable.py", user_code_script
        )

    def test_certmaprule_del(self):
        """
        This test checks that certmap rule is deleted using
        api.Command["certmaprule_del"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    msg = ('Deleted Certificate Identity Mapping Rule "testrule"')
    cmd = api.Command["certmaprule_del"]("testrule")
    assert msg in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/certmap_rule_del.py", user_code_script
        )

    def test_add_role(self):
        """
        This test checks that role and privilege is added using
        api.Command["role_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
        {API_INIT}
    cmd1 = api.Command["role_add"]("junioradmin",
    description="Junior admin")
    assert 'Added role "junioradmin"' in cmd1["summary"]
    cmd2 = api.Command.role_add_privilege("junioradmin",
    privilege="Vault Administrators")["result"]
    assert 'Vault Administrators' in cmd2["memberof_privilege"]
        """
        )
        self.create_and_run_script(
            "/tmp/add_role.py", user_code_script
        )

    def test_add_subid(self):
        """
        This test checks that subid is added for IPA user
        using api.Command["subid_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
        {API_INIT}
    cmd = api.Command["subid_add"](ipaowner="jsmith")
    assert 'Added subordinate id ' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/add_subid.py", user_code_script
        )

    def test_add_otptoken(self):
        """
        This test checks that otp token is added for IPA user
        using api.Command["otptoken_add"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["otptoken_add"](
    type='HOTP', description='testotp',
    ipatokenotpalgorithm='sha512', ipatokenowner='jsmith',
    ipatokenotpdigits='6')
    assert 'Added OTP token' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/add_otptoken.py", user_code_script
        )

    def test_user_del(self):
        """
        This test checks that user is deleted
        using api.Command["user_del"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["user_del"]("jsmith")
    assert 'Deleted user "jsmith"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/user_del.py", user_code_script
        )

    def test_remove_ipa_group(self):
        """
        This test checks that group is removed
        using api.Command["group_del"]
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    cmd = api.Command["group_del"]("developers")
    assert 'Deleted group "developers"' in cmd['summary']
        """
        )
        self.create_and_run_script(
            "/tmp/show_group.py", user_code_script
        )

    def test_batch_command(self):
        """
        This test checks that batch commands
        can be run using api.
        """
        user_code_script = textwrap.dedent(
            f"""
    {API_INIT}
    batch_args = []
    for i in range(5):
        user_id = "user%i" % i
        args = [user_id]
        kw = dict(givenname=user_id, sn=user_id, random=True)
        batch_args.append(dict(method='user_add', params=[args, kw]))

    batch_args.append(dict(method='ping', params=[(), dict()]))
    keeponly=('dn', 'uid', 'randompassword')
    batch = api.Command["batch"](methods=batch_args, keeponly=keeponly)
    # Make sure only the attributes from keeponly returned in result dict
    # The ping() test above will have no attributes returned
    for r in batch['results']:
        if r.get('result', None):
            assert set(keeponly) >= set(r['result'].keys())
        """
        )
        self.create_and_run_script(
            "/tmp/batch.py", user_code_script
        )
