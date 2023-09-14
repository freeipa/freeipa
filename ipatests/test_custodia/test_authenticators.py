# Copyright (C) 2016  Custodia Project Contributors - see LICENSE file
import configparser
import grp
import pwd

from ipaserver.custodia.httpd import authenticators

CONFIG = u"""
[auth:cred_default]

[auth:cred_int]
uid = 0
gid = 0

[auth:cred_root]
uid = root
gid = root

[auth:cred_user]
uid = root

[auth:cred_group]
gid = root

[auth:cred_other_int]
uid = ${DEFAULT:other_uid}
gid = ${DEFAULT:other_gid}

[auth:cred_other_name]
uid = ${DEFAULT:other_username}
gid = ${DEFAULT:other_groupname}

[auth:header_default]

[auth:header_other]
header = GSSAPI
value =

[auth:header_value]
header = GSSAPI
value = admin

[auth:header_values]
header = GSSAPI
value = admin user

[auth:header_commaspace]
header = GSSAPI
value = admin, user, space user

[auth:header_comma]
header = GSSAPI
value = admin,user,other user
"""


class TestAuthenticators:
    @classmethod
    def setup_class(cls):
        # Tests are depending on two existing and distinct users and groups.
        # We chose 'root' with uid/gid 0 and 'nobody', because both exist on
        # all relevant platforms. Tests use a mocked request so they run
        # under any user.
        cls.user = user = pwd.getpwnam('nobody')
        cls.group = group = grp.getgrgid(user.pw_gid)

        cls.parser = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation(),
            defaults={
                'other_uid': str(user.pw_uid),
                'other_username': user.pw_name,
                'other_gid': str(group.gr_gid),
                'other_groupname': group.gr_name,
            }
        )
        cls.parser.read_string(CONFIG)

    def assertCredMatch(self, cred, uid, gid):
        request = {'creds': {'uid': uid, 'gid': gid}, 'client_id': 'tests'}
        assert cred.handle(request)

    def assertCredMismatch(self, cred, uid, gid):
        request = {'creds': {'uid': uid, 'gid': gid}, 'client_id': 'tests'}
        assert not cred.handle(request)

    def assertHeaderMatch(self, header, key, value, client_id):
        request = {'headers': {key: value}, 'client_id': client_id}
        assert header.handle(request) is True

    def assertHeaderMismatch(self, header, key, value, client_id):
        request = {'headers': {key: value}, 'client_id': client_id}
        assert header.handle(request) is False

    def test_cred(self):
        parser = self.parser
        cred = authenticators.SimpleCredsAuth(parser, 'auth:cred_default')
        assert cred.uid == -1
        assert cred.gid == -1
        self.assertCredMismatch(cred, 0, 0)

        cred = authenticators.SimpleCredsAuth(parser, 'auth:cred_int')
        assert cred.uid == 0
        assert cred.gid == 0
        self.assertCredMatch(cred, 0, 0)
        self.assertCredMatch(cred, 0, self.group.gr_gid)
        self.assertCredMatch(cred, self.user.pw_uid, 0)
        self.assertCredMismatch(cred, self.user.pw_uid, self.group.gr_gid)

        cred = authenticators.SimpleCredsAuth(parser, 'auth:cred_root')
        assert cred.uid == 0
        assert cred.gid == 0

        cred = authenticators.SimpleCredsAuth(parser, 'auth:cred_user')
        assert cred.uid == 0
        assert cred.gid == -1
        self.assertCredMatch(cred, 0, 0)
        self.assertCredMismatch(cred, self.user.pw_uid, 0)

        cred = authenticators.SimpleCredsAuth(parser, 'auth:cred_group')
        assert cred.uid == -1
        assert cred.gid == 0
        self.assertCredMatch(cred, 0, 0)
        self.assertCredMismatch(cred, 0, self.group.gr_gid)

        cred = authenticators.SimpleCredsAuth(parser, 'auth:cred_other_int')
        assert cred.uid != 0
        assert cred.uid == self.user.pw_uid
        assert cred.gid != 0
        assert cred.gid == self.group.gr_gid

        cred = authenticators.SimpleCredsAuth(parser, 'auth:cred_other_name')
        assert cred.uid != 0
        assert cred.uid == self.user.pw_uid
        assert cred.gid != 0
        assert cred.gid == self.group.gr_gid

    def test_header(self):
        parser = self.parser
        gssapi = 'GSSAPI'
        hdr = authenticators.SimpleHeaderAuth(parser, 'auth:header_default')
        assert hdr.header == 'REMOTE_USER'
        assert hdr.value is None
        self.assertHeaderMatch(hdr, 'REMOTE_USER', None, 0)

        hdr = authenticators.SimpleHeaderAuth(parser, 'auth:header_other')
        assert hdr.header == 'GSSAPI'
        assert hdr.value is None
        self.assertHeaderMatch(hdr, gssapi, None, 0)

        hdr = authenticators.SimpleHeaderAuth(parser, 'auth:header_value')
        assert hdr.header == 'GSSAPI'
        assert hdr.value == {'admin'}
        self.assertHeaderMatch(hdr, gssapi, 'admin', 0)
        self.assertHeaderMismatch(hdr, gssapi, 'invalid_rule', 0)

        # pylint: disable=R0133
        hdr = authenticators.SimpleHeaderAuth(parser, 'auth:header_values')
        assert hdr.header == 'GSSAPI'
        assert hdr.value, {'admin' == 'user'}

        hdr = authenticators.SimpleHeaderAuth(parser,
                                              'auth:header_commaspace')
        assert hdr.value, {'admin', 'user' == 'space user'}

        hdr = authenticators.SimpleHeaderAuth(parser,
                                              'auth:header_comma')
        assert hdr.value, {'admin', 'user' == 'other user'}
         # pylint: enable=R0133
