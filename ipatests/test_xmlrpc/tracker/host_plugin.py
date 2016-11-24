#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function


from ipapython.dn import DN
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.tracker.kerberos_aliases import KerberosAliasMixin
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_uuid
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import assert_deepequal
from ipalib import errors


class HostTracker(KerberosAliasMixin, Tracker):
    """Wraps and tracks modifications to a Host object

    Implements the helper functions for host plugin.

    The HostTracker object stores information about the host, e.g.
    ``fqdn`` and ``dn``.
    """
    retrieve_keys = {
        'dn', 'fqdn', 'description', 'l', 'krbcanonicalname',
        'krbprincipalname', 'managedby_host',
        'has_keytab', 'has_password', 'issuer', 'md5_fingerprint',
        'serial_number', 'serial_number_hex', 'sha1_fingerprint',
        'subject', 'usercertificate', 'valid_not_after', 'valid_not_before',
        'macaddress', 'sshpubkeyfp', 'ipaallowedtoperform_read_keys_user',
        'memberof_hostgroup', 'memberofindirect_hostgroup',
        'ipaallowedtoperform_read_keys_group',
        'ipaallowedtoperform_read_keys_host',
        'ipaallowedtoperform_read_keys_hostgroup',
        'ipaallowedtoperform_write_keys_user',
        'ipaallowedtoperform_write_keys_group',
        'ipaallowedtoperform_write_keys_host',
        'ipaallowedtoperform_write_keys_hostgroup'}
    retrieve_all_keys = retrieve_keys | {
        u'cn', u'ipakrbokasdelegate', u'ipakrbrequirespreauth', u'ipauniqueid',
        u'krbcanonicalname', u'managing_host', u'objectclass',
        u'serverhostname', u'ipakrboktoauthasdelegate',
        u'krbpwdpolicyreference'}
    create_keys = retrieve_keys | {'objectclass', 'ipauniqueid',
                                   'randompassword'}
    update_keys = retrieve_keys - {'dn'}
    managedby_keys = retrieve_keys - {'has_keytab', 'has_password'}
    allowedto_keys = retrieve_keys - {'has_keytab', 'has_password'}
    find_keys = retrieve_keys - {
        'has_keytab', 'has_password', 'memberof_hostgroup',
        'memberofindirect_hostgroup', 'managedby_host',
    }
    find_all_keys = retrieve_all_keys - {'has_keytab', 'has_password'}

    def __init__(self, name, fqdn=None, default_version=None):
        super(HostTracker, self).__init__(default_version=default_version)

        self.shortname = name
        if fqdn:
            self.fqdn = fqdn
        else:
            self.fqdn = u'%s.%s' % (name, self.api.env.domain)
        self.dn = DN(('fqdn', self.fqdn), 'cn=computers', 'cn=accounts',
                     self.api.env.basedn)

        self.description = u'Test host <%s>' % name
        self.location = u'Undisclosed location <%s>' % name

    def make_create_command(self, force=True):
        """Make function that creates this host using host_add"""
        return self.make_command('host_add', self.fqdn,
                                 description=self.description,
                                 l=self.location,
                                 force=force)

    def make_delete_command(self):
        """Make function that deletes the host using host_del"""
        return self.make_command('host_del', self.fqdn)

    def make_retrieve_command(self, all=False, raw=False):
        """Make function that retrieves the host using host_show"""
        return self.make_command('host_show', self.fqdn, all=all, raw=raw)

    def make_find_command(self, *args, **kwargs):
        """Make function that finds hosts using host_find

        Note that the fqdn (or other search terms) needs to be specified
        in arguments.
        """
        return self.make_command('host_find', *args, **kwargs)

    def make_update_command(self, updates):
        """Make function that modifies the host using host_mod"""
        return self.make_command('host_mod', self.fqdn, **updates)

    def track_create(self):
        """Update expected state for host creation"""
        self.attrs = dict(
            dn=self.dn,
            fqdn=[self.fqdn],
            description=[self.description],
            l=[self.location],
            krbprincipalname=[u'host/%s@%s' % (self.fqdn, self.api.env.realm)],
            krbcanonicalname=[u'host/%s@%s' % (self.fqdn, self.api.env.realm)],
            objectclass=objectclasses.host,
            ipauniqueid=[fuzzy_uuid],
            managedby_host=[self.fqdn],
            has_keytab=False,
            has_password=False,
            cn=[self.fqdn],
            ipakrbokasdelegate=False,
            ipakrbrequirespreauth=True,
            managing_host=[self.fqdn],
            serverhostname=[self.shortname],
            ipakrboktoauthasdelegate=False,
            krbpwdpolicyreference=[DN(
                u'cn=Default Host Password Policy',
                self.api.env.container_host,
                self.api.env.basedn,
            )],
        )
        self.exists = True

    def check_create(self, result):
        """Check `host_add` command result"""
        assert_deepequal(dict(
            value=self.fqdn,
            summary=u'Added host "%s"' % self.fqdn,
            result=self.filter_attrs(self.create_keys),
        ), result)

    def check_delete(self, result):
        """Check `host_del` command result"""
        assert_deepequal(dict(
            value=[self.fqdn],
            summary=u'Deleted host "%s"' % self.fqdn,
            result=dict(failed=[]),
        ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """Check `host_show` command result"""
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(dict(
            value=self.fqdn,
            summary=None,
            result=expected,
        ), result)

    def check_find(self, result, all=False, raw=False):
        """Check `host_find` command result"""
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)
        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 host matched',
            result=[expected],
        ), result)

    def check_update(self, result, extra_keys=()):
        """Check `host_update` command result"""
        assert_deepequal(dict(
            value=self.fqdn,
            summary=u'Modified host "%s"' % self.fqdn,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)

    def add_finalizer_certcleanup(self, request):
        """ Fixture to cleanup certificate from local host """
        cleanup_command = self.make_update_command(
            updates={'usercertificate':''})

        def cleanup():
            try:
                cleanup_command()
            except errors.EmptyModlist:
                pass

        request.addfinalizer(cleanup)

    #  Kerberos aliases methods
    def _make_add_alias_cmd(self):
        return self.make_command('host_add_principal', self.name)

    def _make_remove_alias_cmd(self):
        return self.make_command('host_remove_principal', self.name)
