# -*- coding: utf-8 -*-
#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from ipalib import api
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.tracker.kerberos_aliases import KerberosAliasMixin
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_uuid
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import assert_deepequal
from ipapython.dn import DN


class ServiceTracker(KerberosAliasMixin, Tracker):
    """
    Tracker class for service plugin

    So far does not include methods for these commands:
        service-add-host
        service-remove-host
        service-allow-retrieve-keytab
        service-disallow-retrieve-keytab
        service-allow-create-keytab
        service-disallow-create-keytab
        service-disable
        service-add-cert
        service-remove-cert
    """

    retrieve_keys = {
        'dn', 'krbprincipalname', 'usercertificate', 'has_keytab',
        'ipakrbauthzdata', 'ipaallowedtoperform', 'subject',
        'managedby', 'serial_number', 'serial_number_hex', 'issuer',
        'valid_not_before', 'valid_not_after', 'sha1_fingerprint',
        'sha256_fingerprint', 'krbprincipalauthind', 'managedby_host',
        'krbcanonicalname'}
    retrieve_all_keys = retrieve_keys | {
        'ipaKrbPrincipalAlias', 'ipaUniqueID', 'krbExtraData',
        'krbLastPwdChange', 'krbLoginFailedCount', 'memberof',
        'objectClass', 'ipakrbrequirespreauth', 'krbpwdpolicyreference',
        'ipakrbokasdelegate', 'ipakrboktoauthasdelegate'}

    create_keys = (retrieve_keys | {'objectclass', 'ipauniqueid'}) - {
        'usercertificate', 'has_keytab'}
    update_keys = retrieve_keys - {'dn', 'has_keytab'}

    def __init__(self, name, host_fqdn, options=None):
        super(ServiceTracker, self).__init__(default_version=None)
        self._name = "{0}/{1}@{2}".format(name, host_fqdn, api.env.realm)
        self.dn = DN(
            ('krbprincipalname', self.name), api.env.container_service,
            api.env.basedn)
        self.host_fqdn = host_fqdn
        self.options = options or {}

    @property
    def name(self):
        return self._name

    def make_create_command(self, force=True):
        """ Make function that creates a service """
        return self.make_command('service_add', self.name,
                                 force=force, **self.options)

    def make_delete_command(self):
        """ Make function that deletes a service """
        return self.make_command('service_del', self.name)

    def make_retrieve_command(self, all=False, raw=False):
        """ Make function that retrieves a service """
        return self.make_command('service_show', self.name, all=all)

    def make_find_command(self, *args, **kwargs):
        """ Make function that searches for a service"""
        return self.make_command('service_find', *args, **kwargs)

    def make_update_command(self, updates):
        """ Make function that updates a service """

        return self.make_command('service_mod', self.name, **updates)

    def make_disable_command(self):
        """ make command  that disables the service principal """
        return self.make_command('service_disable', self.name)

    def create(self, force=True):
        """Helper function to create an entry and check the result"""
        self.ensure_missing()
        self.track_create()
        command = self.make_create_command(force=force)
        result = command()
        self.check_create(result)

    def track_create(self, **options):
        """ Update expected state for service creation """
        self.attrs = {
            'dn': self.dn,
            'krbprincipalname': ['{0}'.format(self.name)],
            'objectclass': objectclasses.service,
            'ipauniqueid': [fuzzy_uuid],
            'managedby_host': [self.host_fqdn],
            'krbcanonicalname': ['{0}'.format(self.name)],
            'has_keytab': False,
            'ipakrboktoauthasdelegate': False,
            'krbpwdpolicyreference': [DN(
                'cn=Default Service Password Policy',
                self.api.env.container_service,
                self.api.env.basedn,
            )],
        }

        for key in self.options:
            self.attrs[key] = [self.options[key]]

        self.exists = True

    def check_create(self, result):
        """ Check service-add command result """
        assert_deepequal({
            'value': '{0}'.format(self.name),
            'summary': 'Added service "{0}"'.format(self.name),
            'result': self.filter_attrs(self.create_keys)
            }, result)

    def check_delete(self, result):
        """ Check service-del command result """
        assert_deepequal({
            'value': ['{0}'.format(self.name)],
            'summary': 'Deleted service "{0}"'.format(self.name),
            'result': {'failed': []}
            }, result)

    def check_retrieve(self, result, all=False, raw=False):
        """ Check service-show command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal({
            'value': '{0}'.format(self.name),
            'summary': None,
            'result': expected,
        }, result)

    def check_find(self, result, all=False, raw=False):
        """ Check service-find command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal({
            'count': 1,
            'truncated': False,
            'summary': '1 service matched',
            'result': [expected]
            }, result)

    def check_update(self, result, extra_keys=()):
        """ Check service-mod command result """
        assert_deepequal({
            'value': '{0}'.format(self.name),
            'summary': 'Modified service "{0}"'.format(self.name),
            'result': self.filter_attrs(self.update_keys | set(extra_keys))
            }, result)

    #  Kerberos aliases methods
    def _make_add_alias_cmd(self):
        return self.make_command('service_add_principal', self.name)

    def _make_remove_alias_cmd(self):
        return self.make_command('service_remove_principal', self.name)
