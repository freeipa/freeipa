#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from ipapython.dn import DN
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.tracker.base import ConfigurationTracker, EnableTracker
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_string
from ipatests.util import assert_deepequal


class CertmapruleTracker(Tracker, EnableTracker):
    """ Tracker for testin certmaprule plugin """
    retrieve_keys = {
        u'dn',
        u'cn',
        u'description',
        u'ipacertmapmaprule',
        u'ipacertmapmatchrule',
        u'associateddomain',
        u'ipacertmappriority',
        u'ipaenabledflag'
    }
    retrieve_all_keys = retrieve_keys | {u'objectclass'}
    create_keys = retrieve_keys | {u'objectclass'}
    update_keys = retrieve_keys - {u'dn'}

    def __init__(self, cn, description, ipacertmapmaprule,
                 ipacertmapmatchrule, associateddomain, ipacertmappriority,
                 default_version=None):
        super(CertmapruleTracker, self).__init__(
            default_version=default_version)

        self.dn = DN((u'cn', cn,),
                     self.api.env.container_certmaprules,
                     self.api.env.basedn)
        self.options = {
            u'description': description,
            u'ipacertmapmaprule': ipacertmapmaprule,
            u'ipacertmapmatchrule': ipacertmapmatchrule,
            u'associateddomain': associateddomain,
            u'ipacertmappriority': ipacertmappriority,
        }

    def make_create_command(self, dont_fill=()):
        kwargs = {k: v for k, v in self.options.items() if k not in dont_fill}

        return self.make_command('certmaprule_add', self.name, **kwargs)

    def track_create(self, dont_fill=()):
        self.attrs = {
            'dn': self.dn,
            'cn': [self.name],
            'ipaenabledflag': [u'TRUE'],
            'objectclass': objectclasses.certmaprule,
        }
        self.attrs.update({
            k: [v] for k, v in self.options.items() if k not in dont_fill
        })
        self.exists = True

    def check_create(self, result):
        assert_deepequal(dict(
            value=self.name,
            summary=u'Added Certificate Identity Mapping Rule "{}"'
                    u''.format(self.name),
            result=self.filter_attrs(self.create_keys),
        ), result)

    def create(self, dont_fill=()):
        self.track_create(dont_fill)
        command = self.make_create_command(dont_fill)
        result = command()
        self.check_create(result)

    def make_delete_command(self):
        return self.make_command('certmaprule_del', self.name)

    def check_delete(self, result):
        assert_deepequal(
            dict(
                value=[self.name],
                summary=u'Deleted Certificate Identity Mapping Rule "{}"'
                        ''.format(self.name),
                result=dict(failed=[]),
            ),
            result
        )

    def make_retrieve_command(self, all=False, raw=False):
        return self.make_command('certmaprule_show', self.name, all=all,
                                 raw=raw)

    def check_retrieve(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(
            dict(
                value=self.name,
                summary=None,
                result=expected,
            ),
            result
        )

    def make_find_command(self, *args, **kwargs):
        return self.make_command('certmaprule_find', *args, **kwargs)

    def check_find(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(
            dict(
                count=1,
                truncated=False,
                summary=u'1 Certificate Identity Mapping Rule matched',
                result=[expected],
            ),
            result
        )

    def make_update_command(self, updates):
        return self.make_command('certmaprule_mod', self.name, **updates)

    def check_update(self, result, extra_keys=()):
        assert_deepequal(
            dict(
                value=self.name,
                summary=u'Modified Certificate Identity Mapping Rule "{}"'
                        u''.format(self.name),
                result=self.filter_attrs(self.update_keys | set(extra_keys)),
            ),
            result
        )

    def make_enable_command(self):
        return self.make_command('certmaprule_enable', self.name)

    def check_enable(self, result):
        assert_deepequal(
            dict(
                value=self.name,
                summary=u'Enabled Certificate Identity Mapping Rule "{}"'
                        u''.format(self.name),
                result=True,
            ),
            result
        )

    def make_disable_command(self):
        return self.make_command('certmaprule_disable', self.name)

    def check_disable(self, result):
        assert_deepequal(
            dict(
                value=self.name,
                summary=u'Disabled Certificate Identity Mapping Rule "{}"'
                        u''.format(self.name),
                result=True,
            ),
            result
        )


class CertmapconfigTracker(ConfigurationTracker):
    retrieve_keys = {
        u'dn',
        u'ipacertmappromptusername',
    }

    retrieve_all_keys = retrieve_keys | {
        u'cn',
        u'objectclass',
        u'aci',
    }
    update_keys = retrieve_keys - {u'dn'}
    singlevalue_keys = {u'ipacertmappromptusername'}

    def __init__(self, default_version=None):
        super(CertmapconfigTracker, self).__init__(
            default_version=default_version)

        self.attrs = {
            u'dn': DN(self.api.env.container_certmap, self.api.env.basedn),
            u'cn': [self.api.env.container_certmap[0].value],
            u'objectclass': objectclasses.certmapconfig,
            u'aci': [fuzzy_string],
            u'ipacertmappromptusername': self.api.Command.certmapconfig_show(
                )[u'result'][u'ipacertmappromptusername']
        }

    def make_update_command(self, updates):
        return self.make_command('certmapconfig_mod', **updates)

    def check_update(self, result, extra_keys=()):
        assert_deepequal(
            dict(
                value=None,
                summary=None,
                result=self.filter_attrs(self.update_keys | set(extra_keys)),
            ),
            result
        )

    def make_retrieve_command(self, all=False, raw=False):
        return self.make_command('certmapconfig_show', all=all, raw=raw)

    def check_retrieve(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(
            dict(
                value=None,
                summary=None,
                result=expected,
            ),
            result
        )
