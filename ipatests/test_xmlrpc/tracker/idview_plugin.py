#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipalib import api
from ipapython.dn import DN
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc import objectclasses

import six

if six.PY3:
    unicode = str


class IdviewTracker(Tracker):
    """Class for idview tests"""

    retrieve_keys = {
        u'cn'
    }

    retrieve_all_keys = retrieve_keys | {
        u'description', u'objectclass', u'dn'
    }

    create_keys = retrieve_all_keys
    find_all_keys = retrieve_all_keys

    def del_cert_from_idoverrideuser(self, username, cert):
        result = api.Command.idoverrideuser_remove_cert(
            self.cn, username, usercertificate=cert
        )
        return dict(
            usercertificate=result['result'].get('usercertificate', []),
            value=result.get('value'),
            summary=result.get('summary')
        )

    def add_cert_to_idoverrideuser(self, username, cert):
        result = api.Command.idoverrideuser_add_cert(
            self.cn, username, usercertificate=cert
        )
        return dict(
            usercertificate=result['result'].get('usercertificate', []),
            value=result.get('value'),
            summary=result.get('summary')
        )

    def __init__(self, cn, **kwargs):
        super(IdviewTracker, self).__init__(default_version=None)
        self.cn = cn
        self.dn = DN(('cn', cn), api.env.container_views, api.env.basedn)
        self.kwargs = kwargs

    def make_create_command(self):
        return self.make_command(
            'idview_add', self.cn, **self.kwargs
            )

    def make_delete_command(self):
        return self.make_command(
            'idview_del', self.cn, **self.kwargs
            )

    def make_retrieve_command(self, all=False, raw=False):
        """ Make function that retrieves a idview using idview-show """
        return self.make_command('idview_show', self.cn, all=all)

    def make_find_command(self, *args, **kwargs):
        """ Make function that finds idview using idview-find """
        return self.make_command('idview_find', *args, **kwargs)

    def make_update_command(self, updates):
        """ Make function that updates idview using idview-mod """
        return self.make_command('idview_mod', self.cn, **updates)

    def track_create(self):
        self.attrs = dict(
            cn=(self.cn,),
            dn=unicode(self.dn),
            idoverrideusers=[],
            objectclass=objectclasses.idview
        )
        if 'description' in self.kwargs:
            self.attrs['description'] = self.kwargs['description']
        self.exists = True

    def make_add_idoverrideuser_command(self, username, options=None):
        options = options or {}
        """ Make function that adds a member to a group """
        return self.make_command('idoverrideuser_add', self.cn, username,
                                 **options)

    def idoverrideuser_add(self, user):
        command = self.make_add_idoverrideuser_command(user.name)
        result = command()
        self.attrs['idoverrideusers'].append(result['value'])
        self.check_idoverrideuser_add(result, user)

    def check_create(self, result, extra_keys=()):
        """ Check 'user-add' command result """
        expected = self.filter_attrs(self.create_keys | set(extra_keys))
        assert_deepequal(dict(
            summary=u'Added ID View "%s"' % self.cn,
            result=self.filter_attrs(expected),
            value=self.cn
            ), result)

    def check_idoverrideuser_add(self, result, user):
        """ Checks 'group_add_member' command result """
        assert_deepequal(
            u'Added User ID override "%s"' % user.name,
            result['summary']
        )
