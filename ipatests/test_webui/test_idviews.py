#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_idviews as idview
import ipatests.test_webui.data_user as user
import ipatests.test_webui.data_group as group
import ipatests.test_webui.data_hostgroup as hostgroup
from ipatests.test_webui.test_host import host_tasks, ENTITY as HOST_ENTITY
import pytest

DATA_USER = {
    'pkey': user.PKEY,
    'add': [
        ('combobox', 'ipaanchoruuid', user.PKEY),
        ('textbox', 'uid', 'iduser'),
        ('textbox', 'gecos', 'id user'),
        ('textbox', 'uidnumber', 1),
        ('textbox', 'gidnumber', 1),
        ('textbox', 'loginshell', 'shell'),
        ('textbox', 'homedirectory', 'home'),
        ('textarea', 'description', 'desc'),
    ],
    'mod': [
        ('textbox', 'uid', 'moduser'),
        ('textbox', 'uidnumber', 3),
    ],
}

DATA_GROUP = {
    'pkey': group.PKEY,
    'add': [
        ('combobox', 'ipaanchoruuid', group.PKEY),
        ('textbox', 'cn', 'idgroup'),
        ('textbox', 'gidnumber', 2),
        ('textarea', 'description', 'desc'),
    ],
    'mod': [
        ('textbox', 'cn', 'modgroup'),
        ('textbox', 'gidnumber', 3),
    ],
}


@pytest.mark.tier1
class test_idviews(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: ID view
        """
        self.init_app()
        self.basic_crud(
            idview.ENTITY, idview.DATA, default_facet=idview.USER_FACET)

    @screenshot
    def test_overrides(self):
        """
        User and group overrides
        """
        self.init_app()

        self.add_record(user.ENTITY, user.DATA, navigate=False)
        self.add_record(group.ENTITY, group.DATA)
        self.add_record(idview.ENTITY, idview.DATA)

        self.navigate_to_record(idview.PKEY)
        parent_entity = 'idview'

        # user override
        self.add_record(parent_entity, DATA_USER, facet=idview.USER_FACET)
        self.navigate_to_record(user.PKEY)
        self.mod_record(idview.USER_FACET, DATA_USER)
        self.delete_action(idview.ENTITY, user.PKEY)

        # group override
        self.navigate_to_record(idview.PKEY)
        self.switch_to_facet(idview.GROUP_FACET)
        self.add_record(parent_entity, DATA_GROUP, facet=idview.GROUP_FACET)
        self.navigate_to_record(group.PKEY)
        self.mod_record(idview.GROUP_FACET, DATA_GROUP)
        self.delete_action(idview.ENTITY, group.PKEY)

        # cleanup
        self.delete(idview.ENTITY, [idview.DATA])
        self.delete(user.ENTITY, [user.DATA])
        self.delete(group.ENTITY, [group.DATA])

    @screenshot
    def test_hosts(self):
        """
        Apply to hosts and host groups
        """
        self.init_app()
        host = host_tasks()
        host.driver = self.driver
        host.config = self.config
        host.prep_data()

        self.add_record(HOST_ENTITY, host.data)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.navigate_to_record(hostgroup.PKEY)
        self.add_associations([host.pkey])
        self.add_record(idview.ENTITY, idview.DATA)

        self.navigate_to_record(idview.PKEY)
        self.switch_to_facet(idview.HOST_FACET)

        # apply to host
        self.add_associations(
            [host.pkey], facet='appliedtohosts', facet_btn='idview_apply')
        self.delete_record([host.pkey], facet_btn='idview_unapply')

        # apply to hostgroup
        self.add_associations(
            [hostgroup.PKEY], facet_btn='idview_apply_hostgroups',
            member_pkeys=[host.pkey])
        self.delete_associations(
            [hostgroup.PKEY], facet_btn='idview_unapply_hostgroups',
            member_pkeys=[host.pkey])

        # cleanup
        self.delete(idview.ENTITY, [idview.DATA])
        self.delete(hostgroup.ENTITY, [hostgroup.DATA])
        self.delete(HOST_ENTITY, [host.data])
