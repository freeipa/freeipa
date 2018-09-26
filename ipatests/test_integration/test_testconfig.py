# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import copy

from ipatests.pytest_ipa.integration import config
from ipapython.ipautil import write_tmp_file
from ipatests.util import assert_deepequal
from ipalib.constants import MAX_DOMAIN_LEVEL

DEFAULT_OUTPUT_DICT = {
    "nis_domain": "ipatest",
    "test_dir": "/root/ipatests",
    "ad_admin_name": "Administrator",
    "ipv6": False,
    "ssh_key_filename": "~/.ssh/id_rsa",
    "ssh_username": "root",
    "admin_name": "admin",
    "ad_admin_password": "Secret123",
    "ssh_password": None,
    "dns_forwarder": "8.8.8.8",
    "domains": [],
    "dirman_dn": "cn=Directory Manager",
    "dirman_password": "Secret123",
    "ntp_server": "ntp.clock.test",
    "admin_password": "Secret123",
    "domain_level": MAX_DOMAIN_LEVEL,
    "log_journal_since": "-1h",
}

DEFAULT_OUTPUT_ENV = {
    "IPATEST_DIR": "/root/ipatests",
    "IPA_ROOT_SSH_KEY": "~/.ssh/id_rsa",
    "IPA_ROOT_SSH_PASSWORD": "",
    "ADMINID": "admin",
    "ADMINPW": "Secret123",
    "ROOTDN": "cn=Directory Manager",
    "ROOTDNPWD": "Secret123",
    "DNSFORWARD": "8.8.8.8",
    "NISDOMAIN": "ipatest",
    "NTPSERVER": "ntp.clock.test",
    "ADADMINID": "Administrator",
    "ADADMINPW": "Secret123",
    "IPv6SETUP": "",
    "IPADEBUG": "",
    "DOMAINLVL": str(MAX_DOMAIN_LEVEL),
    "LOG_JOURNAL_SINCE": "-1h",
}

DEFAULT_INPUT_ENV = {
    'NTPSERVER': 'ntp.clock.test',
}

DEFAULT_INPUT_DICT = {
    'ntp_server': 'ntp.clock.test',
    'domains': [],
}


def extend_dict(defaults, *others, **kwargs):
    result = dict(defaults)
    for other in others:
        result.update(other)
    result.update(kwargs)
    return copy.deepcopy(result)


class CheckConfig:
    def check_config(self, conf):
        pass

    def get_input_env(self):
        return extend_dict(DEFAULT_INPUT_ENV, self.extra_input_env)

    def get_output_env(self):
        return extend_dict(DEFAULT_OUTPUT_ENV, self.extra_output_env)

    def get_input_dict(self):
        return extend_dict(DEFAULT_INPUT_DICT, self.extra_input_dict)

    def get_output_dict(self):
        return extend_dict(DEFAULT_OUTPUT_DICT, self.extra_output_dict)

    def test_env_to_dict(self):
        conf = config.Config.from_env(self.get_input_env())
        assert_deepequal(self.get_output_dict(), conf.to_dict())
        self.check_config(conf)

    def test_env_to_env(self):
        conf = config.Config.from_env(self.get_input_env())
        assert_deepequal(self.get_output_env(), dict(conf.to_env()))
        self.check_config(conf)

    def test_dict_to_env(self):
        conf = config.Config.from_dict(self.get_input_dict())
        assert_deepequal(self.get_output_env(), dict(conf.to_env()))
        self.check_config(conf)

    def test_dict_to_dict(self):
        conf = config.Config.from_dict(self.get_input_dict())
        assert_deepequal(self.get_output_dict(), conf.to_dict())
        self.check_config(conf)

    def test_env_roundtrip(self):
        conf = config.Config.from_env(self.get_output_env())
        assert_deepequal(self.get_output_env(), dict(conf.to_env()))
        self.check_config(conf)

    def test_dict_roundtrip(self):
        conf = config.Config.from_dict(self.get_output_dict())
        assert_deepequal(self.get_output_dict(), conf.to_dict())
        self.check_config(conf)

    def test_from_json_file(self):
        file = write_tmp_file(json.dumps(self.get_input_dict()))
        conf = config.Config.from_env({'IPATEST_JSON_CONFIG': file.name})
        assert_deepequal(self.get_output_dict(), conf.to_dict())
        self.check_config(conf)

    # Settings to override:
    extra_input_dict = {}
    extra_input_env = {}
    extra_output_dict = {}
    extra_output_env = {}


class TestEmptyConfig(CheckConfig):
    extra_input_dict = {}
    extra_input_env = {}
    extra_output_dict = {}
    extra_output_env = {}


class TestMinimalConfig(CheckConfig):
    extra_input_dict = dict(
        domains=[
            dict(name='ipadomain.test', type='IPA', hosts=[
                dict(name='master', ip='192.0.2.1', host_type=None),
            ]),
        ],
    )
    extra_input_env = dict(
        MASTER='master.ipadomain.test',
        BEAKERMASTER1_IP_env1='192.0.2.1',
    )
    extra_output_dict = dict(
        domains=[
            dict(
                type="IPA",
                name="ipadomain.test",
                hosts=[
                    dict(
                        name='master.ipadomain.test',
                        ip="192.0.2.1",
                        external_hostname="master.ipadomain.test",
                        role="master",
                        host_type=None,
                    ),
                ],
            ),
        ],
    )
    extra_output_env = dict(
        DOMAIN_env1="ipadomain.test",
        RELM_env1="IPADOMAIN.TEST",
        BASEDN_env1="dc=ipadomain,dc=test",
        MASTER_env1="master.ipadomain.test",
        BEAKERMASTER_env1="master.ipadomain.test",
        BEAKERMASTER_IP_env1="192.0.2.1",
        MASTER1_env1="master.ipadomain.test",
        BEAKERMASTER1_env1="master.ipadomain.test",
        BEAKERMASTER1_IP_env1="192.0.2.1",
        MASTER="master.ipadomain.test",
        BEAKERMASTER="master.ipadomain.test",
        MASTERIP="192.0.2.1",
    )

    def check_config(self, conf):
        assert len(conf.domains) == 1
        assert conf.domains[0].name == 'ipadomain.test'
        assert conf.domains[0].type == 'IPA'
        assert len(conf.domains[0].hosts) == 1

        master = conf.domains[0].master
        assert master == conf.domains[0].hosts[0]
        assert master.hostname == 'master.ipadomain.test'
        assert master.role == 'master'

        assert conf.domains[0].replicas == []
        assert conf.domains[0].clients == []
        assert conf.domains[0].hosts_by_role('replica') == []
        assert conf.domains[0].host_by_role('master') == master


class TestComplexConfig(CheckConfig):
    extra_input_dict = dict(
        domains=[
            dict(name='ipadomain.test', type='IPA', hosts=[
                dict(name='master', ip='192.0.2.1', role='master',
                     host_type=None),
                dict(name='replica1', ip='192.0.2.2', role='replica',
                     host_type=None),
                dict(name='replica2', ip='192.0.2.3', role='replica',
                     external_hostname='r2.ipadomain.test', host_type=None),
                dict(name='client1', ip='192.0.2.4', role='client',
                     host_type=None),
                dict(name='client2', ip='192.0.2.5', role='client',
                     external_hostname='c2.ipadomain.test', host_type=None),
                dict(name='extra', ip='192.0.2.6', role='extrarole',
                     host_type=None),
                dict(name='extram1', ip='192.0.2.7', role='extrarolem',
                     host_type=None),
                dict(name='extram2', ip='192.0.2.8', role='extrarolem',
                     external_hostname='e2.ipadomain.test', host_type=None),
            ]),
            dict(name='addomain.test', type='AD', hosts=[
                dict(name='ad', ip='192.0.2.33', role='ad', host_type=None),
            ]),
            dict(name='ipadomain2.test', type='IPA', hosts=[
                dict(name='master.ipadomain2.test', ip='192.0.2.65',
                     host_type=None),
            ]),
        ],
    )
    extra_input_env = dict(
        MASTER='master.ipadomain.test',
        BEAKERMASTER1_IP_env1='192.0.2.1',
        REPLICA='replica1.ipadomain.test replica2.ipadomain.test',
        BEAKERREPLICA1_IP_env1='192.0.2.2',
        BEAKERREPLICA2_IP_env1='192.0.2.3',
        BEAKERREPLICA2_env1='r2.ipadomain.test',
        CLIENT='client1.ipadomain.test client2.ipadomain.test',
        BEAKERCLIENT1_IP_env1='192.0.2.4',
        BEAKERCLIENT2_IP_env1='192.0.2.5',
        BEAKERCLIENT2_env1='c2.ipadomain.test',
        TESTHOST_EXTRAROLE_env1='extra.ipadomain.test',
        BEAKEREXTRAROLE1_IP_env1='192.0.2.6',
        TESTHOST_EXTRAROLEM_env1='extram1.ipadomain.test extram2.ipadomain.test',
        BEAKEREXTRAROLEM1_IP_env1='192.0.2.7',
        BEAKEREXTRAROLEM2_IP_env1='192.0.2.8',
        BEAKEREXTRAROLEM2_env1='e2.ipadomain.test',

        AD_env2='ad.addomain.test',
        BEAKERAD1_IP_env2='192.0.2.33',

        MASTER_env3='master.ipadomain2.test',
        BEAKERMASTER1_IP_env3='192.0.2.65',
    )
    extra_output_dict = dict(
        domains=[
            dict(
                type="IPA",
                name="ipadomain.test",
                hosts=[
                    dict(
                        name='master.ipadomain.test',
                        ip="192.0.2.1",
                        external_hostname="master.ipadomain.test",
                        role="master",
                        host_type=None,
                    ),
                    dict(
                        name='replica1.ipadomain.test',
                        ip="192.0.2.2",
                        external_hostname="replica1.ipadomain.test",
                        role="replica",
                        host_type=None,
                    ),
                    dict(
                        name='replica2.ipadomain.test',
                        ip="192.0.2.3",
                        external_hostname="r2.ipadomain.test",
                        role="replica",
                        host_type=None,
                    ),
                    dict(
                        name='client1.ipadomain.test',
                        ip="192.0.2.4",
                        external_hostname="client1.ipadomain.test",
                        role="client",
                        host_type=None,
                    ),
                    dict(
                        name='client2.ipadomain.test',
                        ip="192.0.2.5",
                        external_hostname="c2.ipadomain.test",
                        role="client",
                        host_type=None,
                    ),
                    dict(
                        name='extra.ipadomain.test',
                        ip="192.0.2.6",
                        external_hostname="extra.ipadomain.test",
                        role="extrarole",
                        host_type=None,
                    ),
                    dict(
                        name='extram1.ipadomain.test',
                        ip="192.0.2.7",
                        external_hostname="extram1.ipadomain.test",
                        role="extrarolem",
                        host_type=None,
                    ),
                    dict(
                        name='extram2.ipadomain.test',
                        ip="192.0.2.8",
                        external_hostname="e2.ipadomain.test",
                        role="extrarolem",
                        host_type=None,
                    ),
                ],
            ),
            dict(
                type="AD",
                name="addomain.test",
                hosts=[
                    dict(
                        name='ad.addomain.test',
                        ip="192.0.2.33",
                        external_hostname="ad.addomain.test",
                        role="ad",
                        host_type=None,
                    ),
                ],
            ),
            dict(
                type="IPA",
                name="ipadomain2.test",
                hosts=[
                    dict(
                        name='master.ipadomain2.test',
                        ip="192.0.2.65",
                        external_hostname="master.ipadomain2.test",
                        role="master",
                        host_type=None,
                    ),
                ],
            ),
        ],
    )
    extra_output_env = extend_dict(extra_input_env,
        DOMAIN_env1="ipadomain.test",
        RELM_env1="IPADOMAIN.TEST",
        BASEDN_env1="dc=ipadomain,dc=test",

        MASTER_env1="master.ipadomain.test",
        BEAKERMASTER_env1="master.ipadomain.test",
        BEAKERMASTER_IP_env1="192.0.2.1",
        MASTER="master.ipadomain.test",
        BEAKERMASTER="master.ipadomain.test",
        MASTERIP="192.0.2.1",
        MASTER1_env1="master.ipadomain.test",
        BEAKERMASTER1_env1="master.ipadomain.test",
        BEAKERMASTER1_IP_env1="192.0.2.1",

        REPLICA_env1="replica1.ipadomain.test replica2.ipadomain.test",
        BEAKERREPLICA_env1="replica1.ipadomain.test r2.ipadomain.test",
        BEAKERREPLICA_IP_env1="192.0.2.2 192.0.2.3",
        REPLICA="replica1.ipadomain.test replica2.ipadomain.test",
        REPLICA1_env1="replica1.ipadomain.test",
        BEAKERREPLICA1_env1="replica1.ipadomain.test",
        BEAKERREPLICA1_IP_env1="192.0.2.2",
        REPLICA2_env1="replica2.ipadomain.test",
        BEAKERREPLICA2_env1="r2.ipadomain.test",
        BEAKERREPLICA2_IP_env1="192.0.2.3",
        SLAVE="replica1.ipadomain.test replica2.ipadomain.test",
        BEAKERSLAVE="replica1.ipadomain.test r2.ipadomain.test",
        SLAVEIP="192.0.2.2 192.0.2.3",

        CLIENT_env1="client1.ipadomain.test client2.ipadomain.test",
        BEAKERCLIENT_env1="client1.ipadomain.test c2.ipadomain.test",
        BEAKERCLIENT='client1.ipadomain.test',
        BEAKERCLIENT2='c2.ipadomain.test',
        BEAKERCLIENT_IP_env1="192.0.2.4 192.0.2.5",
        CLIENT="client1.ipadomain.test",
        CLIENT2="client2.ipadomain.test",
        CLIENT1_env1="client1.ipadomain.test",
        BEAKERCLIENT1_env1="client1.ipadomain.test",
        BEAKERCLIENT1_IP_env1="192.0.2.4",
        CLIENT2_env1="client2.ipadomain.test",
        BEAKERCLIENT2_env1="c2.ipadomain.test",
        BEAKERCLIENT2_IP_env1="192.0.2.5",

        TESTHOST_EXTRAROLE_env1="extra.ipadomain.test",
        BEAKEREXTRAROLE_env1="extra.ipadomain.test",
        BEAKEREXTRAROLE_IP_env1="192.0.2.6",
        TESTHOST_EXTRAROLE1_env1="extra.ipadomain.test",
        BEAKEREXTRAROLE1_env1="extra.ipadomain.test",
        BEAKEREXTRAROLE1_IP_env1="192.0.2.6",

        TESTHOST_EXTRAROLEM_env1="extram1.ipadomain.test extram2.ipadomain.test",
        BEAKEREXTRAROLEM_env1="extram1.ipadomain.test e2.ipadomain.test",
        BEAKEREXTRAROLEM_IP_env1="192.0.2.7 192.0.2.8",
        TESTHOST_EXTRAROLEM1_env1="extram1.ipadomain.test",
        BEAKEREXTRAROLEM1_env1="extram1.ipadomain.test",
        BEAKEREXTRAROLEM1_IP_env1="192.0.2.7",
        TESTHOST_EXTRAROLEM2_env1="extram2.ipadomain.test",
        BEAKEREXTRAROLEM2_env1="e2.ipadomain.test",
        BEAKEREXTRAROLEM2_IP_env1="192.0.2.8",

        DOMAIN_env2="addomain.test",
        RELM_env2="ADDOMAIN.TEST",
        BASEDN_env2="dc=addomain,dc=test",
        AD_env2="ad.addomain.test",
        BEAKERAD_env2="ad.addomain.test",
        BEAKERAD_IP_env2="192.0.2.33",
        AD1_env2="ad.addomain.test",
        BEAKERAD1_env2="ad.addomain.test",
        BEAKERAD1_IP_env2="192.0.2.33",

        DOMAIN_env3="ipadomain2.test",
        RELM_env3="IPADOMAIN2.TEST",
        BASEDN_env3="dc=ipadomain2,dc=test",
        MASTER_env3="master.ipadomain2.test",
        BEAKERMASTER_env3="master.ipadomain2.test",
        BEAKERMASTER_IP_env3="192.0.2.65",
        MASTER1_env3="master.ipadomain2.test",
        BEAKERMASTER1_env3="master.ipadomain2.test",
        BEAKERMASTER1_IP_env3="192.0.2.65",
    )

    def check_config(self, conf):
        assert len(conf.domains) == 3
        main_dom = conf.domains[0]
        (client1, client2, extra, extram1, extram2, _master,
         replica1, replica2) = sorted(main_dom.hosts, key=lambda h: h.role)
        assert main_dom.name == 'ipadomain.test'
        assert main_dom.type == 'IPA'

        assert sorted(main_dom.roles) == ['client', 'extrarole', 'extrarolem',
                                          'master', 'replica']
        assert main_dom.static_roles == ('master', 'replica', 'client', 'other')
        assert sorted(main_dom.extra_roles) == ['extrarole', 'extrarolem']

        assert main_dom.replicas == [replica1, replica2]
        assert main_dom.clients == [client1, client2]
        assert main_dom.hosts_by_role('replica') == [replica1, replica2]
        assert main_dom.hosts_by_role('extrarolem') == [extram1, extram2]
        assert main_dom.host_by_role('extrarole') == extra

        assert extra.ip == '192.0.2.6'
        assert extram2.hostname == 'extram2.ipadomain.test'
        assert extram2.external_hostname == 'e2.ipadomain.test'

        ad_dom = conf.domains[1]
        assert ad_dom.roles == ['ad']
        assert ad_dom.static_roles == ('ad',)
        assert ad_dom.extra_roles == []
