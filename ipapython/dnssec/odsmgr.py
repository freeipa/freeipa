#!/usr/bin/python2
#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

import logging
from lxml import etree
import dns.name
import subprocess

from ipapython import ipa_log_manager, ipautil

# hack: zone object UUID is stored as path to imaginary zone file
ENTRYUUID_PREFIX = "/var/lib/ipa/dns/zone/entryUUID/"
ENTRYUUID_PREFIX_LEN = len(ENTRYUUID_PREFIX)


class ZoneListReader(object):
    def __init__(self):
        self.names = set()  # dns.name
        self.uuids = set()  # UUID strings
        self.mapping = dict()      # {UUID: dns.name}
        self.log = ipa_log_manager.log_mgr.get_logger(self)

    def _add_zone(self, name, zid):
        """Add zone & UUID to internal structures.

        Zone with given name and UUID must not exist."""
        # detect duplicate zone names
        name = dns.name.from_text(name)
        assert name not in self.names, \
            'duplicate name (%s, %s) vs. %s' % (name, zid, self.mapping)
        # duplicate non-None zid is not allowed
        assert not zid or zid not in self.uuids, \
            'duplicate UUID (%s, %s) vs. %s' % (name, zid, self.mapping)

        self.names.add(name)
        self.uuids.add(zid)
        self.mapping[zid] = name

    def _del_zone(self, name, zid):
        """Remove zone & UUID from internal structures.

        Zone with given name and UUID must exist.
        """
        name = dns.name.from_text(name)
        assert zid is not None
        assert name in self.names, \
            'name (%s, %s) does not exist in %s' % (name, zid, self.mapping)
        assert zid in self.uuids, \
            'UUID (%s, %s) does not exist in %s' % (name, zid, self.mapping)
        assert zid in self.mapping and name == self.mapping[zid], \
            'pair {%s: %s} does not exist in %s' % (zid, name, self.mapping)

        self.names.remove(name)
        self.uuids.remove(zid)
        del self.mapping[zid]


class ODSZoneListReader(ZoneListReader):
    """One-shot parser for ODS zonelist.xml."""
    def __init__(self, zonelist_text):
        super(ODSZoneListReader, self).__init__()
        xml = etree.fromstring(zonelist_text)
        self._parse_zonelist(xml)

    def _parse_zonelist(self, xml):
        """iterate over Zone elements with attribute 'name' and
        add IPA zones to self.zones"""
        for zone_xml in xml.xpath('/ZoneList/Zone[@name]'):
            name, zid = self._parse_ipa_zone(zone_xml)
            self._add_zone(name, zid)

    def _parse_ipa_zone(self, zone_xml):
        """Extract zone name, input adapter and detect IPA zones.

        IPA zones have contains Adapters/Input/Adapter element with
        attribute type = "File" and with value prefixed with ENTRYUUID_PREFIX.

        Returns:
            tuple (zone name, ID)
        """
        name = zone_xml.get('name')
        in_adapters = zone_xml.xpath(
            'Adapters/Input/Adapter[@type="File" '
            'and starts-with(text(), "%s")]' % ENTRYUUID_PREFIX)
        assert len(in_adapters) == 1, 'only IPA zones are supported: %s' \
            % etree.tostring(zone_xml)

        path = in_adapters[0].text
        # strip prefix from path
        zid = path[ENTRYUUID_PREFIX_LEN:]
        return (name, zid)


class LDAPZoneListReader(ZoneListReader):
    def __init__(self):
        super(LDAPZoneListReader, self).__init__()

    def process_ipa_zone(self, op, uuid, zone_ldap):
        assert (op == 'add' or op == 'del'), 'unsupported op %s' % op
        assert uuid is not None
        assert 'idnsname' in zone_ldap, \
            'LDAP zone UUID %s without idnsName' % uuid
        assert len(zone_ldap['idnsname']) == 1, \
            'LDAP zone UUID %s with len(idnsname) != 1' % uuid

        if op == 'add':
            self._add_zone(zone_ldap['idnsname'][0], uuid)
        elif op == 'del':
            self._del_zone(zone_ldap['idnsname'][0], uuid)


class ODSMgr(object):
    """OpenDNSSEC zone manager. It does LDAP->ODS synchronization.

    Zones with idnsSecInlineSigning attribute = TRUE in LDAP are added
    or deleted from ODS as necessary. ODS->LDAP key synchronization
    has to be solved seperatelly.
    """
    def __init__(self):
        self.log = ipa_log_manager.log_mgr.get_logger(self)
        self.zl_ldap = LDAPZoneListReader()

    def ksmutil(self, params):
        """Call ods-ksmutil with given parameters and return stdout.

        Raises CalledProcessError if returncode != 0.
        """
        cmd = ['ods-ksmutil'] + params
        return ipautil.run(cmd)[0]

    def get_ods_zonelist(self):
        stdout = self.ksmutil(['zonelist', 'export'])
        reader = ODSZoneListReader(stdout)
        return reader

    def add_ods_zone(self, uuid, name):
        zone_path = '%s%s' % (ENTRYUUID_PREFIX, uuid)
        cmd = ['zone', 'add', '--zone', str(name), '--input', zone_path]
        output = self.ksmutil(cmd)
        self.log.info(output)
        self.notify_enforcer()

    def del_ods_zone(self, name):
        # ods-ksmutil blows up if zone name has period at the end
        name = name.relativize(dns.name.root)
        # detect if name is root zone
        if name == dns.name.empty:
            name = dns.name.root
        cmd = ['zone', 'delete', '--zone', str(name)]
        output = self.ksmutil(cmd)
        self.log.info(output)
        self.notify_enforcer()

    def notify_enforcer(self):
        cmd = ['notify']
        output = self.ksmutil(cmd)
        self.log.info(output)

    def ldap_event(self, op, uuid, attrs):
        """Record single LDAP event - zone addition or deletion.

        Change is only recorded to memory.
        self.sync() have to be called to synchronize change to ODS."""
        assert op == 'add' or op == 'del'
        self.zl_ldap.process_ipa_zone(op, uuid, attrs)
        self.log.debug("LDAP zones: %s", self.zl_ldap.mapping)

    def sync(self):
        """Synchronize list of zones in LDAP with ODS."""
        zl_ods = self.get_ods_zonelist()
        self.log.debug("ODS zones: %s", zl_ods.mapping)
        removed = self.diff_zl(zl_ods, self.zl_ldap)
        self.log.info("Zones removed from LDAP: %s", removed)
        added = self.diff_zl(self.zl_ldap, zl_ods)
        self.log.info("Zones added to LDAP: %s", added)
        for (uuid, name) in removed:
            self.del_ods_zone(name)
        for (uuid, name) in added:
            self.add_ods_zone(uuid, name)

    def diff_zl(self, s1, s2):
        """Compute zones present in s1 but not present in s2.

        Returns: List of (uuid, name) tuples with zones present only in s1."""
        s1_extra = s1.uuids - s2.uuids
        removed = [(uuid, name) for (uuid, name) in s1.mapping.items()
                   if uuid in s1_extra]
        return removed


if __name__ == '__main__':
    ipa_log_manager.standard_logging_setup(debug=True)
    ods = ODSMgr()
    reader = ods.get_ods_zonelist()
    ipa_log_manager.root_logger.info('ODS zones: %s', reader.mapping)
