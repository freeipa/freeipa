#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

import logging

import dns.name
try:
    from xml.etree import cElementTree as etree
except ImportError:
    from xml.etree import ElementTree as etree

from ipapython import ipa_log_manager, ipautil
from ipaplatform.tasks import tasks

logger = logging.getLogger(__name__)

# hack: zone object UUID is stored as path to imaginary zone file
ENTRYUUID_PREFIX = "/var/lib/ipa/dns/zone/entryUUID/"
ENTRYUUID_PREFIX_LEN = len(ENTRYUUID_PREFIX)


class ZoneListReader(object):
    def __init__(self):
        self.names = set()  # dns.name
        self.uuids = set()  # UUID strings
        self.mapping = dict()      # {UUID: dns.name}

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
        root = etree.fromstring(zonelist_text)
        self._parse_zonelist(root)

    def _parse_zonelist(self, root):
        """iterate over Zone elements with attribute 'name' and
        add IPA zones to self.zones"""
        if not root.tag == 'ZoneList':
            raise ValueError(root.tag)
        for zone_xml in root.findall('./Zone[@name]'):
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
        zids = []
        for in_adapter in zone_xml.findall(
                './Adapters/Input/Adapter[@type="File"]'):
            path = in_adapter.text
            if path.startswith(ENTRYUUID_PREFIX):
                # strip prefix from path
                zids.append(path[ENTRYUUID_PREFIX_LEN:])

        if len(zids) != 1:
            raise ValueError('only IPA zones are supported: {}'.format(
                etree.tostring(zone_xml)))

        return name, zids[0]


class LDAPZoneListReader(ZoneListReader):
    def __init__(self):
        super(LDAPZoneListReader, self).__init__()

    def process_ipa_zone(self, op, uuid, zone_ldap):
        assert (op in ['add', 'del']), 'unsupported op %s' % op
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
        self.zl_ldap = LDAPZoneListReader()

    def ksmutil(self, params):
        """Call ods-ksmutil / ods-enforcer with parameters and return stdout.

        Raises CalledProcessError if returncode != 0.
        """
        result = tasks.run_ods_manager(params, capture_output=True)
        return result.output

    def get_ods_zonelist(self):
        stdout = self.ksmutil(['zonelist', 'export'])
        reader = ODSZoneListReader(stdout)
        return reader

    def add_ods_zone(self, uuid, name):
        zone_path = '%s%s' % (ENTRYUUID_PREFIX, uuid)
        cmd = ['zone', 'add', '--zone', str(name), '--input', zone_path]
        output = self.ksmutil(cmd)
        logger.info('%s', output)
        self.notify_enforcer()

    def del_ods_zone(self, name):
        # ods-ksmutil blows up if zone name has period at the end
        name = name.relativize(dns.name.root)
        # detect if name is root zone
        if name == dns.name.empty:
            name = dns.name.root
        cmd = ['zone', 'delete', '--zone', str(name)]
        output = self.ksmutil(cmd)
        logger.info('%s', output)
        self.notify_enforcer()
        self.cleanup_signer(name)

    def notify_enforcer(self):
        cmd = ['notify']
        output = self.ksmutil(cmd)
        logger.info('%s', output)

    def cleanup_signer(self, zone_name):
        cmd = ['ods-signer', 'ldap-cleanup', str(zone_name)]
        output = ipautil.run(cmd, capture_output=True)
        logger.info('%s', output)

    def ldap_event(self, op, uuid, attrs):
        """Record single LDAP event - zone addition or deletion.

        Change is only recorded to memory.
        self.sync() have to be called to synchronize change to ODS."""
        assert op in ('add', 'del')
        self.zl_ldap.process_ipa_zone(op, uuid, attrs)
        logger.debug("LDAP zones: %s", self.zl_ldap.mapping)

    def sync(self):
        """Synchronize list of zones in LDAP with ODS."""
        zl_ods = self.get_ods_zonelist()
        logger.debug("ODS zones: %s", zl_ods.mapping)
        removed = self.diff_zl(zl_ods, self.zl_ldap)
        logger.info("Zones removed from LDAP: %s", removed)
        added = self.diff_zl(self.zl_ldap, zl_ods)
        logger.info("Zones added to LDAP: %s", added)
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
    logger.info('ODS zones: %s', reader.mapping)
