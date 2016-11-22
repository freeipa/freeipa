#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
"""
Test the `ipaserver/dnssec` package.
"""
import dns.name

from ipaserver.dnssec.odsmgr import ODSZoneListReader


ZONELIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ZoneList>
  <Zone name="ipa.example">
    <Policy>default</Policy>
    <Adapters>
      <Input>
        <Adapter type="File">/var/lib/ipa/dns/zone/entryUUID/12345</Adapter>
      </Input>
      <Output>
        <Adapter type="File">/var/lib/ipa/dns/zone/entryUUID/12345</Adapter>
      </Output>
    </Adapters>
  </Zone>
</ZoneList>
"""


def test_ods_zonelist_reader():
    uuid = '12345'
    name = dns.name.from_text('ipa.example.')

    reader = ODSZoneListReader("<ZoneList/>")
    assert reader.mapping == {}
    assert reader.names == set()
    assert reader.uuids == set()

    reader = ODSZoneListReader(ZONELIST_XML)
    assert reader.mapping == {uuid: name}
    assert reader.names == {name}
    assert reader.uuids == {uuid}
