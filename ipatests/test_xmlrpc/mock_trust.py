# coding: utf-8
#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
import six

from ipalib import api


def get_range_dn(name):
    format_str = "cn={name},cn=ranges,cn=etc,{basedn}"
    data = dict(name=name, basedn=api.env.basedn)
    return format_str.format(**data)


def get_trust_dn(name):
    format_str = "cn={name},cn=ad,cn=trusts,{basedn}"
    data = dict(name=name, basedn=api.env.basedn)
    return format_str.format(**data)


def encode_mockldap_value(value):
    value = str(value)
    if six.PY3:
        return value.encode('utf-8')
    else:
        return value


def get_trusted_dom_range_dict(name, base_id, size, rangetype, base_rid, sid):
    return dict(
        objectClass=[b"ipaIDrange", b"ipatrustedaddomainrange"],
        ipaBaseID=encode_mockldap_value("{base_id}".format(base_id=base_id)),
        ipaBaseRID=encode_mockldap_value("{base_rid}".format(base_rid=base_rid)),
        ipaIDRangeSize=encode_mockldap_value("{size}".format(size=size)),
        ipaNTTrustedDomainSID=encode_mockldap_value("{sid}".format(sid=sid)),
        ipaRangeType=encode_mockldap_value("{rangetype}".format(rangetype=rangetype)),
        )


def get_trusted_dom_dict(name, sid):
    return dict(
        objectClass=[b"ipaNTTrustedDomain", b"ipaIDobject", b"top"],
        ipaNTFlatName=encode_mockldap_value(name.split('.')[0].upper()),
        ipaNTTrustedDomainSID=encode_mockldap_value(sid),
        ipaNTSIDBlacklistIncoming=b'S-1-0',
        ipaNTTrustPartner=encode_mockldap_value('{name}.mock'.format(name=name)),
        ipaNTTrustType=b'2',
        ipaNTTrustDirection=b'3',
        ipaNTTrustAttributes=b'8',
        )
