# coding: utf-8
#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from contextlib import contextmanager

from ipalib import api
from ipatests.util import MockLDAP

trust_container_dn = "cn=ad,cn=trusts,{basedn}".format(
    basedn=api.env.basedn)
trust_container_add = dict(
    objectClass=[b"nsContainer", b"top"]
    )

smb_cont_dn = "{cifsdomains},{basedn}".format(
    cifsdomains=api.env.container_cifsdomains,
    basedn=api.env.basedn)
smb_cont_add = dict(
    objectClass=[b"nsContainer", b"top"]
    )


def create_mock_trust_containers():
    with MockLDAP() as ldap:
        ldap.add_entry(trust_container_dn, trust_container_add)
        ldap.add_entry(smb_cont_dn, smb_cont_add)


def remove_mock_trust_containers():
    with MockLDAP() as ldap:
        ldap.del_entry(trust_container_dn)
        ldap.del_entry(smb_cont_dn)


@contextmanager
def mocked_trust_containers():
    """Mocked trust containers

    Provides containers for the RPC tests:
    cn=ad,cn=trusts,BASEDN
    cn=ad,cn=etc,BASEDN

    Upon exiting, it tries to remove the container entries.
    If the user of the context manager failed to remove
    all child entries, exiting the context manager will fail.
    """
    create_mock_trust_containers()
    try:
        yield
    finally:
        remove_mock_trust_containers()
