import base64
from jinja2 import Environment, PackageLoader
from samba.dcerpc import security
from samba.ndr import ndr_pack
import uuid

from ipalib import api
from ipapython.dn import DN

GROUP_TYPE_ACCOUNT_GROUP = 0x00000002
GROUP_TYPE_RESOURCE_GROUP = 0x00000004
GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008
GROUP_TYPE_SECURITY_ENABLED = 0x80000000
GROUP_TYPE_OFFSET = 0x100000000


def transform_sid(sid):
    """Transforms a SID from a string format to an AD-compatible format

    For instance input: (string) S-1-5-21-290024825-4011531429-1633689518-500
    output: (string) AQUAAAAAAAUVAAAAeW1JEaUcG++uH2Bh7QMAAA==
    """
    return base64.b64encode(ndr_pack(security.dom_sid(sid))).decode('utf-8')


def transform_gid(uniqueid):
    """Transforms an id from a string format to an AD-compatible format

    For instance input: (string) 7d976a62-0703-11ea-89b6-001a4a2312ca
    output (string): fZdqYgcDEeqJtgAaSiMSyg==
    """
    return base64.b64encode(uuid.UUID(uniqueid).bytes).decode('utf-8')


def rename_group_members(api, group, conn):
    """Fix the member attribute of a group entry

    In IdM the users are below cn=users,cn=accounts,$suffix
    and they have a dn: uid=%uid%
    but in the Global Catalog they are in CN=Users,$suffix
    and they have a dn: Cn=%cn%
    """
    users_dn = DN(api.env.container_user, api.env.basedn)
    groups_dn = DN(api.env.container_group, api.env.basedn)

    new_member_attr = []
    for memberDN in group.get('member', []):
        if memberDN.find(users_dn) == 1:
            # The member value is right below the user container
            # Need to find the CN single_value
            user = conn.get_entry(
                memberDN, ["cn"], time_limit=0, size_limit=-1)
            user_cn = user.single_value['cn']
            new_member_attr.append(DN(
                'cn={}'.format(user_cn), 'cn=users', api.env.basedn))
            continue
        if memberDN.find(groups_dn) == 1:
            # The member value is right below the group container
            new_member_attr.append(DN(
                memberDN[0], 'cn=users', api.env.basedn))

    # If the group is an external group, it also contains ipaexternalmember
    # they are transformed into member: cn=SID,CN=ForeignSecurityPrincipals,..
    for memberSid in group.get('ipaexternalmember', []):
        memberDN = DN(
            ('cn', memberSid), api.env.container_fsp, api.env.basedn)
        new_member_attr.append(memberDN)
        # TODO
        # We also need to create the entry memberDN if it does not exist
    group['member'] = new_member_attr


def get_groupType(group):
    """Get the groupType for the provided groups

    If the group is a posixGroup, it is mapped to a security group (ie with
    the GROUP_TYPE_SECURITY_ENABLED flag), as a global group (ie with the
    GROUP_TYPE_ACCOUNT_GROUP flag).
    If the group is an external group, it is mapped to a security group, as
    a domain-local group (ie with the GROUP_TYPE_RESOURCE_GROUP flag).
    Other groups (non posix, non-external) are mapped to distribution groups
    as a global group.
    """
    objectclasses = set(oc.lower() for oc in group['objectclass'])
    if 'posixgroup' in objectclasses:
        groupType = GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP
    elif 'ipaexternalgroup' in objectclasses:
        groupType = GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_RESOURCE_GROUP
    else:
        groupType = GROUP_TYPE_ACCOUNT_GROUP

    # Make sure the signed value is used
    if groupType >= GROUP_TYPE_SECURITY_ENABLED:
        groupType -= GROUP_TYPE_OFFSET
    return groupType


def rename_groups(api, user):
    """Fix the memberof attribute of a user get_entry

    In IdM the groups are below cn=groups,cn=accounts,$suffix but in
    the Global Catalog they are in CN=Users,$suffix
    """
    groups_dn = DN(api.env.container_group, api.env.basedn)
    new_memberof_attr = []
    for groupDN in user.get('memberof', []):
        if groupDN.find(groups_dn) == 1:
            # The memberof value is right below the group container
            # rename and append
            new_memberof_attr.append(
                DN(groupDN[0], 'cn=users', api.env.basedn))
            continue
        # The memberof is not in the group container, keep as-is
        new_memberof_attr.append(groupDN)

    user['memberof'] = new_memberof_attr


class GCTransformer:
    def __init__(self, api, conn):
        loader = PackageLoader('ipaserver', 'globalcatalog/templates')
        jinja_env = Environment(loader=loader)
        self.user_template = jinja_env.get_template('gc_user_template.tmpl')
        self.group_template = jinja_env.get_template('gc_group_template.tmpl')
        self.api = api
        self.ldap_conn = conn

    def create_ldif_user(self, entry):
        """Creates a LDIF allowing to add the entry

        entry: the input user entry
        template: the jinja template to apply
        """
        # the uid value is multivalued, extract the right one as primary key
        # (i.e. the one from the DN)
        pkey = entry.dn[0][0].value
        sid = transform_sid(entry.single_value['ipantsecurityidentifier'])
        guid = transform_gid(entry.single_value['ipauniqueid'])
        rename_groups(api, entry)
        ldif_add = self.user_template.render(
            entry=entry, pkey=pkey, sid=sid, guid=guid,
            suffix=api.env.basedn)
        return ldif_add

    def create_ldif_group(self, entry):
        """Creates a LDIF allowing to add the group entry

        entry: the input group entry
        template: the jinja template to apply
        """
        # the cn value is multivalued, extract the right one as primary key
        # (i.e. the one from the DN)
        pkey = entry.dn[0][0].value
        try:
            sid = transform_sid(entry.single_value['ipantsecurityidentifier'])
        except KeyError:
            sid = None
        guid = transform_gid(entry.single_value['ipauniqueid'])
        groupType = get_groupType(entry)
        rename_group_members(self.api, entry, conn=self.ldap_conn)
        ldif_add = self.group_template.render(
            entry=entry, pkey=pkey, guid=guid,
            sid=sid, suffix=api.env.basedn, groupType=groupType)
        return ldif_add
