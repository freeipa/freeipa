#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipalib import (
    _,
    ngettext,
    api,
    Str,
    DNSNameParam
)
from ipalib.plugable import Registry
from ipaserver.plugins.baseldap import (
    LDAPCreate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPDelete,
    LDAPObject,
    LDAPUpdate,
)
from ipapython.dnsutil import DNSName

__doc__ = _("""
IPA locations
""") + _("""
Manipulate DNS locations
""") + _("""
EXAMPLES:
""") + _("""
  Find all locations:
    ipa location-find
""") + _("""
  Show specific location:
    ipa location-show location
""") + _("""
  Add location:
    ipa location-add location --description 'My location'
""") + _("""
  Delete location:
    ipa location-del location
""")

register = Registry()


@register()
class location(LDAPObject):
    """
    IPA locations
    """
    container_dn = api.env.container_locations
    object_name = _('location')
    object_name_plural = _('locations')
    object_class = ['top', 'ipaLocationObject']
    search_attributes = ['idnsName']
    default_attributes = [
        'idnsname', 'description'
    ]
    label = _('IPA Locations')
    label_singular = _('IPA Location')

    permission_filter_objectclasses = ['ipaLocationObject']
    managed_permissions = {
        'System: Read IPA Locations': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'idnsname', 'description',
            },
            'default_privileges': {'DNS Administrators'},
        },
        'System: Add IPA Locations': {
            'ipapermright': {'add'},
            'default_privileges': {'DNS Administrators'},
        },
        'System: Remove IPA Locations': {
            'ipapermright': {'delete'},
            'default_privileges': {'DNS Administrators'},
        },
        'System: Modify IPA Locations': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'description',
            },
            'default_privileges': {'DNS Administrators'},
        },
    }

    takes_params = (
        DNSNameParam(
            'idnsname',
            cli_name='name',
            primary_key=True,
            label=_('Location name'),
            doc=_('IPA location name'),
            # dns name must be relative, we will put it into middle of
            # location domain name for location records
            only_relative=True,
        ),
        Str(
            'description?',
            label=_('Description'),
            doc=_('IPA Location description'),
        ),
    )

    def get_dn(self, *keys, **options):
        loc = keys[-1]
        assert isinstance(loc, DNSName)
        loc_a = loc.ToASCII()

        return super(location, self).get_dn(loc_a, **options)


@register()
class location_add(LDAPCreate):
    __doc__ = _('Add a new IPA location.')

    msg_summary = _('Added IPA location "%(value)s"')


@register()
class location_del(LDAPDelete):
    __doc__ = _('Delete an IPA location.')

    msg_summary = _('Deleted IPA location "%(value)s"')


@register()
class location_mod(LDAPUpdate):
    __doc__ = _('Modify information about an IPA location.')

    msg_summary = _('Modified IPA location "%(value)s"')


@register()
class location_find(LDAPSearch):
    __doc__ = _('Search for IPA locations.')

    msg_summary = ngettext(
        '%(count)d IPA location matched',
        '%(count)d IPA locations matched', 0
    )


@register()
class location_show(LDAPRetrieve):
    __doc__ = _('Display information about an IPA location.')
