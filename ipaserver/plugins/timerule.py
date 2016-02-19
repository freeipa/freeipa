#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import icalendar
from datetime import date
from ipalib import api, errors
from ipalib import Str
from ipalib import _, ngettext
from ipalib.plugable import Registry
from ipaserver.plugins.baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPRetrieve,
    LDAPUpdate,
    LDAPSearch)
from ipapython.ipa_log_manager import root_logger
from ipapython.dn import DN

__doc__ = _("""
Time Rules

Time Rules are rules used to describe time periods (mostly recurring events)
for different purposes. Most of the time the  purpose of a time rule is to
set a restrictive time policy, e.g. in HBAC rules where time rules are used
to restrict when the HBAC rule should apply.

These time rules are based on the iCalendar format
(https://tools.ietf.org/html/rfc5545).

There are multiple ways to create a time rule:
1) from an iCalendar string
    ipa timerule-add ruleName \\
    --time="BEGIN:VCALENDAR\\nPRODID:-//The Empire//iCal4j 1.0//EN\\n
VERSION:2.0\\nCALSCALE:GREGORIAN\\nMETHOD:REQUEST\\nBEGIN:VEVENT\\n
DTSTAMP:20160406T112129Z\\nDTSTART;VALUE=DATE:20160505\\nUID:1@darkside.com\\n
END:VEVENT\\nEND:VCALENDAR\\n"
    - note that the --time option requires an escaped string

2) from an iCalendar file (must be run from the client context)
    ipa timerule-add ruleName --icalfile=icalfile.ics
    - the --icalfile option requires an iCalendar file containing valid
      iCalendar string of a VCALENDAR component containing a single VEVENT
      subcomponent
""")

register = Registry()

topic = 'timerule'


def validate_ical_component(comp, name):
    if comp.errors:
        ical_errors = ('{prop}: {err}'
                       .format(prop=prop, err=e) for prop, e in comp.errors)
        raise errors.ValidationError(
            name=name,
            error=_('There were errors parsing the iCalendar string:\n%(errs)s'
                    ) % {'errs': '\n'.join(ical_errors)}
            )

    for prop in comp.required:
        if prop not in comp.keys():
            raise errors.ValidationError(
                name=name,
                error=_('A required property "%(prop)s" not found '
                        'in "%(comp)s".') % {'prop': prop, 'comp': comp.name}
                )

    for prop in comp.keys():
        if prop not in (comp.singletons + comp.multiple):
            raise errors.ValidationError(
                name=name,
                error=_('A "%(comp)s" component can\'t contain '
                        'property "%(prop)s".'
                        ) % {'comp': comp.name, 'prop': prop}
                )

        if (prop in comp.singletons and isinstance(comp[prop], list) and
                len(comp[prop]) > 1):
            raise errors.ValidationError(
                name=name,
                error=_('A "%(comp)s" component can\'t have more than '
                        'one "%(prop)s" property."'
                        ) % {'comp': comp.name, 'prop': prop}
                )


def validate_icalstring(ics):
    name = 'accesstime'

    try:
        vcal = icalendar.cal.Calendar().from_ical(ics)
    except ValueError as e:
        raise errors.ValidationError(
            name=name,
            error=_('Couln\'t parse iCalendar string: %(err)s'
                    ) % {'err': e}
            )

    if(vcal.name != 'VCALENDAR'):  # pylint: disable=no-member
        raise errors.ValidationError(
            name=name,
            error=_('Received object is not a VCALENDAR')
            )

    validate_ical_component(vcal, name)

    if len(vcal.subcomponents) > 1:  # pylint: disable=no-member
        raise errors.ValidationError(
            name=name,
            error=_('Only one VEVENT component may be present in the '
                    'iCalendar string at a time in this IPA version.'))

    comp = vcal.subcomponents[0]  # pylint: disable=no-member

    if comp.name != 'VEVENT':
        raise errors.ValidationError(
            name=name,
            error=_('Found "%(comp)s" but only VEVENT component is '
                    'supported.') % {'comp': comp.name}
            )

    validate_ical_component(comp, name)
    for sub in comp.subcomponents:
        if sub.name != 'VALARM':
            raise errors.ValidationError(
                name=name,
                error=_('A VEVENT component can\'t contain '
                        'subcomponent "%(sub)s".') % {'sub': sub.name}
                )
        else:
            root_logger.info(
                'Found "{comp}" but only VEVENT component is '
                'supported.'
                .format(comp=sub.name))

    # we WILL require DTSTART for VEVENTs
    if 'DTSTART' not in comp.keys():
        raise errors.ValidationError(
            name=name,
            error=_('DTSTART property is required in VEVENT.')
            )

    if 'DTEND' in comp.keys():
        if 'DURATION' in comp.keys():
            raise errors.ValidationError(
                name=name,
                error=_('Both DURATION and DTEND set in a VEVENT.')
            )

        if type(comp['DTSTART'].dt) != type(comp['DTEND'].dt):
            raise errors.ValidationError(
                name=name,
                error=_('Different types of DTSTART and DTEND '
                        'component in VEVENT.')
                )

    elif 'DURATION' in comp.keys() and isinstance(comp['DTSTART'].dt, date):
        # python-icalendar represents DURATION as datetime.timedelta. This,
        # in some cases, blocks us from checking whether it was originally
        # set correctly.
        #
        # Example: If DTSTART has value of type DATE, DURATION should be set
        # only as dur-day or dur-week. However, DURATION:PT24H will evaluate
        # as timedelta(1)
        if comp['DURATION'].dt.seconds:
            raise errors.ValidationError(
                name=name,
                error=_('DURATION is not of type dur-day or dur-week '
                        'when DTSTART value type is DATE.')
                )


@register()
class timerule(LDAPObject):
    """
    Time Rule object
    """
    container_dn = api.env.container_timerules
    object_name = _('Time Rule')
    object_name_plural = _('Time Rules')
    object_class = ['ipatimerule']
    permission_filter_objectclasses = ['ipatimerule']
    default_attributes = ['cn', 'description', 'accesstime', 'memberof']
    attribute_members = {
        'memberof': ['hbacrule']
    }
    label = _('Time Rules')
    label_singular = _('Time Rule')
    managed_permissions = {
        'System: Read Time Rule': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'description', 'accesstime'
            },
        },
        'System: Read Time Rule Membership': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'memberof',
            },
        },
        'System: Add Time Rule': {
            'ipapermright': {'add'},
            'default_privileges': {'Time Rules Administrator'},
        },
        'System: Delete Time Rule': {
            'ipapermright': {'delete'},
            'default_privileges': {'Time Rules Administrator'},
        },
        'System: Modify Time Rule': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'description', 'accesstime'},
            'default_privileges': {'Time Rules Administrator'},
        },
    }

    takes_params = (
        Str('cn', cli_name='name',
            label=_('Rule name'),
            primary_key=True),
        Str('description?',
            label=_('Description')
            ),
        # we need to have '?' here so that accessTime is not asked for if it is
        # set using options/from icalfile
        Str('accesstime?',
            cli_name='time',
            label=_('Access time'),
            ),
    )


@register()
class timerule_add(LDAPCreate):
    __doc__ = _('Create new time rule.')

    msg_summary = _('Added time rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert(isinstance(dn, DN))
        if not options.get('accesstime', False):
            raise errors.RequirementError(name='accesstime')
        entry_attrs['accesstime'] = \
            entry_attrs['accesstime'].decode('unicode-escape')
        # perform the validation here so that there's no need to decode
        # the string twice (validation and before storing it to LDAP)
        validate_icalstring(entry_attrs['accesstime'])
        return dn


@register()
class timerule_del(LDAPDelete):
    __doc__ = _('Delete a time rule.')

    msg_summary = _('Deleted time rule "%(value)s"')


@register()
class timerule_mod(LDAPUpdate):
    __doc__ = _('Modify a time rule.')

    msg_summary = _('Modified a time rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if 'accesstime' in entry_attrs:
            entry_attrs['accesstime'] = \
                entry_attrs['accesstime'].decode('unicode-escape')
            validate_icalstring(entry_attrs['accesstime'])
        return dn


@register()
class timerule_find(LDAPSearch):
    __doc__ = _('Search for time rules.')

    member_attributes = ['memberof']

    msg_summary = ngettext(
        '%(count)d time rule matched',
        '%(count)d time rules matched',
        0,
    )


@register()
class timerule_show(LDAPRetrieve):
    __doc__ = _('Display the properties of a time rule object')
