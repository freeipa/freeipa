#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import
import six

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

__doc__ = _("""
Simulate use of Host-based access controls

HBAC rules control who can access what services on what hosts.
You can use HBAC to control which users or groups can access a service,
or group of services, on a target host.

Since applying HBAC rules implies use of a production environment,
this plugin aims to provide simulation of HBAC rules evaluation without
having access to the production environment.

 Test user coming to a service on a named host against
 existing enabled rules.

 ipa hbactest --user= --host= --service=
              [--rules=rules-list] [--nodetail] [--enabled] [--disabled]
              [--sizelimit= ]

 --user, --host, and --service are mandatory, others are optional.

 If --rules is specified simulate enabling of the specified rules and test
 the login of the user using only these rules.

 If --enabled is specified, all enabled HBAC rules will be added to simulation

 If --disabled is specified, all disabled HBAC rules will be added to simulation

 If --nodetail is specified, do not return information about rules matched/not matched.

 If both --rules and --enabled are specified, apply simulation to --rules _and_
 all IPA enabled rules.

 If no --rules specified, simulation is run against all IPA enabled rules.
 By default there is a IPA-wide limit to number of entries fetched, you can change it
 with --sizelimit option.

EXAMPLES:

    1. Use all enabled HBAC rules in IPA database to simulate:
    $ ipa  hbactest --user=a1a --host=bar --service=sshd
    --------------------
    Access granted: True
    --------------------
      Not matched rules: my-second-rule
      Not matched rules: my-third-rule
      Not matched rules: myrule
      Matched rules: allow_all

    2. Disable detailed summary of how rules were applied:
    $ ipa hbactest --user=a1a --host=bar --service=sshd --nodetail
    --------------------
    Access granted: True
    --------------------

    3. Test explicitly specified HBAC rules:
    $ ipa hbactest --user=a1a --host=bar --service=sshd \
          --rules=myrule --rules=my-second-rule
    ---------------------
    Access granted: False
    ---------------------
      Not matched rules: my-second-rule
      Not matched rules: myrule

    4. Use all enabled HBAC rules in IPA database + explicitly specified rules:
    $ ipa hbactest --user=a1a --host=bar --service=sshd \
          --rules=myrule --rules=my-second-rule --enabled
    --------------------
    Access granted: True
    --------------------
      Not matched rules: my-second-rule
      Not matched rules: my-third-rule
      Not matched rules: myrule
      Matched rules: allow_all

    5. Test all disabled HBAC rules in IPA database:
    $ ipa hbactest --user=a1a --host=bar --service=sshd --disabled
    ---------------------
    Access granted: False
    ---------------------
      Not matched rules: new-rule

    6. Test all disabled HBAC rules in IPA database + explicitly specified rules:
    $ ipa hbactest --user=a1a --host=bar --service=sshd \
          --rules=myrule --rules=my-second-rule --disabled
    ---------------------
    Access granted: False
    ---------------------
      Not matched rules: my-second-rule
      Not matched rules: my-third-rule
      Not matched rules: myrule

    7. Test all (enabled and disabled) HBAC rules in IPA database:
    $ ipa hbactest --user=a1a --host=bar --service=sshd \
          --enabled --disabled
    --------------------
    Access granted: True
    --------------------
      Not matched rules: my-second-rule
      Not matched rules: my-third-rule
      Not matched rules: myrule
      Not matched rules: new-rule
      Matched rules: allow_all


HBACTEST AND TRUSTED DOMAINS

When an external trusted domain is configured in IPA, HBAC rules are also applied
on users accessing IPA resources from the trusted domain. Trusted domain users and
groups (and their SIDs) can be then assigned to external groups which can be
members of POSIX groups in IPA which can be used in HBAC rules and thus allowing
access to resources protected by the HBAC system.

hbactest plugin is capable of testing access for both local IPA users and users
from the trusted domains, either by a fully qualified user name or by user SID.
Such user names need to have a trusted domain specified as a short name
(DOMAIN\Administrator) or with a user principal name (UPN), Administrator@ad.test.

Please note that hbactest executed with a trusted domain user as --user parameter
can be only run by members of "trust admins" group.

EXAMPLES:

    1. Test if a user from a trusted domain specified by its shortname matches any
       rule:

    $ ipa hbactest --user 'DOMAIN\Administrator' --host `hostname` --service sshd
    --------------------
    Access granted: True
    --------------------
      Matched rules: allow_all
      Matched rules: can_login

    2. Test if a user from a trusted domain specified by its domain name matches
       any rule:

    $ ipa hbactest --user 'Administrator@domain.com' --host `hostname` --service sshd
    --------------------
    Access granted: True
    --------------------
      Matched rules: allow_all
      Matched rules: can_login

    3. Test if a user from a trusted domain specified by its SID matches any rule:

    $ ipa hbactest --user S-1-5-21-3035198329-144811719-1378114514-500 \
            --host `hostname` --service sshd
    --------------------
    Access granted: True
    --------------------
      Matched rules: allow_all
      Matched rules: can_login

    4. Test if other user from a trusted domain specified by its SID matches any rule:

    $ ipa hbactest --user S-1-5-21-3035198329-144811719-1378114514-1203 \
            --host `hostname` --service sshd
    --------------------
    Access granted: True
    --------------------
      Matched rules: allow_all
      Not matched rules: can_login

   5. Test if other user from a trusted domain specified by its shortname matches
       any rule:

    $ ipa hbactest --user 'DOMAIN\Otheruser' --host `hostname` --service sshd
    --------------------
    Access granted: True
    --------------------
      Matched rules: allow_all
      Not matched rules: can_login
""")

register = Registry()


@register()
class hbactest(Command):
    __doc__ = _("Simulate use of Host-based access controls")

    takes_options = (
        parameters.Str(
            'user',
            label=_(u'User name'),
        ),
        parameters.Str(
            'sourcehost',
            required=False,
            deprecated=True,
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'targethost',
            cli_name='host',
            label=_(u'Target host'),
        ),
        parameters.Str(
            'service',
            label=_(u'Service'),
        ),
        parameters.Str(
            'rules',
            required=False,
            multivalue=True,
            label=_(u'Rules to test. If not specified, --enabled is assumed'),
        ),
        parameters.Flag(
            'nodetail',
            required=False,
            label=_(u'Hide details which rules are matched, not matched, or invalid'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'enabled',
            required=False,
            label=_(u'Include all enabled IPA rules into test [default]'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'disabled',
            required=False,
            label=_(u'Include all disabled IPA rules into test'),
            default=False,
            autofill=True,
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of rules to process when no --rules is specified'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'warning',
            (list, tuple, type(None)),
            doc=_(u'Warning'),
        ),
        output.Output(
            'matched',
            (list, tuple, type(None)),
            doc=_(u'Matched rules'),
        ),
        output.Output(
            'notmatched',
            (list, tuple, type(None)),
            doc=_(u'Not matched rules'),
        ),
        output.Output(
            'error',
            (list, tuple, type(None)),
            doc=_(u'Non-existent or invalid rules'),
        ),
        output.Output(
            'value',
            bool,
            doc=_(u'Result of simulation'),
        ),
    )
