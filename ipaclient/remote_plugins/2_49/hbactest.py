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

HBAC rules control who can access what services on what hosts and from where.
You can use HBAC to control which users or groups can access a service,
or group of services, on a target host.

Since applying HBAC rules implies use of a production environment,
this plugin aims to provide simulation of HBAC rules evaluation without
having access to the production environment.

 Test user coming to a service on a named host against
 existing enabled rules.

 ipa hbactest --user= --host= --service=
              [--rules=rules-list] [--nodetail] [--enabled] [--disabled]
              [--srchost= ] [--sizelimit= ]

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

 If --srchost is specified, it will be ignored. It is left because of compatibility reasons only.

EXAMPLES:

    1. Use all enabled HBAC rules in IPA database to simulate:
    $ ipa  hbactest --user=a1a --host=bar --service=sshd
    --------------------
    Access granted: True
    --------------------
      notmatched: my-second-rule
      notmatched: my-third-rule
      notmatched: myrule
      matched: allow_all

    2. Disable detailed summary of how rules were applied:
    $ ipa hbactest --user=a1a --host=bar --service=sshd --nodetail
    --------------------
    Access granted: True
    --------------------

    3. Test explicitly specified HBAC rules:
    $ ipa hbactest --user=a1a --host=bar --service=sshd           --rules=my-second-rule,myrule
    ---------------------
    Access granted: False
    ---------------------
      notmatched: my-second-rule
      notmatched: myrule

    4. Use all enabled HBAC rules in IPA database + explicitly specified rules:
    $ ipa hbactest --user=a1a --host=bar --service=sshd           --rules=my-second-rule,myrule --enabled
    --------------------
    Access granted: True
    --------------------
      notmatched: my-second-rule
      notmatched: my-third-rule
      notmatched: myrule
      matched: allow_all

    5. Test all disabled HBAC rules in IPA database:
    $ ipa hbactest --user=a1a --host=bar --service=sshd --disabled
    ---------------------
    Access granted: False
    ---------------------
      notmatched: new-rule

    6. Test all disabled HBAC rules in IPA database + explicitly specified rules:
    $ ipa hbactest --user=a1a --host=bar --service=sshd           --rules=my-second-rule,myrule --disabled
    ---------------------
    Access granted: False
    ---------------------
      notmatched: my-second-rule
      notmatched: my-third-rule
      notmatched: myrule

    7. Test all (enabled and disabled) HBAC rules in IPA database:
    $ ipa hbactest --user=a1a --host=bar --service=sshd           --enabled --disabled
    --------------------
    Access granted: True
    --------------------
      notmatched: my-second-rule
      notmatched: my-third-rule
      notmatched: myrule
      notmatched: new-rule
      matched: allow_all
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
            cli_name='srchost',
            label=_(u'Source host'),
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
