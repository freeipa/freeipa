# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2011  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging

from ipalib import api, errors, output, util
from ipalib import Command, Str, Flag, Int
from ipalib import _
from ipapython.dn import DN
from ipalib.plugable import Registry
if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc
        _dcerpc_bindings_installed = True
    except ImportError:
        _dcerpc_bindings_installed = False

import six

try:
    import pyhbac
except ImportError:
    raise errors.SkipPluginModule(reason=_('pyhbac is not installed.'))


if six.PY3:
    unicode = str

__doc__ = _(r"""
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
    $ ipa hbactest --user=a1a --host=bar --service=sshd \\
          --rules=myrule --rules=my-second-rule
    ---------------------
    Access granted: False
    ---------------------
      Not matched rules: my-second-rule
      Not matched rules: myrule

    4. Use all enabled HBAC rules in IPA database + explicitly specified rules:
    $ ipa hbactest --user=a1a --host=bar --service=sshd \\
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
    $ ipa hbactest --user=a1a --host=bar --service=sshd \\
          --rules=myrule --rules=my-second-rule --disabled
    ---------------------
    Access granted: False
    ---------------------
      Not matched rules: my-second-rule
      Not matched rules: my-third-rule
      Not matched rules: myrule

    7. Test all (enabled and disabled) HBAC rules in IPA database:
    $ ipa hbactest --user=a1a --host=bar --service=sshd \\
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

    $ ipa hbactest --user S-1-5-21-3035198329-144811719-1378114514-500 \\
            --host `hostname` --service sshd
    --------------------
    Access granted: True
    --------------------
      Matched rules: allow_all
      Matched rules: can_login

    4. Test if other user from a trusted domain specified by its SID matches any rule:

    $ ipa hbactest --user S-1-5-21-3035198329-144811719-1378114514-1203 \\
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

logger = logging.getLogger(__name__)

register = Registry()

def _convert_to_ipa_rule(rule):
    # convert a dict with a rule to an pyhbac rule
    ipa_rule = pyhbac.HbacRule(rule['cn'][0])
    ipa_rule.enabled = rule['ipaenabledflag'][0]
    # Following code attempts to process rule systematically
    structure = \
        (('user',       'memberuser',    'user',    'group',        ipa_rule.users),
         ('host',       'memberhost',    'host',    'hostgroup',    ipa_rule.targethosts),
         ('sourcehost', 'sourcehost',    'host',    'hostgroup',    ipa_rule.srchosts),
         ('service',    'memberservice', 'hbacsvc', 'hbacsvcgroup', ipa_rule.services),
        )
    for element in structure:
        category = '%scategory' % (element[0])
        if (category in rule and rule[category][0] == u'all') or (element[0] == 'sourcehost'):
            # rule applies to all elements
            # sourcehost is always set to 'all'
            element[4].category = set([pyhbac.HBAC_CATEGORY_ALL])
        else:
            # rule is about specific entities
            # Check if there are explicitly listed entities
            attr_name = '%s_%s' % (element[1], element[2])
            if attr_name in rule:
                element[4].names = rule[attr_name]
            # Now add groups of entities if they are there
            attr_name = '%s_%s' % (element[1], element[3])
            if attr_name in rule:
                element[4].groups = rule[attr_name]
    if 'externalhost' in rule:
            ipa_rule.srchosts.names.extend(rule['externalhost']) #pylint: disable=E1101
    return ipa_rule


@register()
class hbactest(Command):
    __doc__ = _('Simulate use of Host-based access controls')

    has_output = (
        output.summary,
        output.Output('warning', (list, tuple, type(None)),   _('Warning')),
        output.Output('matched', (list, tuple, type(None)),   _('Matched rules')),
        output.Output('notmatched', (list, tuple, type(None)), _('Not matched rules')),
        output.Output('error', (list, tuple, type(None)), _('Non-existent or invalid rules')),
        output.Output('value',  bool, _('Result of simulation'), ['no_display']),
    )

    takes_options = (
        Str('user',
            cli_name='user',
            label=_('User name'),
            primary_key=True,
        ),
        Str('sourcehost?',
            deprecated=True,
            cli_name='srchost',
            label=_('Source host'),
            flags={'no_option'},
        ),
        Str('targethost',
            cli_name='host',
            label=_('Target host'),
        ),
        Str('service',
            cli_name='service',
            label=_('Service'),
        ),
        Str('rules*',
             cli_name='rules',
             label=_('Rules to test. If not specified, --enabled is assumed'),
        ),
        Flag('nodetail?',
             cli_name='nodetail',
             label=_('Hide details which rules are matched, not matched, or invalid'),
        ),
        Flag('enabled?',
             cli_name='enabled',
             label=_('Include all enabled IPA rules into test [default]'),
        ),
        Flag('disabled?',
             cli_name='disabled',
             label=_('Include all disabled IPA rules into test'),
        ),
        Int('sizelimit?',
            label=_('Size Limit'),
            doc=_('Maximum number of rules to process when no --rules is specified'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
    )

    def canonicalize(self, host):
        """
        Canonicalize the host name -- add default IPA domain if that is missing
        """
        if host.find('.') == -1:
            return u'%s.%s' % (host, self.env.domain)
        return host

    def execute(self, *args, **options):
        # First receive all needed information:
        # 1. HBAC rules (whether enabled or disabled)
        # 2. Required options are (user, target host, service)
        # 3. Options: rules to test (--rules, --enabled, --disabled), request for detail output
        rules = []

        # Use all enabled IPA rules by default
        all_enabled = True
        all_disabled = False

        # We need a local copy of test rules in order find incorrect ones
        testrules = {}
        if 'rules' in options:
            testrules = list(options['rules'])
            # When explicit rules are provided, disable assumptions
            all_enabled = False
            all_disabled = False

        sizelimit = None
        if 'sizelimit' in options:
            sizelimit = int(options['sizelimit'])

        # Check if --disabled is specified, include all disabled IPA rules
        if options['disabled']:
            all_disabled = True
            all_enabled = False

        # Finally, if enabled is specified implicitly, override above decisions
        if options['enabled']:
            all_enabled = True

        hbacset = []
        if len(testrules) == 0:
            hbacset = self.api.Command.hbacrule_find(
                sizelimit=sizelimit, no_members=False)['result']
        else:
            for rule in testrules:
                try:
                    hbacset.append(self.api.Command.hbacrule_show(rule)['result'])
                except Exception:
                    pass

        # We have some rules, import them
        # --enabled will import all enabled rules (default)
        # --disabled will import all disabled rules
        # --rules will implicitly add the rules from a rule list
        for rule in hbacset:
            ipa_rule = _convert_to_ipa_rule(rule)
            if ipa_rule.name in testrules:
                ipa_rule.enabled = True
                rules.append(ipa_rule)
                testrules.remove(ipa_rule.name)
            elif all_enabled and ipa_rule.enabled:
                # Option --enabled forces to include all enabled IPA rules into test
                rules.append(ipa_rule)
            elif all_disabled and not ipa_rule.enabled:
                # Option --disabled forces to include all disabled IPA rules into test
                ipa_rule.enabled = True
                rules.append(ipa_rule)

        # Check if there are unresolved rules left
        if len(testrules) > 0:
            # Error, unresolved rules are left in --rules
            return {'summary' : unicode(_(u'Unresolved rules in --rules')),
                    'error': testrules, 'matched': None, 'notmatched': None,
                    'warning' : None, 'value' : False}

        # Rules are converted to pyhbac format, build request and then test it
        request = pyhbac.HbacRequest()

        if options['user'] != u'all':
            # check first if this is not a trusted domain user
            if _dcerpc_bindings_installed:
                is_valid_sid = ipaserver.dcerpc.is_sid_valid(options['user'])
            else:
                is_valid_sid = False
            components = util.normalize_name(options['user'])
            if is_valid_sid or 'domain' in components or 'flatname' in components:
                # this is a trusted domain user
                if not _dcerpc_bindings_installed:
                    raise errors.NotFound(reason=_(
                        'Cannot perform external member validation without '
                        'Samba 4 support installed. Make sure you have installed '
                        'server-trust-ad sub-package of IPA on the server'))
                domain_validator = ipaserver.dcerpc.DomainValidator(self.api)
                if not domain_validator.is_configured():
                    raise errors.NotFound(reason=_(
                        'Cannot search in trusted domains without own domain configured. '
                        'Make sure you have run ipa-adtrust-install on the IPA server first'))
                user_sid, group_sids = domain_validator.get_trusted_domain_user_and_groups(options['user'])
                request.user.name = user_sid

                # Now search for all external groups that have this user or
                # any of its groups in its external members. Found entires
                # memberOf links will be then used to gather all groups where
                # this group is assigned, including the nested ones
                filter_sids = "(&(objectclass=ipaexternalgroup)(|(ipaExternalMember=%s)))" \
                        % ")(ipaExternalMember=".join(group_sids + [user_sid])

                ldap = self.api.Backend.ldap2
                group_container = DN(api.env.container_group, api.env.basedn)
                try:
                    entries, _truncated = ldap.find_entries(
                        filter_sids, ['memberof'], group_container)
                except errors.NotFound:
                    request.user.groups = []
                else:
                    groups = []
                    for entry in entries:
                        memberof_dns = entry.get('memberof', [])
                        for memberof_dn in memberof_dns:
                            if memberof_dn.endswith(group_container):
                                groups.append(memberof_dn[0][0].value)
                    request.user.groups = sorted(set(groups))
            else:
                # try searching for a local user
                try:
                    request.user.name = options['user']
                    search_result = self.api.Command.user_show(request.user.name)['result']
                    groups = search_result['memberof_group']
                    if 'memberofindirect_group' in search_result:
                        groups += search_result['memberofindirect_group']
                    request.user.groups = sorted(set(groups))
                except Exception:
                    pass

        if options['service'] != u'all':
            try:
                request.service.name = options['service']
                service_result = self.api.Command.hbacsvc_show(request.service.name)['result']
                if 'memberof_hbacsvcgroup' in service_result:
                    request.service.groups = service_result['memberof_hbacsvcgroup']
            except Exception:
                pass

        if options['targethost'] != u'all':
            try:
                request.targethost.name = self.canonicalize(options['targethost'])
                tgthost_result = self.api.Command.host_show(request.targethost.name)['result']
                groups = tgthost_result['memberof_hostgroup']
                if 'memberofindirect_hostgroup' in tgthost_result:
                    groups += tgthost_result['memberofindirect_hostgroup']
                request.targethost.groups = sorted(set(groups))
            except Exception:
                pass

        matched_rules = []
        notmatched_rules = []
        error_rules = []
        warning_rules = []

        result = {'warning':None, 'matched':None, 'notmatched':None, 'error':None}
        if not options['nodetail']:
            # Validate runs rules one-by-one and reports failed ones
            for ipa_rule in rules:
                try:
                    res = request.evaluate([ipa_rule])
                    if res == pyhbac.HBAC_EVAL_ALLOW:
                        matched_rules.append(ipa_rule.name)
                    if res == pyhbac.HBAC_EVAL_DENY:
                        notmatched_rules.append(ipa_rule.name)
                except pyhbac.HbacError as e:
                    code, rule_name = e.args
                    if code == pyhbac.HBAC_EVAL_ERROR:
                        error_rules.append(rule_name)
                        logger.info('Native IPA HBAC rule "%s" parsing error: '
                                    '%s',
                                    rule_name, pyhbac.hbac_result_string(code))
                except (TypeError, IOError) as info:
                    logger.error('Native IPA HBAC module error: %s', info)

            access_granted = len(matched_rules) > 0
        else:
            res = request.evaluate(rules)
            access_granted = (res == pyhbac.HBAC_EVAL_ALLOW)

        result['summary'] = _('Access granted: %s') % (access_granted)


        if len(matched_rules) > 0:
            result['matched'] = matched_rules
        if len(notmatched_rules) > 0:
            result['notmatched'] = notmatched_rules
        if len(error_rules) > 0:
            result['error'] = error_rules
        if len(warning_rules) > 0:
            result['warning'] = warning_rules

        result['value'] = access_granted
        return result
