# Authors:
#   Martin Kosek <mkosek@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from __future__ import print_function

import six
import copy
import re

from ipaclient.frontend import MethodOverride
from ipalib import errors
from ipalib.dns import (get_record_rrtype,
                        has_cli_options,
                        iterate_rrparams_by_parts,
                        part_name_format,
                        record_name_format)
from ipalib.frontend import Command
from ipalib.parameters import Bool, Str
from ipalib.plugable import Registry
from ipalib import _, ngettext
from ipalib import util
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

register = Registry()

# most used record types, always ask for those in interactive prompt
_top_record_types = ('A', 'AAAA', )
_rev_top_record_types = ('PTR', )
_zone_top_record_types = ('NS', 'MX', 'LOC', )


def __get_part_param(rrtype, cmd, part, output_kw, default=None):
    name = part_name_format % (rrtype.lower(), part.name)
    label = unicode(cmd.params[name].label)
    optional = not part.required

    output_kw[name] = cmd.prompt_param(part,
                                       optional=optional,
                                       label=label)


def prompt_parts(rrtype, cmd, mod_dnsvalue=None):
    mod_parts = None
    if mod_dnsvalue is not None:
        name = record_name_format % rrtype.lower()
        mod_parts = cmd.api.Command.dnsrecord_split_parts(
            name, mod_dnsvalue)['result']

    user_options = {}
    try:
        rrobj = cmd.api.Object['dns{}record'.format(rrtype.lower())]
    except KeyError:
        return user_options

    for part_id, part in enumerate(rrobj.params()):
        name = part_name_format % (rrtype.lower(), part.name)
        if name not in cmd.params:
            continue

        if mod_parts:
            default = mod_parts[part_id]
        else:
            default = None

        __get_part_param(rrtype, cmd, part, user_options, default)

    return user_options


def prompt_missing_parts(rrtype, cmd, kw, prompt_optional=False):
    user_options = {}
    try:
        rrobj = cmd.api.Object['dns{}record'.format(rrtype.lower())]
    except KeyError:
        return user_options

    for part in rrobj.params():
        name = part_name_format % (rrtype.lower(), part.name)
        if name not in cmd.params:
            continue

        if name in kw:
            continue

        optional = not part.required
        if optional and not prompt_optional:
            continue

        default = part.get_default(**kw)
        __get_part_param(rrtype, cmd, part, user_options, default)

    return user_options


class DNSZoneMethodOverride(MethodOverride):
    def get_options(self):
        for option in super(DNSZoneMethodOverride, self).get_options():
            if option.name == 'idnsallowdynupdate':
                option = option.clone_retype(option.name, Bool)
            yield option


@register(override=True, no_fail=True)
class dnszone_add(DNSZoneMethodOverride):
    pass


@register(override=True, no_fail=True)
class dnszone_mod(DNSZoneMethodOverride):
    pass


# Support old servers without dnsrecord_split_parts
# Do not add anything new here!
@register(no_fail=True)
class dnsrecord_split_parts(Command):
    NO_CLI = True

    takes_args = (
        Str('name'),
        Str('value'),
    )

    def execute(self, name, value, *args, **options):
        def split_exactly(count):
            values = value.split()
            if len(values) != count:
                return None
            return tuple(values)

        result = ()

        rrtype = get_record_rrtype(name)
        if rrtype in ('A', 'AAAA', 'CNAME', 'DNAME', 'NS', 'PTR'):
            result = split_exactly(1)
        elif rrtype in ('AFSDB', 'KX', 'MX'):
            result = split_exactly(2)
        elif rrtype in ('CERT', 'DLV', 'DS', 'SRV', 'TLSA'):
            result = split_exactly(4)
        elif rrtype in ('NAPTR'):
            result = split_exactly(6)
        elif rrtype in ('A6', 'TXT'):
            result = (value,)
        elif rrtype == 'LOC':
            regex = re.compile(
                r'(?P<d1>\d{1,2}\s+)'
                r'(?:(?P<m1>\d{1,2}\s+)'
                r'(?P<s1>\d{1,2}(?:\.\d{1,3})?\s+)?)?'
                r'(?P<dir1>[NS])\s+'
                r'(?P<d2>\d{1,3}\s+)'
                r'(?:(?P<m2>\d{1,2}\s+)'
                r'(?P<s2>\d{1,2}(?:\.\d{1,3})?\s+)?)?'
                r'(?P<dir2>[WE])\s+'
                r'(?P<alt>-?\d{1,8}(?:\.\d{1,2})?)m?'
                r'(?:\s+(?P<siz>\d{1,8}(?:\.\d{1,2})?)m?'
                r'(?:\s+(?P<hp>\d{1,8}(?:\.\d{1,2})?)m?'
                r'(?:\s+(?P<vp>\d{1,8}(?:\.\d{1,2})?)m?\s*)?)?)?$')

            m = regex.match(value)
            if m is not None:
                result = tuple(
                    x.strip() if x is not None else x for x in m.groups())
        elif rrtype == 'SSHFP':
            values = value.split(None, 2)
            if len(values) == 3:
                result = tuple(values)

        return dict(result=result)


@register(override=True, no_fail=True)
class dnsrecord_add(MethodOverride):
    no_option_msg = 'No options to add a specific record provided.\n' \
            "Command help may be consulted for all supported record types."

    def interactive_prompt_callback(self, kw):
        try:
            has_cli_options(self, kw, self.no_option_msg)

            # Some DNS records were entered, do not use full interactive help
            # We should still ask user for required parts of DNS parts he is
            # trying to add in the same way we do for standard LDAP parameters
            #
            # Do not ask for required parts when any "extra" option is used,
            # it can be used to fill all required params by itself
            new_kw = {}
            for rrparam in iterate_rrparams_by_parts(self, kw,
                                                     skip_extra=True):
                rrtype = get_record_rrtype(rrparam.name)
                user_options = prompt_missing_parts(rrtype, self, kw,
                                                    prompt_optional=False)
                new_kw.update(user_options)
            kw.update(new_kw)
            return
        except errors.OptionError:
            pass

        try:
            idnsname = DNSName(kw['idnsname'])
        except Exception as e:
            raise errors.ValidationError(name='idnsname', error=unicode(e))

        try:
            zonename = DNSName(kw['dnszoneidnsname'])
        except Exception as e:
            raise errors.ValidationError(name='dnszoneidnsname', error=unicode(e))

        # check zone type
        if idnsname.is_empty():
            common_types = u', '.join(_zone_top_record_types)
        elif zonename.is_reverse():
            common_types = u', '.join(_rev_top_record_types)
        else:
            common_types = u', '.join(_top_record_types)

        self.Backend.textui.print_plain(_(u'Please choose a type of DNS resource record to be added'))
        self.Backend.textui.print_plain(_(u'The most common types for this type of zone are: %s\n') %\
                                          common_types)

        ok = False
        while not ok:
            rrtype = self.Backend.textui.prompt(_(u'DNS resource record type'))

            if rrtype is None:
                return

            rrtype = rrtype.upper()

            try:
                name = record_name_format % rrtype.lower()
                param = self.params[name]

                if 'no_option' in param.flags:
                    raise ValueError()
            except (KeyError, ValueError):
                all_types = u', '.join(get_record_rrtype(p.name)
                                       for p in self.params()
                                       if (get_record_rrtype(p.name) and
                                           'no_option' not in p.flags))
                self.Backend.textui.print_plain(_(u'Invalid or unsupported type. Allowed values are: %s') % all_types)
                continue
            ok = True

        user_options = prompt_parts(rrtype, self)
        kw.update(user_options)


@register(override=True, no_fail=True)
class dnsrecord_mod(MethodOverride):
    no_option_msg = 'No options to modify a specific record provided.'

    def interactive_prompt_callback(self, kw):
        try:
            has_cli_options(self, kw, self.no_option_msg, True)
        except errors.OptionError:
            pass
        else:
            # some record type entered, skip this helper
            return

        # get DNS record first so that the NotFound exception is raised
        # before the helper would start
        dns_record = self.api.Command['dnsrecord_show'](kw['dnszoneidnsname'], kw['idnsname'])['result']

        self.Backend.textui.print_plain(_("No option to modify specific record provided."))

        # ask user for records to be removed
        self.Backend.textui.print_plain(_(u'Current DNS record contents:\n'))
        record_params = []

        for attr in dns_record:
            try:
                param = self.params[attr]
            except KeyError:
                continue
            rrtype = get_record_rrtype(param.name)
            if not rrtype:
                continue

            record_params.append((param, rrtype))
            rec_type_content = u', '.join(dns_record[param.name])
            self.Backend.textui.print_plain(u'%s: %s' % (param.label, rec_type_content))
        self.Backend.textui.print_plain(u'')

        # ask what records to remove
        for param, rrtype in record_params:
            rec_values = list(dns_record[param.name])
            for rec_value in dns_record[param.name]:
                rec_values.remove(rec_value)
                mod_value = self.Backend.textui.prompt_yesno(
                        _("Modify %(name)s '%(value)s'?") % dict(name=param.label, value=rec_value), default=False)
                if mod_value is True:
                    user_options = prompt_parts(rrtype, self,
                                                mod_dnsvalue=rec_value)
                    kw[param.name] = [rec_value]
                    kw.update(user_options)

                    if rec_values:
                         self.Backend.textui.print_plain(ngettext(
                            u'%(count)d %(type)s record skipped. Only one value per DNS record type can be modified at one time.',
                            u'%(count)d %(type)s records skipped. Only one value per DNS record type can be modified at one time.',
                            0) % dict(count=len(rec_values), type=rrtype))
                         break


@register(override=True, no_fail=True)
class dnsrecord_del(MethodOverride):
    no_option_msg = _('Neither --del-all nor options to delete a specific record provided.\n'\
            "Command help may be consulted for all supported record types.")

    def interactive_prompt_callback(self, kw):
        if kw.get('del_all', False):
            return
        try:
            has_cli_options(self, kw, self.no_option_msg)
        except errors.OptionError:
            pass
        else:
            # some record type entered, skip this helper
            return

        # get DNS record first so that the NotFound exception is raised
        # before the helper would start
        dns_record = self.api.Command['dnsrecord_show'](kw['dnszoneidnsname'], kw['idnsname'])['result']

        self.Backend.textui.print_plain(_("No option to delete specific record provided."))
        user_del_all = self.Backend.textui.prompt_yesno(_("Delete all?"), default=False)

        if user_del_all is True:
            kw['del_all'] = True
            return

        # ask user for records to be removed
        self.Backend.textui.print_plain(_(u'Current DNS record contents:\n'))
        present_params = []

        for attr in dns_record:
            try:
                param = self.params[attr]
            except KeyError:
                continue
            if not get_record_rrtype(param.name):
                continue

            present_params.append(param)
            rec_type_content = u', '.join(dns_record[param.name])
            self.Backend.textui.print_plain(u'%s: %s' % (param.label, rec_type_content))
        self.Backend.textui.print_plain(u'')

        # ask what records to remove
        for param in present_params:
            deleted_values = []
            for rec_value in dns_record[param.name]:
                user_del_value = self.Backend.textui.prompt_yesno(
                        _("Delete %(name)s '%(value)s'?")
                            % dict(name=param.label, value=rec_value), default=False)
                if user_del_value is True:
                     deleted_values.append(rec_value)
            if deleted_values:
                kw[param.name] = tuple(deleted_values)


@register(override=True, no_fail=True)
class dnsconfig_mod(MethodOverride):
    def interactive_prompt_callback(self, kw):

        # show informative message on client side
        # server cannot send messages asynchronous
        if kw.get('idnsforwarders', False):
            self.Backend.textui.print_plain(
                _("Server will check DNS forwarder(s)."))
            self.Backend.textui.print_plain(
                _("This may take some time, please wait ..."))


@register(override=True, no_fail=True)
class dnsforwardzone_add(MethodOverride):
    def interactive_prompt_callback(self, kw):
        if ('idnsforwarders' not in kw and
                kw.get('idnsforwardpolicy') != u'none'):
            kw['idnsforwarders'] = self.Backend.textui.prompt(
                _(u'DNS forwarder'))

        # show informative message on client side
        # server cannot send messages asynchronous
        if kw.get('idnsforwarders', False):
            self.Backend.textui.print_plain(
                _("Server will check DNS forwarder(s)."))
            self.Backend.textui.print_plain(
                _("This may take some time, please wait ..."))


@register(override=True, no_fail=True)
class dnsforwardzone_mod(MethodOverride):
    def interactive_prompt_callback(self, kw):
        # show informative message on client side
        # server cannot send messages asynchronous
        if kw.get('idnsforwarders', False):
            self.Backend.textui.print_plain(
                _("Server will check DNS forwarder(s)."))
            self.Backend.textui.print_plain(
                _("This may take some time, please wait ..."))


@register(override=True, no_fail=True)
class dns_update_system_records(MethodOverride):
    record_groups = ('ipa_records', 'location_records')

    takes_options = (
        Str(
            'out?',
            include='cli',
            doc=_('file to store DNS records in nsupdate format')
        ),
    )
    def _standard_output(self, textui, result, labels):
        """Print output in standard format common across the other plugins"""
        for key in self.record_groups:
            if result.get(key):
                textui.print_indented(u'{}:'.format(labels[key]), indent=1)
                for val in sorted(result[key]):
                    textui.print_indented(val, indent=2)
                textui.print_line(u'')

    def _nsupdate_output_file(self, out_f, result):
        """Store data in nsupdate format in file"""
        def parse_rname_rtype(record):
            """Get rname and rtype from textual representation of record"""
            l = record.split(' ', 4)
            return l[0], l[3]

        labels = {
            p.name: unicode(p.label) for p in self.output_params()
        }

        already_removed = set()
        for key in self.record_groups:
            if result.get(key):  # process only non-empty
                out_f.write("; {}\n".format(labels[key]))  # comment
                for val in sorted(result[key]):
                    # delete old first
                    r_name_type = parse_rname_rtype(val)
                    if r_name_type not in already_removed:
                        # remove it only once
                        already_removed.add(r_name_type)
                        out_f.write("update delete {rname} {rtype}\n".format(
                            rname=r_name_type[0], rtype=r_name_type[1]
                        ))
                    # add new
                    out_f.write("update add {}\n".format(val))
                out_f.write("send\n\n")

    def forward(self, *keys, **options):
        # pop `out` before sending to server as it is only client side option
        out = options.pop('out', None)
        if out:
            util.check_writable_file(out)

        res = super(dns_update_system_records, self).forward(*keys, **options)

        if out and 'result' in res:
            try:
                with open(out, "w") as f:
                    self._nsupdate_output_file(f, res['result'])
            except (OSError, IOError) as e:
                raise errors.FileError(reason=unicode(e))

        return res

    def output_for_cli(self, textui, output, *args, **options):
        output_super = copy.deepcopy(output)
        super_res = output_super.get('result', {})
        super_res.pop('ipa_records', None)
        super_res.pop('location_records', None)

        super(dns_update_system_records, self).output_for_cli(
            textui, output_super, *args, **options)

        labels = {
            p.name: unicode(p.label) for p in self.output_params()
        }

        result = output.get('result', {})

        self._standard_output(textui, result, labels)

        return int(not output['value'])
