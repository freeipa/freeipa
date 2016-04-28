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

from __future__ import absolute_import

import re

from ipalib import errors

# dnsrecord param name formats
record_name_format = '%srecord'
part_name_format = "%s_part_%s"
extra_name_format = "%s_extra_%s"


def get_record_rrtype(name):
    match = re.match('([^_]+)record$', name)
    if match is None:
        return None

    return match.group(1).upper()


def get_part_rrtype(name):
    match = re.match('([^_]+)_part_.*$', name)
    if match is None:
        return None

    return match.group(1).upper()


def get_extra_rrtype(name):
    match = re.match('([^_]+)_extra_.*$', name)
    if match is None:
        return None

    return match.group(1).upper()


def has_cli_options(cmd, options, no_option_msg, allow_empty_attrs=False):
    sufficient = ('setattr', 'addattr', 'delattr', 'rename')
    if any(k in options for k in sufficient):
        return

    has_options = False
    for attr in options.keys():
        obj_params = [n for n in cmd.params
                      if get_record_rrtype(n) or get_part_rrtype(n)]
        if attr in obj_params:
            if options[attr] or allow_empty_attrs:
                has_options = True
                break

    if not has_options:
        raise errors.OptionError(no_option_msg)


def get_rrparam_from_part(cmd, part_name):
    """
    Get an instance of DNSRecord parameter that has part_name as its part.
    If such parameter is not found, None is returned

    :param part_name Part parameter name
    """
    try:
        param = cmd.params[part_name]

        rrtype = (get_part_rrtype(param.name) or
                  get_extra_rrtype(param.name))
        if not rrtype:
            return None

        # All DNS record part or extra parameters contain a name of its
        # parent RR parameter in its hint attribute
        rrparam = cmd.params[record_name_format % rrtype.lower()]
    except (KeyError, AttributeError):
        return None

    return rrparam


def iterate_rrparams_by_parts(cmd, kw, skip_extra=False):
    """
    Iterates through all DNSRecord instances that has at least one of its
    parts or extra options in given dictionary. It returns the DNSRecord
    instance only for the first occurence of part/extra option.

    :param kw Dictionary with DNS record parts or extra options
    :param skip_extra Skip DNS record extra options, yield only DNS records
                      with a real record part
    """
    processed = []
    for opt in kw:
        rrparam = get_rrparam_from_part(cmd, opt)
        if rrparam is None:
            continue

        if skip_extra and get_extra_rrtype(opt):
            continue

        if rrparam.name not in processed:
            processed.append(rrparam.name)
            yield rrparam
