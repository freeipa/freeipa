# Authors:
#   John Dennis <jdennis@redhat.com>
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
#

from __future__ import print_function

# WARNING: Do not import ipa modules, this is also used as a
# stand-alone script (invoked from po Makefile).
import optparse  # pylint: disable=deprecated-module
import sys
import gettext
import re
import os
import traceback
import polib
from collections import namedtuple

import six

'''
We test our translations by taking the original untranslated string
(e.g. msgid) and prepend a prefix character and then append a suffix
character. The test consists of asserting that the first character in the
translated string is the prefix, the last character in the translated string
is the suffix and the everything between the first and last character exactly
matches the original msgid.

We use unicode characters not in the ascii character set for the prefix and
suffix to enhance the test. To make reading the translated string easier the
prefix is the unicode right pointing arrow and the suffix left pointing arrow,
thus the translated string looks like the original string enclosed in
arrows. In ASCII art the string "foo" would render as:
-->foo<--
'''

#-------------------------------------------------------------------------------

verbose = False
print_traceback = False
pedantic = False
show_strings = True

# Unicode right pointing arrow
prefix = u'\u2192'               # utf-8 == '\xe2\x86\x92'
# Unicode left pointing arrow
suffix = u'\u2190'               # utf-8 == '\xe2\x86\x90'

page_width = 80
section_seperator = '=' * page_width
entry_seperator = '-' * page_width

# Python 3: Enforce ASCII mode so \w matches only ASCII chars. This avoids
# false positives in Chinese translation.
ASCII = getattr(re, "ASCII", 0)

# --------------------------------------------------------------------------
# For efficiency compile these regexps just once
_substitution_regexps = [
    re.compile(r'%[srduoxf]'),                 # e.g. %s
    re.compile(r'%\(\w+\)[srduoxf]', ASCII),   # e.g. %(foo)s
    re.compile(r'\$\w+', ASCII),               # e.g. $foo
    re.compile(r'\${\w+}', ASCII),             # e.g. ${foo}
    re.compile(r'\$\(\w+\)', ASCII)            # e.g. $(foo)
]
# Python style substitution, e.g. %(foo)s
# where foo is the key and s is the format char
# group 1: whitespace between % and (
# group 2: whitespace between ( and key
# group 3: whitespace between key and )
# group 4: whitespace between ) and format char
# group 5: format char
_python_substitution_regexp = re.compile(
    r'%(\s*)\((\s*)\w+(\s*)\)(\s*)([srduoxf])?', ASCII
)

# Shell style substitution, e.g. $foo $(foo) ${foo}
# where foo is the variable
_shell_substitution_regexp = re.compile(
    r'\$(\s*)([({]?)(\s*)\w+(\s*)([)}]?)', ASCII
)
# group 1: whitespace between $ and delimiter
# group 2: begining delimiter
# group 3: whitespace between beginning delmiter and variable
# group 4: whitespace between variable and ending delimiter
# group 5: ending delimiter

printf_fmt_re = re.compile(
    r"%"                                      # start
    r"(\d+\$)?"                               # fmt_arg    (group  1)
    r"(([#0 +'I]|-(?!\d))*)"                  # flags      (group  2)
    r"(([+-]?([1-9][0-9]*)?)|(\*|\*\d+\$))?"  # width      (group  4)
    r"(\.((-?\d*)|(\*|)|(\*\d+\$)))?"         # precision  (group  8)
    r"(h|hh|l|ll|L|j|z|t)?"                   # length     (group 13)
    r"([diouxXeEfFgGaAcspnm%])")              # conversion (group 14)

#-------------------------------------------------------------------------------

def get_prog_langs(entry):
    '''
    Given an entry in a pot or po file return a set of the
    programming languges it was found in. It needs to be a set
    because the same msgid may appear in more than one file which may
    be in different programming languages.

    Note: One might think you could use the c-format etc. flags to
    attached to entry to make this determination, but you can't. Those
    flags refer to the style of the string not the programming
    language it came from. Also the flags are often omitted and/or are
    inaccurate.

    For now we just look at the file extension. If we knew the path to
    the file we could use other heuristics such as looking for the
    shbang interpreter string.

    The set of possible language types witch might be returned are:

    * c
    * python

    '''
    result = set()

    for location in entry.occurrences:
        filename = location[0]
        ext = os.path.splitext(filename)[1]

        if ext in ('.c', '.h', '.cxx', '.cpp', '.hxx'):
            result.add('c')
        elif ext in ('.py'):
            result.add('python')

    return result

def parse_printf_fmt(s):
    '''
    Parse a printf style format string and return a list of format
    conversions found in the string.

    Each conversion specification is introduced by the character %, and
    ends with a conversion specifier.  In between there may be (in this
    order) zero or more flags, an optional minimum field width, an
    optional precision and an optional length modifier. See "man 3
    printf" for details.

    Each item in the returned list is a dict whose keys are the
    sub-parts of a conversion specification. The key and values are:

    fmt
        The entire format conversion specification
    fmt_arg
        The positional index of the matching argument in the argument
        list, e.g. %1$ indicates the first argument in the argument
        will be read for this conversion, excludes the leading % but
        includes the trailing $, 1$ is the fmt_arg in %1$.
    flags
        The flag characaters, e.g. 0 is the flag in %08d
    width
        The width field, e.g. 20 is the width in %20s
    precision
        The precisioin field, e.g. .2 is the precision in %8.2f
    length
        The length modifier field, e.g. l is the length modifier in %ld
    conversion
        The conversion specifier character, e.g. d is the conversion
        specification character in %ld

    If the part is not found in the format it's value will be None.
    '''

    result = []

    # get list of all matches, but skip escaped %
    matches = [x for x in printf_fmt_re.finditer(s) if x.group(0) != "%%"]

    # build dict of each sub-part of the format, append to result
    for match in matches:
        parts = {}
        parts['fmt']        = match.group(0)
        parts['fmt_arg']    = match.group(1)
        parts['flags']      = match.group(2) or None
        parts['width']      = match.group(4) or None
        parts['precision']  = match.group(8)
        parts['length']     = match.group(13)
        parts['conversion'] = match.group(14)

        result.append(parts)

    return result

def validate_substitutions_match(s1, s2, s1_name='string1', s2_name='string2'):
    '''
    Validate both s1 and s2 have the same number of substitution strings.
    A substitution string would be something that looked like this:

    * %(foo)s
    * $foo
    * ${foo}
    * $(foo)

    The substitutions may appear in any order in s1 and s2, however their
    format must match exactly and the exact same number of each must exist
    in both s1 and s2.

    A list of error diagnostics is returned explaining how s1 and s2 failed
    the validation check. If the returned error list is empty then the
    validation succeeded.

    :param s1:      First string to validate
    :param s2:      First string to validate
    :param s1_name: In diagnostic messages the name for s1
    :param s2_name: In diagnostic messages the name for s2
    :return:        List of diagnostic error messages, if empty then success
    '''
    errors = []

    def get_subs(s):
        '''
        Return a dict whoses keys are each unique substitution and whose
        value is the count of how many times that substitution appeared.
        '''
        subs = {}
        for regexp in _substitution_regexps:
            for match in regexp.finditer(s):
                matched = match.group(0)
                subs[matched] = subs.get(matched, 0) + 1
        return subs

    # Get the substitutions and their occurance counts
    subs1 = get_subs(s1)
    subs2 = get_subs(s2)

    # Form a set for each strings substitutions and
    # do set subtraction and interesection
    set1 = set(subs1.keys())
    set2 = set(subs2.keys())

    missing1 = set2 - set1
    missing2 = set1 - set2
    common = set1 & set2

    # Test for substitutions which are absent in either string
    if missing1:
        errors.append("The following substitutions are absent in %s: %s" %
                      (s1_name, ' '.join(missing1)))

    if missing2:
        errors.append("The following substitutions are absent in %s: %s" %
                      (s2_name, ' '.join(missing2)))

    if pedantic:
        # For the substitutions which are shared assure they occur an equal number of times
        for sub in common:
            if subs1[sub] != subs2[sub]:
                errors.append("unequal occurances of '%s', %s has %d occurances, %s has %d occurances" %
                              (sub, s1_name, subs1[sub], s2_name, subs2[sub]))

    if errors:
        if show_strings:
            errors.append('>>> %s <<<' % s1_name)
            errors.append(s1.rstrip())

            errors.append('>>> %s <<<' % s2_name)
            errors.append(s2.rstrip())
    return errors


def validate_substitution_syntax(s, s_name='string'):
    '''
    If s has one or more substitution variables then validate they
    are syntactically correct.
    A substitution string would be something that looked like this:

    * %(foo)s
    * $foo
    * ${foo}
    * $(foo)

    A list of error diagnostics is returned explaining how s1 and s2 failed
    the validation check. If the returned error list is empty then the
    validation succeeded.

    :param s:      String to validate
    :param s_name: In diagnostic messages the name for s
    :return:       List of diagnostic error messages, if empty then success
    '''
    errors = []

    # Look for Python style substitutions, e.g. %(foo)s
    for match in _python_substitution_regexp.finditer(s):
        if match.group(1):
            errors.append("%s has whitespace between %% and key in '%s'" %
                          (s_name, match.group(0)))
        if match.group(2) or match.group(3):
            errors.append("%s has whitespace next to key in '%s'" %
                          (s_name, match.group(0)))
        if match.group(4):
            errors.append("%s has whitespace between key and format character in '%s'" %
                          (s_name, match.group(0)))
        if not match.group(5):
            errors.append("%s has no format character in '%s'" %
                          (s_name, match.group(0)))

    # Look for shell style substitutions, e.g. $foo $(foo) ${foo}
    for match in _shell_substitution_regexp.finditer(s):
        if match.group(1):
            errors.append("%s has whitespace between $ and variable in '%s'" %
                          (s_name, match.group(0)))
        if match.group(3) or (match.group(4) and match.group(5)):
            errors.append("%s has whitespace next to variable in '%s'" %
                          (s_name, match.group(0)))

        beg_delimiter = match.group(2)
        end_delimiter = match.group(5)
        matched_delimiters = {'': '', '(': ')', '{': '}'}
        if beg_delimiter is not None or end_delimiter is not None:
            if matched_delimiters[beg_delimiter] != end_delimiter:
                errors.append("%s variable delimiters do not match in '%s', begin delimiter='%s' end delimiter='%s'" %
                              (s_name, match.group(0), beg_delimiter, end_delimiter))

    if errors:
        if show_strings:
            errors.append('>>> %s <<<' % s_name)
            errors.append(s.rstrip())

    return errors


def validate_positional_substitutions(s, prog_langs, s_name='string'):
    '''
    We do not permit multiple positional substitutions in translation
    strings (e.g. '%s') because they do not allow translators to reorder the
    wording. Instead keyword substitutions should be used when there are
    more than one.
    '''
    errors = []

    fmts = parse_printf_fmt(s)
    n_fmts = len(fmts)

    errors = []
    if n_fmts > 1:
        for fmt_parts in fmts:
            fmt        = fmt_parts['fmt']
            fmt_arg    = fmt_parts['fmt_arg']
            width      = fmt_parts['width']

            if width == '*':
                errors.append("Error: * width arg in format '%s should be indexed" % fmt)

            if fmt_arg is None:
                if 'c' in prog_langs:
                    errors.append("%s format '%s' is positional, should use indexed argument" %
                                  (s_name, fmt))
                else:
                    errors.append("%s format '%s' is positional, should use keyword substitution" %
                                  (s_name, fmt))

    if errors:
        if show_strings:
            errors.append('>>> %s <<<' % s_name)
            errors.append(s.rstrip())

    return errors

def validate_file(file_path, validation_mode, reference_pot=None):
    '''
    Given a pot or po file scan all it's entries looking for problems
    with variable substitutions. See the following functions for
    details on how the validation is performed.

    * validate_substitutions_match()
    * validate_substitution_syntax()
    * validate_positional_substitutions()

    Returns the number of entries with errors.

    For po files, ``reference_pot`` gives a pot file to merge with (to recover
    comments and file locations)
    '''

    def emit_messages():
        if n_warnings:
            warning_lines.insert(0, section_seperator)
            warning_lines.insert(1, "%d validation warnings in %s" % (n_warnings, file_path))
            print('\n'.join(warning_lines))

        if n_errors:
            error_lines.insert(0, section_seperator)
            error_lines.insert(1, "%d validation errors in %s" % (n_errors, file_path))
            print('\n'.join(error_lines))

    Result = namedtuple('ValidateFileResult', ['n_entries', 'n_msgids', 'n_msgstrs', 'n_warnings', 'n_errors'])

    warning_lines = []
    error_lines = []
    n_entries = 0
    n_msgids = 0
    n_msgstrs = 0
    n_entries = 0
    n_warnings = 0
    n_errors  = 0
    n_plural_forms = 0

    if not os.path.isfile(file_path):
        error_lines.append(entry_seperator)
        error_lines.append('file does not exist "%s"' % (file_path))
        n_errors += 1
        emit_messages()
        return Result(n_entries=n_entries, n_msgids=n_msgids, n_msgstrs=n_msgstrs, n_warnings=n_warnings, n_errors=n_errors)

    try:
        po = polib.pofile(file_path)
    except Exception as e:
        error_lines.append(entry_seperator)
        error_lines.append('Unable to parse file "%s": %s' % (file_path, e))
        n_errors += 1
        emit_messages()
        return Result(n_entries=n_entries, n_msgids=n_msgids, n_msgstrs=n_msgstrs, n_warnings=n_warnings, n_errors=n_errors)

    if validation_mode == 'po' and reference_pot:
        # Merge the .pot file for comments and file locations
        po.merge(reference_pot)

    if validation_mode == 'po':
        plural_forms = po.metadata.get('Plural-Forms')
        if not plural_forms:
            error_lines.append(entry_seperator)
            error_lines.append("%s: does not have Plural-Forms header" % file_path)
            n_errors += 1
        match = re.search(r'\bnplurals\s*=\s*(\d+)', plural_forms)
        if match:
            n_plural_forms = int(match.group(1))
        else:
            error_lines.append(entry_seperator)
            error_lines.append("%s: does not specify integer nplurals in Plural-Forms header" % file_path)
            n_errors += 1

    n_entries = len(po)
    for entry in po:
        entry_warnings = []
        entry_errors = []
        have_msgid = entry.msgid.strip() != ''
        have_msgid_plural = entry.msgid_plural.strip() != ''
        have_msgstr = entry.msgstr.strip() != ''

        if have_msgid:
            n_msgids += 1
        if have_msgid_plural:
            n_msgids += 1
        if have_msgstr:
            n_msgstrs += 1

        if validation_mode == 'pot':
            prog_langs = get_prog_langs(entry)
            if have_msgid:
                errors = validate_positional_substitutions(entry.msgid, prog_langs, 'msgid')
                entry_errors.extend(errors)
            if have_msgid_plural:
                errors = validate_positional_substitutions(entry.msgid_plural, prog_langs, 'msgid_plural')
                entry_errors.extend(errors)
        elif validation_mode == 'po':
            if have_msgid:
                if have_msgstr:
                    errors = validate_substitutions_match(entry.msgid, entry.msgstr, 'msgid', 'msgstr')
                    entry_errors.extend(errors)

                if have_msgid_plural and have_msgstr:
                    n_plurals = 0
                    for index, msgstr in entry.msgstr_plural.items():
                        have_msgstr_plural = msgstr.strip() != ''
                        if have_msgstr_plural:
                            n_plurals += 1
                            errors = validate_substitutions_match(entry.msgid_plural, msgstr, 'msgid_plural', 'msgstr_plural[%s]' % index)
                            entry_errors.extend(errors)
                        else:
                            entry_errors.append('msgstr_plural[%s] is empty' % (index))
                    if n_plural_forms != n_plurals:
                        entry_errors.append('%d plural forms specified, but this entry has %d plurals' % (n_plural_forms, n_plurals))

        if pedantic:
            if have_msgid:
                errors = validate_substitution_syntax(entry.msgid, 'msgid')
                entry_warnings.extend(errors)

            if have_msgid_plural:
                errors = validate_substitution_syntax(entry.msgid_plural, 'msgid_plural')
                entry_warnings.extend(errors)

                errors = validate_substitutions_match(entry.msgid, entry.msgid_plural, 'msgid', 'msgid_plural')
                entry_warnings.extend(errors)

                for index, msgstr in entry.msgstr_plural.items():
                    have_msgstr_plural = msgstr.strip() != ''
                    if have_msgstr_plural:
                        errors = validate_substitution_syntax(msgstr,  'msgstr_plural[%s]' % index)
                        entry_warnings.extend(errors)

            if have_msgstr:
                errors = validate_substitution_syntax(entry.msgstr, 'msgstr')
                entry_warnings.extend(errors)

        if entry_warnings:
            warning_lines.append(entry_seperator)
            warning_lines.append('locations: %s' % (', '.join(["%s:%d" % (x[0], int(x[1])) for x in entry.occurrences])))
            warning_lines.extend(entry_warnings)
            n_warnings += 1

        if entry_errors:
            error_lines.append(entry_seperator)
            error_lines.append('locations: %s' % (', '.join(["%s:%d" % (x[0], int(x[1])) for x in entry.occurrences])))
            error_lines.extend(entry_errors)
            n_errors += 1

    emit_messages()
    return Result(n_entries=n_entries, n_msgids=n_msgids, n_msgstrs=n_msgstrs, n_warnings=n_warnings, n_errors=n_errors)


#----------------------------------------------------------------------
def create_po(pot_file, po_file, mo_file):

    if not os.path.isfile(pot_file):
        print('file does not exist "%s"' % (pot_file), file=sys.stderr)
        return 1
    try:
        po = polib.pofile(pot_file)
    except Exception as e:
        print('Unable to parse file "%s": %s' % (pot_file, e), file=sys.stderr)
        return 1

    # Update the metadata in the po file header
    # It's case insensitive so search the keys in a case insensitive manner
    #
    # We need to update the Plural-Forms otherwise gettext.py will raise the
    # following error:
    #
    # raise ValueError, 'plural forms expression could be dangerous'
    #
    # It is demanding the rhs of plural= only contains the identifer 'n'

    for k in po.metadata:
        if k.lower() == 'plural-forms':
            po.metadata[k] = 'nplurals=2; plural=(n != 1)'
        # the auto-generated PO file should have charset set to UTF-8
        # because we are using UTF-8 prefix and suffix below
        elif k.lower() == 'content-type':
            po.metadata[k] = 'Content-Type: text/plain; charset=UTF-8'


    # Iterate over all msgid's and form a msgstr by prepending
    # the prefix and appending the suffix
    for entry in po:
        if entry.msgid_plural:
            entry.msgstr_plural = {0: prefix + entry.msgid + suffix,
                                   1: prefix + entry.msgid_plural + suffix}
        else:
            entry.msgstr = prefix + entry.msgid + suffix

    # Write out the po and mo files
    po.save(po_file)
    print("Wrote: %s" % (po_file))

    po.save_as_mofile(mo_file)
    print("Wrote: %s" % (mo_file))

    return 0

#----------------------------------------------------------------------

def validate_unicode_edit(msgid, msgstr):
    # Verify the first character is the test prefix
    if msgstr[0] != prefix:
        raise ValueError('First char in translated string "%s" not equal to prefix "%s"' %
                         (msgstr.encode('utf-8'), prefix.encode('utf-8')))

    # Verify the last character is the test suffix
    if msgstr[-1] != suffix:
        raise ValueError('Last char in translated string "%s" not equal to suffix "%s"' %
                         (msgstr.encode('utf-8'), suffix.encode('utf-8')))

    # Verify everything between the first and last character is the
    # original untranslated string
    if msgstr[1:-1] != msgid:
        raise ValueError('Translated string "%s" minus the first & last character is not equal to msgid "%s"' %
                         (msgstr.encode('utf-8'), msgid))

    if verbose:
        msg = 'Success: message string "%s" maps to translated string "%s"' % (msgid, msgstr)
        print(msg.encode('utf-8'))


def test_translations(po_file, lang, domain, locale_dir):
    # The test installs the test message catalog under the xh_ZA
    # (e.g. Zambia Xhosa) language by default. It would be nice to
    # use a dummy language not associated with any real language,
    # but the setlocale function demands the locale be a valid
    # known locale, Zambia Xhosa is a reasonable choice :)
    locale_envs = ('LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG')

    os.environ.update(
        {locale_env: lang for locale_env in locale_envs}
    )

    # Create a gettext translation object specifying our domain as
    # 'ipa' and the locale_dir as 'test_locale' (i.e. where to
    # look for the message catalog). Then use that translation
    # object to obtain the translation functions.

    t = gettext.translation(domain, locale_dir)

    if six.PY2:
        # pylint: disable=no-member
        get_msgstr = t.ugettext
        get_msgstr_plural = t.ungettext
        # pylint: enable=no-member
    else:
        get_msgstr = t.gettext
        get_msgstr_plural = t.ngettext

    return po_file_iterate(po_file, get_msgstr, get_msgstr_plural)

def po_file_iterate(po_file, get_msgstr, get_msgstr_plural):
    try:
        # Iterate over the msgid's
        if not os.path.isfile(po_file):
            print('file does not exist "%s"' % (po_file), file=sys.stderr)
            return 1
        try:
            po = polib.pofile(po_file)
        except Exception as e:
            print('Unable to parse file "%s": %s' % (po_file, e), file=sys.stderr)
            return 1

        n_entries = 0
        n_translations = 0
        n_valid = 0
        n_fail = 0
        for entry in po:
            if entry.msgid_plural:
                msgid = entry.msgid
                msgid_plural = entry.msgid_plural
                msgstr = get_msgstr_plural(msgid, msgid_plural, 1)
                msgstr_plural = get_msgstr_plural(msgid, msgid_plural, 2)

                try:
                    n_translations += 1
                    validate_unicode_edit(msgid, msgstr)
                    n_valid += 1
                except Exception as e:
                    n_fail += 1
                    if print_traceback:
                        traceback.print_exc()
                    print("ERROR: %s" % e, file=sys.stderr)

                try:
                    n_translations += 1
                    validate_unicode_edit(msgid_plural, msgstr_plural)
                    n_valid += 1
                except Exception as e:
                    n_fail += 1
                    if print_traceback:
                        traceback.print_exc()
                    print("ERROR: %s" % e, file=sys.stderr)


            else:
                msgid = entry.msgid
                msgstr = get_msgstr(msgid)

                try:
                    n_translations += 1
                    validate_unicode_edit(msgid, msgstr)
                    n_valid += 1
                except Exception as e:
                    n_fail += 1
                    if print_traceback:
                        traceback.print_exc()
                    print("ERROR: %s" % e, file=sys.stderr)

            n_entries += 1

    except Exception as e:
        if print_traceback:
            traceback.print_exc()
        print("ERROR: %s" % e, file=sys.stderr)
        return 1

    if not n_entries:
        print("ERROR: no translations found in %s" % (po_file), file=sys.stderr)
        return 1

    if n_fail:
        print("ERROR: %d failures out of %d translations" % (n_fail, n_entries), file=sys.stderr)
        return 1

    print("%d translations in %d messages successfully tested" % (n_translations, n_entries))
    return 0

#----------------------------------------------------------------------

usage ='''

%prog --test-gettext
%prog --create-test
%prog --validate-pot [pot_file1, ...]
%prog --validate-po po_file1 [po_file2, ...]
'''

def main():
    global verbose, print_traceback, pedantic, show_strings

    parser = optparse.OptionParser(usage=usage)

    mode_group = optparse.OptionGroup(parser, 'Operational Mode',
                                      'You must select one these modes to run in')

    mode_group.add_option('-g', '--test-gettext', action='store_const', const='test_gettext', dest='mode',
                          help='create the test translation file(s) and exercise them')
    mode_group.add_option('-c', '--create-test', action='store_const', const='create_test', dest='mode',
                          help='create the test translation file(s)')
    mode_group.add_option('-P', '--validate-pot', action='store_const', const='validate_pot', dest='mode',
                          help='validate pot file(s)')
    mode_group.add_option('-p', '--validate-po', action='store_const', const='validate_po', dest='mode',
                          help='validate po file(s)')

    parser.add_option_group(mode_group)
    parser.set_defaults(mode='')

    parser.add_option('-s', '--show-strings', action='store_true', dest='show_strings', default=False,
                      help='show the offending string when an error is detected')
    parser.add_option('--pedantic', action='store_true', dest='pedantic', default=False,
                      help='be aggressive when validating')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=False,
                      help='be informative')
    parser.add_option('--traceback', action='store_true', dest='print_traceback', default=False,
                      help='print the traceback when an exception occurs')

    param_group = optparse.OptionGroup(parser, 'Run Time Parameters',
                                       'These may be used to modify the run time defaults')

    param_group.add_option('--test-lang', action='store', dest='test_lang', default='test',
                           help="test po file uses this as it's basename (default=test)")
    param_group.add_option('--lang', action='store', dest='lang', default='xh_ZA',
                           help='lang used for locale, MUST be a valid lang (default=xh_ZA)')
    param_group.add_option('--domain', action='store', dest='domain', default='ipa',
                           help='translation domain used during test (default=ipa)')
    param_group.add_option('--locale-dir', action='store', dest='locale_dir', default='test_locale',
                           help='locale directory used during test (default=test_locale)')
    param_group.add_option('--pot-file', action='store', dest='pot_file', default='ipa.pot',
                           help='default pot file, used when validating pot file or generating test po and mo files (default=ipa.pot)')

    parser.add_option_group(param_group)

    options, args = parser.parse_args()

    verbose = options.verbose
    print_traceback = options.print_traceback
    pedantic = options.pedantic
    show_strings = options.show_strings

    if not options.mode:
        print('ERROR: no mode specified', file=sys.stderr)
        return 1

    if options.mode in ('validate_pot', 'validate_po'):
        if options.mode == 'validate_pot':
            files = args
            if not files:
                files = [options.pot_file]
            validation_mode = 'pot'
            reference_pot = None
        elif options.mode == 'validate_po':
            files = args
            if not files:
                print('ERROR: no po files specified', file=sys.stderr)
                return 1
            validation_mode = 'po'
            reference_pot = polib.pofile(options.pot_file)
        else:
            print('ERROR: unknown validation mode "%s"' % (options.mode), file=sys.stderr)
            return 1

        total_entries = 0
        total_msgids = 0
        total_msgstrs = 0
        total_warnings = 0
        total_errors = 0

        for f in files:
            result = validate_file(f, validation_mode, reference_pot)
            total_entries += result.n_entries
            total_msgids += result.n_msgids
            total_msgstrs += result.n_msgstrs
            total_warnings += result.n_warnings
            total_errors += result.n_errors
            print("%s: %d entries, %d msgid, %d msgstr, %d warnings %d errors" % \
                (f, result.n_entries, result.n_msgids, result.n_msgstrs, result.n_warnings, result.n_errors))
        if total_errors:
            print(section_seperator)
            print("%d errors in %d files" % (total_errors, len(files)))
            return 1
        else:
            return 0

    elif options.mode in ('create_test', 'test_gettext'):
        po_file = '%s.po' % options.test_lang
        pot_file = options.pot_file

        msg_dir = os.path.join(options.locale_dir, options.lang, 'LC_MESSAGES')
        if not os.path.exists(msg_dir):
            os.makedirs(msg_dir)

        mo_basename = '%s.mo' % options.domain
        mo_file = os.path.join(msg_dir, mo_basename)

        result = create_po(pot_file, po_file, mo_file)
        if result:
            return result

        if options.mode == 'create_test':
            return result

        # The test installs the test message catalog under the xh_ZA
        # (e.g. Zambia Xhosa) language by default. It would be nice to
        # use a dummy language not associated with any real language,
        # but the setlocale function demands the locale be a valid
        # known locale, Zambia Xhosa is a reasonable choice :)

        lang = options.lang

        # Create a gettext translation object specifying our domain as
        # 'ipa' and the locale_dir as 'test_locale' (i.e. where to
        # look for the message catalog). Then use that translation
        # object to obtain the translation functions.

        domain = options.domain
        locale_dir = options.locale_dir

        return test_translations(po_file, lang, domain, locale_dir)

    else:
        print('ERROR: unknown mode "%s"' % (options.mode), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
