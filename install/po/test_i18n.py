#!/usr/bin/python
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

import sys
import gettext
import locale
import re

def get_msgid(po_file):
    'Get the first non-empty msgid from the po file'
    msgid_re = re.compile(r'^\s*msgid\s+"(.+)"\s*$')
    f = open(po_file)
    for line in f.readlines():
        match = msgid_re.search(line)
        if match:
            msgid = match.group(1)
            f.close()
            return msgid
    f.close()
    raise ValueError('No msgid found in %s' % po_file)

# We test our translations by taking the original untranslated string
# (e.g. msgid) and prepend a prefix character and then append a suffix
# character. The test consists of asserting that the first character in the
# translated string is the prefix, the last character in the translated string
# is the suffix and the everything between the first and last character exactly
# matches the original msgid.
#
# We use unicode characters not in the ascii character set for the prefix and
# suffix to enhance the test. To make reading the translated string easier the
# prefix is the unicode right pointing arrow and the suffix left pointing arrow,
# thus the translated string looks like the original string enclosed in
# arrows. In ASCII art the string "foo" would render as:
# -->foo<--

# Unicode right pointing arrow
prefix = u'\u2192'               # utf-8 == '\xe2\x86\x92'
# Unicode left pointing arrow
suffix = u'\u2190'               # utf-8 == '\xe2\x86\x90'

def main():

    test_file = 'test.po'

    try:

        # The test installs the test message catalog under the en_US (e.g. U.S. English)
        # language. It would be nice to use a dummy language not associated with any
        # real language, but the setlocale function demands the locale be a valid known
        # locale, U.S. English is a reasonable choice.
        locale.setlocale(locale.LC_MESSAGES, 'en_US.UTF-8')

        # Tell gettext that our domain is 'ipa', that locale_dir is 'test_locale'
        # (i.e. where to look for the message catalog) and that we want the translations
        # returned as unicode from the _() function
        gettext.install('ipa', 'test_locale', unicode=1)

        # We need a translatable string to test with, read one from the test po file
        msgid = get_msgid(test_file)

        print "Using message string \"%s\" found in file \"%s\"" % (msgid, test_file)

        # Get the translated version of the msgid string by invoking _()
        translated = _(msgid)

        # Verify the first character is the test prefix
        if translated[0] != prefix:
            raise ValueError("First char in translated string \"%s\" not equal to prefix \"%s\"" % \
                                 (translated.encode('utf-8'), prefix.encode('utf-8')))

        # Verify the last character is the test suffix
        if translated[-1] != suffix:
            raise ValueError("Last char in translated string \"%s\" not equal to suffix \"%s\"" % \
                                 (translated.encode('utf-8'), suffix.encode('utf-8')))

        # Verify everything between the first and last character is the
        # original untranslated string
        if translated[1:-1] != msgid:
            raise ValueError("Translated string \"%s\" minus the first & last character is not equal to msgid \"%s\"" % \
                                 (translated.encode('utf-8'), msgid))

        print "Success: message string \"%s\" maps to translated string \"%s\"" % (msgid, _(msgid).encode('utf-8'))
    except Exception, e:
        print >> sys.stderr, "ERROR: %s" % e
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
