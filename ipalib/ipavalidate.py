# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2007  Red Hat
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

import re

from ipalib.text import _


class Validator:
    def __init__(self):
        pass

    def validate(self, value):
        pass


class NumberValidator(Validator):
    pass


class DataValidator(Validator):
    pass


class StrValidator(DataValidator):
    pass


class MinMaxValidator(NumberValidator):
    def __init__(self, min_value=None, max_value=None):
        super().__init__()
        self.min_value = min_value
        self.max_value = max_value

    def validate(self, value):
        if self.min_value and value < self.min_value:
            raise ValueError(
                _('must be at least %(minvalue)d') % dict(
                    minvalue=self.min_value))

        if self.max_value and value > self.max_value:
            raise ValueError(
                _('can be at most %(maxvalue)d') % dict(
                    maxvalue=self.max_value))


class PatternValidator(DataValidator):
    def __init__(self, pattern, re_errmsg=""):
        super().__init__()
        self.pattern = pattern
        self.re = re.compile(pattern)
        self.re_errmsg = re_errmsg

    def validate(self, value):
        if self.re.match(value) is None:
            if self.re_errmsg:
                raise ValueError(self.re_errmsg % dict(pattern=self.pattern))
            else:
                raise ValueError(_('must match pattern "%(pattern)s"') % dict(
                    pattern=self.pattern))


class EmailValidator(StrValidator):
    def validate(self, value):
        usernameRE = re.compile(r"^[^ \t\n\r@<>()]+$", re.I)
        domainRE = re.compile(r"^[a-z0-9][a-z0-9\.\-_]*\.[a-z]+$", re.I)

        value = value.strip()
        s = value.split('@', 1)
        try:
            username, domain = s
        except ValueError:
            raise ValueError((
                'invalid e-mail format: %(email)s') % dict(email=value))
        if not usernameRE.search(username):
            raise ValueError((
                'invalid e-mail format: %(email)s') % dict(email=value))
        if not domainRE.search(domain):
            raise ValueError((
                'invalid e-mail format: %(email)s') % dict(email=value))

        return None


def Email(mail, notEmpty=True):
    """Do some basic validation of an e-mail address.
       Return True if ok
       Return False if not

       If notEmpty is True the this will return an error if the field
       is "" or None.
    """
    usernameRE = re.compile(r"^[^ \t\n\r@<>()]+$", re.I)
    domainRE = re.compile(r"^[a-z0-9][a-z0-9\.\-_]*\.[a-z]+$", re.I)

    if not mail or mail is None:
        if  notEmpty is True:
            return False
        else:
            return True

    mail = mail.strip()
    s = mail.split('@', 1)
    try:
        username, domain=s
    except ValueError:
        return False
    if not usernameRE.search(username):
        return False
    if not domainRE.search(domain):
        return False

    return True

def Plain(text, notEmpty=False, allowSpaces=True):
    """Do some basic validation of a plain text field
       Return True if ok
       Return False if not

       If notEmpty is True the this will return an error if the field
       is "" or None.
    """
    if (text is None) or (not text.strip()):
        if notEmpty is True:
            return False
        else:
            return True

    if allowSpaces:
        textRE = re.compile(r"^[a-zA-Z_\-0-9\'\ ]*$")
    else:
        textRE = re.compile(r"^[a-zA-Z_\-0-9\']*$")
    if not textRE.search(text):
        return False

    return True

def String(text, notEmpty=False):
    """A string type. This is much looser in what it allows than plain"""

    if text is None or not text.strip():
        if notEmpty is True:
            return False
        else:
            return True

    return True

def Path(text, notEmpty=False):
    """Do some basic validation of a path
       Return True if ok
       Return False if not

       If notEmpty is True the this will return an error if the field
       is "" or None.
    """
    textRE = re.compile(r"^[a-zA-Z_\-0-9\\ \.\/\\:]*$")

    if not text and notEmpty is True:
        return False

    if text is None:
        if notEmpty is True:
            return False
        else:
            return True

    if not textRE.search(text):
        return False

    return True

def GoodName(text, notEmpty=False):
    """From shadow-utils:

       User/group names must match gnu e-regex:
       [a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,30}[a-zA-Z0-9_.$-]?

       as a non-POSIX, extension, allow "$" as the last char for
       sake of Samba 3.x "add machine script"

       Return True if ok
       Return False if not
    """
    textRE = re.compile(r"^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,30}[a-zA-Z0-9_.$-]?$")

    if not text and notEmpty is True:
        return False

    if text is None:
        if notEmpty is True:
            return False
        else:
            return True

    m = textRE.match(text)
    if not m or text != m.group(0):
        return False

    return True
