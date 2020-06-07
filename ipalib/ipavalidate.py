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
