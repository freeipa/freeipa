# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import re

def Email(mail, notEmpty=True):
    """Do some basic validation of an e-mail address.
       Return 0 if ok
       Return 1 if not

       If notEmpty is True the this will return an error if the field
       is "" or None.
    """
    usernameRE = re.compile(r"^[^ \t\n\r@<>()]+$", re.I)
    domainRE = re.compile(r"^[a-z0-9][a-z0-9\.\-_]*\.[a-z]+$", re.I)

    if not mail or mail is None:
        if  notEmpty is True:
            return 1
        else:
            return 0

    mail = mail.strip()
    s = mail.split('@', 1)
    try:
        username, domain=s
    except ValueError:
        return 1
    if not usernameRE.search(username):
        return 1
    if not domainRE.search(domain):
        return 1

    return 0

def Plain(text, notEmpty=False, allowSpaces=True):
    """Do some basic validation of a plain text field
       Return 0 if ok
       Return 1 if not

       If notEmpty is True the this will return an error if the field
       is "" or None.
    """
    if (text is None) or (not text.strip()):
        if notEmpty is True:
            return 1
        else:
            return 0

    if allowSpaces:
        textRE = re.compile(r"^[a-zA-Z_\-0-9\'\ ]*$")
    else:
        textRE = re.compile(r"^[a-zA-Z_\-0-9\']*$")
    if not textRE.search(text):
        return 1

    return 0

def String(text, notEmpty=False):
    """A string type. This is much looser in what it allows than plain"""

    if text is None or not text.strip():
        if notEmpty is True:
            return 1
        else:
            return 0

    return 0

def Path(text, notEmpty=False):
    """Do some basic validation of a path
       Return 0 if ok
       Return 1 if not

       If notEmpty is True the this will return an error if the field
       is "" or None.
    """
    textRE = re.compile(r"^[a-zA-Z_\-0-9\\ \.\/\\:]*$")

    if not text and notEmpty is True:
        return 1

    if text is None:
        if notEmpty is True:
            return 1
        else:
            return 0

    if not textRE.search(text):
        return 1

    return 0

