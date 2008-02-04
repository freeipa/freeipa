# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
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

import sys
import datetime

from ipa import ipautil

def password_expires_in(datestr):
    """Returns the number of days that password expires in.  Returns a negative number
       if the password is already expired."""
    if (datestr == None) or (datestr == ""):
        return sys.maxint

    expdate = ipautil.parse_generalized_time(datestr)
    if not expdate:
        return sys.maxint

    delta = expdate - datetime.datetime.now(ipautil.GeneralizedTimeZone())
    return delta.days

def password_is_expired(days):
    return days < 0

def password_expires_soon(days):
    return (not password_is_expired(days)) and (days < 7)

def account_status_display(status):
    if status == "true":
        return "inactive"
    else:
        return "active"
