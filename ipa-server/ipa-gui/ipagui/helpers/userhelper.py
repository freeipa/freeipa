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
