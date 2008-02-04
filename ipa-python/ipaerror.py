# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import exceptions
import types

class IPAError(exceptions.Exception):
    """Base error class for IPA Code"""

    def __init__(self, code, message="", detail=None):
        """code is the IPA error code.
           message is a human viewable error message.
           detail is an optional exception that provides more detail about the
           error."""
        self.code = code
        self.message = message
        # Fill this in as an empty LDAP error message so we don't have a lot
        # of "if e.detail ..." everywhere
        if detail is None:
             detail = []
             detail.append({'desc':'','info':''})
        self.detail = detail

    def __str__(self):
        return self.message

    def __repr__(self):
        repr = "%d: %s" % (self.code, self.message)
        if self.detail:
            repr += "\n%s" % str(self.detail)
        return repr


###############
# Error codes #
###############

code_map_dict = {}

def gen_exception(code, message=None, nested_exception=None):
    """This should be used by IPA code to translate error codes into the
       correct exception/message to throw.

       message is an optional argument which overrides the default message.

       nested_exception is an optional argument providing more details
       about the error."""
    (default_message, exception) = code_map_dict.get(code, ("unknown", IPAError))
    if not message:
        message = default_message
    return exception(code, message, nested_exception)

def exception_for(code):
    """Used to look up the corresponding exception for an error code.
       Will usually be used for an except block."""
    (default_message, exception) = code_map_dict.get(code, ("unknown", IPAError))
    return exception

def gen_error_code(category, detail, message):
    """Private method used to generate exception codes.
       category is one of the 16 bit error code category constants.
       detail is a 16 bit code within the category.
       message is a human readable description on the error.
       exception is the exception to throw for this error code."""
    code = (category << 16) + detail
    exception = types.ClassType("IPAError%d" % code,
                      (IPAError,),
                      {})
    code_map_dict[code] = (message, exception)

    return code

#
# Error codes are broken into two 16-bit values: category and detail
#

#
# LDAP Errors:   0x0001
#
LDAP_CATEGORY = 0x0001

LDAP_DATABASE_ERROR = gen_error_code(
        LDAP_CATEGORY,
        0x0001,
        "A database error occurred")

LDAP_MIDAIR_COLLISION = gen_error_code(
        LDAP_CATEGORY,
        0x0002,
        "Change collided with another change")

LDAP_NOT_FOUND = gen_error_code(
        LDAP_CATEGORY,
        0x0003,
        "Entry not found")

LDAP_DUPLICATE = gen_error_code(
        LDAP_CATEGORY,
        0x0004,
        "This entry already exists")

LDAP_MISSING_DN = gen_error_code(
        LDAP_CATEGORY,
        0x0005,
        "Entry missing dn")

LDAP_EMPTY_MODLIST = gen_error_code(
        LDAP_CATEGORY,
        0x0006,
        "No modifications to be performed")

LDAP_NO_CONFIG = gen_error_code(
        LDAP_CATEGORY,
        0x0007,
        "IPA configuration not found")

#
# Function input errors
#
INPUT_CATEGORY = 0x0002

INPUT_INVALID_PARAMETER = gen_error_code(
        INPUT_CATEGORY,
        0x0001,
        "Invalid parameter(s)")

#
# Connection errors
#
CONNECTION_CATEGORY = 0x0003

CONNECTION_NO_CONN = gen_error_code(
        CONNECTION_CATEGORY,
        0x0001,
        "Connection to database failed")

CONNECTION_NO_CCACHE = gen_error_code(
        CONNECTION_CATEGORY,
        0x0002,
        "No Kerberos credentials cache is available. Connection cannot be made.")

CONNECTION_GSSAPI_CREDENTIALS = gen_error_code(
        CONNECTION_CATEGORY,
        0x0003,
        "GSSAPI Authorization error")

CONNECTION_UNWILLING = gen_error_code(
        CONNECTION_CATEGORY,
        0x0004,
        "Account inactivated. Server is unwilling to perform.")

#
# Configuration errors
#
CONFIGURATION_CATEGORY = 0x0004

CONFIG_REQUIRED_GROUPS = gen_error_code(
        CONFIGURATION_CATEGORY,
        0x0001,
        "The admins and editors groups are required.")

CONFIG_DEFAULT_GROUP = gen_error_code(
        CONFIGURATION_CATEGORY,
        0x0002,
        "You cannot remove the default users group.")

CONFIG_INVALID_OC = gen_error_code(
        CONFIGURATION_CATEGORY,
        0x0003,
        "Invalid object class.")
