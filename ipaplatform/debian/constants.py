#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

'''
This Debian family platform module exports platform dependant constants.
'''

# Fallback to default path definitions
from __future__ import absolute_import

from ipaplatform.base.constants import BaseConstantsNamespace, User, Group


class DebianConstantsNamespace(BaseConstantsNamespace):
    HTTPD_USER = User("www-data")
    HTTPD_GROUP = Group("www-data")
    NAMED_USER = User("bind")
    NAMED_GROUP = Group("bind")
    NAMED_DATA_DIR = ""
    NAMED_ZONE_COMMENT = "//"
    # ntpd init variable used for daemon options
    NTPD_OPTS_VAR = "NTPD_OPTS"
    # quote used for daemon options
    NTPD_OPTS_QUOTE = "\'"
    ODS_USER = User("opendnssec")
    ODS_GROUP = Group("opendnssec")
    SECURE_NFS_VAR = "NEED_GSSD"

constants = DebianConstantsNamespace()
