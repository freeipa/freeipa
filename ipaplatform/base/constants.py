#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This base platform module exports platform dependant constants.
'''


class BaseConstantsNamespace(object):
    HTTPD_USER = "apache"
    IPA_DNS_PACKAGE_NAME = "freeipa-server-dns"
    NAMED_USER = "named"
    # ntpd init variable used for daemon options
    NTPD_OPTS_VAR = "OPTIONS"
    # quote used for daemon options
    NTPD_OPTS_QUOTE = "\""
    # nfsd init variable used to enable kerberized NFS
    SECURE_NFS_VAR = "SECURE_NFS"
