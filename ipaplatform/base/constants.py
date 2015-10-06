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
