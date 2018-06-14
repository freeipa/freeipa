#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This base platform module exports platform dependant constants.
'''
import sys


class BaseConstantsNamespace(object):
    IS_64BITS = sys.maxsize > 2 ** 32
    DS_USER = 'dirsrv'
    DS_GROUP = 'dirsrv'
    HTTPD_USER = "apache"
    HTTPD_GROUP = "apache"
    GSSPROXY_USER = "root"
    IPA_DNS_PACKAGE_NAME = "freeipa-server-dns"
    KDCPROXY_USER = "kdcproxy"
    NAMED_USER = "named"
    NAMED_GROUP = "named"
    PKI_USER = 'pkiuser'
    PKI_GROUP = 'pkiuser'
    # ntpd init variable used for daemon options
    NTPD_OPTS_VAR = "OPTIONS"
    # quote used for daemon options
    NTPD_OPTS_QUOTE = "\""
    ODS_USER = "ods"
    ODS_GROUP = "ods"
    # nfsd init variable used to enable kerberized NFS
    SECURE_NFS_VAR = "SECURE_NFS"
    SSSD_USER = "sssd"
    # WSGIDaemonProcess process count. On 64bit platforms, each process
    # consumes about 110 MB RSS, from which are about 35 MB shared.
    WSGI_PROCESSES = 5 if IS_64BITS else 2
