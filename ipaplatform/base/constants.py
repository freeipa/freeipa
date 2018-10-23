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
    IPA_ADTRUST_PACKAGE_NAME = "freeipa-server-trust-ad"
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
    SELINUX_BOOLEAN_ADTRUST = {
        'samba_portmapper': 'on',
    }
    SELINUX_BOOLEAN_HTTPD = {
        'httpd_can_network_connect': 'on',
        'httpd_manage_ipa': 'on',
        'httpd_run_ipa': 'on',
        'httpd_dbus_sssd': 'on',
    }
    SSSD_USER = "sssd"
    # sql (new format), dbm (old format)
    NSS_DEFAULT_DBTYPE = 'dbm'
    # WSGI module override, only used on Fedora
    MOD_WSGI_PYTHON2 = None
    MOD_WSGI_PYTHON3 = None
    # WSGIDaemonProcess process count. On 64bit platforms, each process
    # consumes about 110 MB RSS, from which are about 35 MB shared.
    WSGI_PROCESSES = 4 if IS_64BITS else 2


constants = BaseConstantsNamespace()
