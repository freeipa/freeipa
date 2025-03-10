#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
This Debian base platform module exports default filesystem paths as common
in Debian-based systems.
"""

# Fallback to default path definitions
from __future__ import absolute_import

from ipaplatform.base.paths import BasePathNamespace
import sysconfig

MULTIARCH = sysconfig.get_config_var('MULTIARCH')

class DebianPathNamespace(BasePathNamespace):
    BIN_HOSTNAMECTL = "/usr/bin/hostnamectl"
    ETC_HTTPD_DIR = "/etc/apache2"
    HTTPD_ALIAS_DIR = "/etc/apache2/ipa"
    HTTPD_CONF_D_DIR = "/etc/apache2/conf-enabled/"
    HTTPD_IPA_KDCPROXY_CONF_SYMLINK = "/etc/apache2/conf-enabled/ipa-kdc-proxy.conf"
    HTTPD_IPA_PKI_PROXY_CONF = "/etc/apache2/conf-enabled/ipa-pki-proxy.conf"
    HTTPD_IPA_REWRITE_CONF = "/etc/apache2/conf-available/ipa-rewrite.conf"
    HTTPD_IPA_CONF = "/etc/apache2/conf-enabled/ipa.conf"
    HTTPD_NSS_CONF = "/etc/apache2/mods-available/nss.conf"
    HTTPD_SSL_CONF = "/etc/apache2/mods-available/ssl.conf"
    HTTPD_SSL_SITE_CONF = "/etc/apache2/sites-available/default-ssl.conf"
    OLD_IPA_KEYTAB = "/etc/apache2/ipa.keytab"
    HTTPD_PASSWORD_CONF = "/etc/apache2/password.conf"
    NAMED_CONF = "/etc/bind/named.conf"
    NAMED_CONF_BAK = "/etc/bind/named.conf.ipa-backup"
    NAMED_CUSTOM_CONF = "/etc/bind/ipa-ext.conf"
    NAMED_CUSTOM_OPTIONS_CONF = "/etc/bind/ipa-options-ext.conf"
    NAMED_LOGGING_OPTIONS_CONF = "/etc/bind/ipa-logging-ext.conf"
    NAMED_VAR_DIR = "/var/cache/bind"
    NAMED_KEYTAB = "/etc/bind/krb5.keytab"
    NAMED_RFC1912_ZONES = "/etc/bind/named.conf.default-zones"
    NAMED_ROOT_KEY = "/etc/bind/bind.keys"
    NAMED_MANAGED_KEYS_DIR = "/var/cache/bind/dynamic"
    CHRONY_CONF = "/etc/chrony/chrony.conf"
    OPENLDAP_LDAP_CONF = "/etc/ldap/ldap.conf"
    OPENSSL_DIR = "/usr/lib/ssl"
    OPENSSL_CERTS_DIR = "/usr/lib/ssl/certs"
    OPENSSL_PRIVATE_DIR = "/usr/lib/ssl/private"
    SAMBA_LOCKDIR = "/run/samba"
    ETC_DEBIAN_VERSION = "/etc/debian_version"
    # Old versions of freeipa wrote all trusted certificates to a single
    # file, which is not supported by ca-certificates.
    CA_CERTIFICATES_BUNDLE_PEM = "/usr/local/share/ca-certificates/ipa-ca.crt"
    CA_CERTIFICATES_DIR = "/usr/local/share/ca-certificates/ipa-ca"
    # Debian's p11-kit does not use ipa.p11-kit, so the file is provided
    # for information only.
    IPA_P11_KIT = "/usr/local/share/ca-certificates/ipa.p11-kit"
    ETC_SYSCONFIG_DIR = "/etc/default"
    SYSCONFIG_AUTOFS = "/etc/default/autofs"
    SYSCONFIG_DIRSRV = "/etc/default/dirsrv"
    SYSCONFIG_DIRSRV_INSTANCE = "/etc/default/dirsrv-%s"
    SYSCONFIG_DIRSRV_SYSTEMD = "/etc/default/dirsrv.systemd"
    SYSCONFIG_IPA_DNSKEYSYNCD = "/etc/default/ipa-dnskeysyncd"
    SYSCONFIG_IPA_ODS_EXPORTER = "/etc/default/ipa-ods-exporter"
    SYSCONFIG_KRB5KDC_DIR = "/etc/default/krb5-kdc"
    SYSCONFIG_NAMED = "/etc/default/named"
    SYSCONFIG_NFS = "/etc/default/nfs-common"
    SYSCONFIG_NTPD = "/etc/default/ntp"
    SYSCONFIG_ODS = "/etc/default/opendnssec"
    SYSCONFIG_PKI = "/etc/dogtag/"
    SYSCONFIG_PKI_TOMCAT = "/etc/default/pki-tomcat"
    SYSCONFIG_PKI_TOMCAT_PKI_TOMCAT_DIR = "/etc/dogtag/tomcat/pki-tomcat"
    BIN_TOMCAT = "/usr/share/tomcat9/bin/version.sh"
    SYSTEMD_SYSTEM_HTTPD_D_DIR = "/etc/systemd/system/apache2.service.d/"
    SYSTEMD_SYSTEM_HTTPD_IPA_CONF = "/etc/systemd/system/apache2.service.d/ipa.conf"
    DNSSEC_TRUSTED_KEY = "/etc/bind/trusted-key.key"
    GSSAPI_SESSION_KEY = "/etc/apache2/ipa/ipasession.key"
    OLD_KRA_AGENT_PEM = "/etc/apache2/nssdb/kra-agent.pem"
    SBIN_SERVICE = "/usr/sbin/service"
    CERTMONGER_COMMAND_TEMPLATE = "/usr/lib/ipa/certmonger/%s"
    ODS_KSMUTIL = None
    UPDATE_CA_TRUST = "/usr/sbin/update-ca-certificates"
    BIND_LDAP_DNS_IPA_WORKDIR = "/var/cache/bind/dyndb-ldap/ipa/"
    BIND_LDAP_DNS_ZONE_WORKDIR = "/var/cache/bind/dyndb-ldap/ipa/master/"
    BIND_LDAP_SO = "/usr/lib/{0}/bind/ldap.so".format(MULTIARCH)
    LIBARCH = "/{0}".format(MULTIARCH)
    LIBSOFTHSM2_SO = "/usr/lib/{0}/softhsm/libsofthsm2.so".format(MULTIARCH)
    PAM_KRB5_SO = "/usr/lib/{0}/security/pam_krb5.so".format(MULTIARCH)
    LIB_SYSTEMD_SYSTEMD_DIR = "/lib/systemd/system/"
    LIBEXEC_CERTMONGER_DIR = "/usr/lib/certmonger"
    DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT = "/usr/lib/certmonger/dogtag-ipa-ca-renew-agent-submit"
    DOGTAG_IPA_RENEW_AGENT_SUBMIT = "/usr/lib/certmonger/dogtag-ipa-renew-agent-submit"
    CERTMONGER_DOGTAG_SUBMIT = "/usr/lib/certmonger/dogtag-submit"
    IPA_SERVER_GUARD = "/usr/lib/certmonger/ipa-server-guard"
    GENERATE_RNDC_KEY = "/bin/true"
    LIBEXEC_IPA_DIR = "/usr/lib/ipa"
    IPA_DNSKEYSYNCD_REPLICA = "/usr/lib/ipa/ipa-dnskeysync-replica"
    IPA_DNSKEYSYNCD = "/usr/lib/ipa/ipa-dnskeysyncd"
    IPA_HTTPD_KDCPROXY = "/usr/lib/ipa/ipa-httpd-kdcproxy"
    IPA_ODS_EXPORTER = "/usr/lib/ipa/ipa-ods-exporter"
    IPA_PKI_RETRIEVE_KEY = "/usr/lib/ipa/ipa-pki-retrieve-key"
    IPA_HTTPD_PASSWD_READER = "/usr/lib/ipa/ipa-httpd-pwdreader"
    IPA_PKI_WAIT_RUNNING = "/usr/lib/ipa/ipa-pki-wait-running"
    HTTPD = "/usr/sbin/apache2ctl"
    FONTS_DIR = "/usr/share/fonts/truetype"
    FONTS_OPENSANS_DIR = "/usr/share/fonts/truetype/open-sans"
    FONTS_FONTAWESOME_DIR = "/usr/share/fonts/truetype/font-awesome"
    VAR_KERBEROS_KRB5KDC_DIR = "/var/lib/krb5kdc/"
    VAR_KRB5KDC_K5_REALM = "/var/lib/krb5kdc/.k5."
    CACERT_PEM = "/var/lib/ipa/certs/cacert.pem"
    KRB5KDC_KADM5_ACL = "/etc/krb5kdc/kadm5.acl"
    KRB5KDC_KADM5_KEYTAB = "/etc/krb5kdc/kadm5.keytab"
    KRB5KDC_KDC_CONF = "/etc/krb5kdc/kdc.conf"
    KDC_CERT = "/var/lib/ipa/certs/kdc.crt"
    KDC_KEY = "/var/lib/ipa/certs/kdc.key"
    VAR_LOG_HTTPD_DIR = "/var/log/apache2"
    VAR_LOG_HTTPD_ERROR = "/var/log/apache2/error.log"
    NAMED_RUN = "/var/cache/bind/named.run"
    VAR_OPENDNSSEC_DIR = "/var/lib/opendnssec"
    OPENDNSSEC_KASP_DB = "/var/lib/opendnssec/db/kasp.db"
    IPA_ODS_EXPORTER_CCACHE = "/var/lib/opendnssec/tmp/ipa-ods-exporter.ccache"
    IPA_CUSTODIA_SOCKET = "/run/apache2/ipa-custodia.sock"
    IPA_CUSTODIA_AUDIT_LOG = '/var/log/ipa-custodia.audit.log'
    IPA_CUSTODIA_HANDLER = "/usr/lib/ipa/custodia"
    IPA_CUSTODIA_CHECK = "/usr/lib/ipa/ipa-custodia-check"
    WSGI_PREFIX_DIR = "/run/apache2/wsgi"

paths = DebianPathNamespace()
