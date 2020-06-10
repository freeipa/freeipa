#
# Copyright (C) 2020 FreeIPA Contributors, see COPYING for license
#

"""
This SUSE OS family base platform module exports default filesystem paths as
common in SUSE OS family-based systems.
"""

from ipaplatform.base.paths import BasePathNamespace


class SusePathNamespace(BasePathNamespace):
    BIN_HOSTNAMECTL = "/usr/bin/hostnamectl"
    SYSTEMCTL = "/usr/bin/systemctl"
    ETC_HTTPD_DIR = "/etc/apache2"
    HTTPD_ALIAS_DIR = "/etc/apache2/ipa"
    GSSAPI_SESSION_KEY = "/etc/apache2/ipa/ipasession.key"
    HTTPD_CONF_D_DIR = "/etc/apache2/conf.d/"
    HTTPD_IPA_KDCPROXY_CONF_SYMLINK = "/etc/apache2/conf.d/ipa-kdc-proxy.conf"
    HTTPD_IPA_PKI_PROXY_CONF = "/etc/apache2/conf.d/ipa-pki-proxy.conf"
    HTTPD_IPA_REWRITE_CONF = "/etc/apache2/conf.d/ipa-rewrite.conf"
    HTTPD_IPA_CONF = "/etc/apache2/conf.d/ipa.conf"
    HTTPD_NSS_CONF = "/etc/apache2/conf.d/nss.conf"
    HTTPD_SSL_CONF = "/etc/apache2/conf.d/ssl.conf"
    HTTPD_SSL_SITE_CONF = "/etc/apache2/conf.d/ssl.conf"
    HTTPD_PASSWORD_CONF = "/etc/apache2/ipa/password.conf"
    NAMED_CUSTOM_CONF = "/etc/named.d/ipa-ext.conf"
    NAMED_CUSTOM_OPTIONS_CONF = "/etc/named.d/ipa-options-ext.conf"
    NAMED_VAR_DIR = "/var/lib/named"
    NAMED_MANAGED_KEYS_DIR = "/var/lib/named/dyn"
    IPA_P11_KIT = "/etc/pki/trust/ipa.p11-kit"
    # Those files are only here to be able to configure them, we copy those in
    # rpm spec to fillupdir
    SYSCONFIG_HTTPD = "/etc/sysconfig/apache2"
    SYSCONFIG_NAMED = "/etc/sysconfig/named-named"
    SYSCONFIG_NTPD = "/etc/sysconfig/ntp"
    SYSCONF_NETWORK = "/etc/sysconfig/network/config"
    SYSTEMD_SYSTEM_HTTPD_D_DIR = "/etc/systemd/system/apache2.service.d/"
    SYSTEMD_SYSTEM_HTTPD_IPA_CONF = (
        "/etc/systemd/system/apache2.service.d/ipa.conf"
    )
    CERTMONGER_COMMAND_TEMPLATE = "/usr/lib/ipa/certmonger/%s"
    CHROMIUM_BROWSER = "/usr/bin/chromium"
    BIN_NISDOMAINNAME = "/bin/nisdomainname"
    BIND_LDAP_DNS_IPA_WORKDIR = "/var/lib/named/dyndb-ldap/ipa/"
    BIND_LDAP_DNS_ZONE_WORKDIR = "/var/lib/named/dyndb-ldap/ipa/master/"
    PAM_KRB5_SO = "/lib/security/pam_krb5.so"
    PAM_KRB5_SO_64 = PAM_KRB5_SO
    # openSUSE still uses lib for libexec, this will change when we don't
    # anymore
    LIBEXEC_CERTMONGER_DIR = "/usr/lib/certmonger"
    DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT = (
        "/usr/lib/certmonger/dogtag-ipa-ca-renew-agent-submit"
    )
    DOGTAG_IPA_RENEW_AGENT_SUBMIT = (
        "/usr/lib/certmonger/dogtag-ipa-renew-agent-submit"
    )
    CERTMONGER_DOGTAG_SUBMIT = "/usr/lib/certmonger/dogtag-submit"
    IPA_SERVER_GUARD = "/usr/lib/certmonger/ipa-server-guard"
    GENERATE_RNDC_KEY = "/usr/lib/generate-rndc-key.sh"
    LIBEXEC_IPA_DIR = "/usr/lib/ipa"
    IPA_DNSKEYSYNCD_REPLICA = "/usr/lib/ipa/ipa-dnskeysync-replica"
    IPA_DNSKEYSYNCD = "/usr/lib/ipa/ipa-dnskeysyncd"
    IPA_HTTPD_KDCPROXY = "/usr/lib/ipa/ipa-httpd-kdcproxy"
    IPA_ODS_EXPORTER = "/usr/lib/ipa/ipa-ods-exporter"
    IPA_PKI_RETRIEVE_KEY = "/usr/lib/ipa/ipa-pki-retrieve-key"
    IPA_HTTPD_PASSWD_READER = "/usr/lib/ipa/ipa-httpd-pwdreader"
    IPA_PKI_WAIT_RUNNING = "/usr/lib/ipa/ipa-pki-wait-running"
    DNSSEC_KEYFROMLABEL = "/usr/sbin/dnssec-keyfromlabel-pkcs11"
    VAR_KERBEROS_KRB5KDC_DIR = "/var/lib/kerberos/krb5kdc/"
    VAR_KRB5KDC_K5_REALM = "/var/lib/kerberos/krb5kdc/.k5."
    CACERT_PEM = "/var/lib/kerberos/krb5kdc/cacert.pem"
    KRB5KDC_KADM5_ACL = "/var/lib/kerberos/krb5kdc/kadm5.acl"
    KRB5KDC_KADM5_KEYTAB = "/var/lib/kerberos/krb5kdc/kadm5.keytab"
    KRB5KDC_KDC_CONF = "/var/lib/kerberos/krb5kdc/kdc.conf"
    KDC_CERT = "/var/lib/kerberos/krb5kdc/kdc.crt"
    KDC_KEY = "/var/lib/kerberos/krb5kdc/kdc.key"
    NAMED_RUN = "/var/lib/named/data/named.run"
    IPA_CUSTODIA_HANDLER = "/usr/lib/ipa/custodia"
    WSGI_PREFIX_DIR = "/run/apache2/wsgi"
    KDESTROY = "/usr/lib/mit/bin/kdestroy"
    BIN_KVNO = "/usr/lib/mit/bin/kvno"
    UPDATE_CA_TRUST = "/usr/sbin/update-ca-certificates"
    AUTHSELECT = "/usr/bin/authselect"


paths = SusePathNamespace()
