#!/bin/bash -eu

function install_debuginfo() {
    dnf makecache ||:
    dnf install -y \
        ${IPA_TESTS_REPO_PATH}/dist/rpms_debuginfo/*.rpm \
        gdb

    dnf debuginfo-install -y \
        389-ds-base \
        bind \
        bind-dyndb-ldap \
        certmonger \
        gssproxy \
        httpd \
        krb5-server \
        krb5-workstation \
        samba \
        sssd
}
