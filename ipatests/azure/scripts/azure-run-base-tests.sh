#!/bin/bash -eux

# this script is intended to be run within container
#
# distro-specifics
source "${IPA_TESTS_SCRIPTS}/variables.sh"

function collect_logs() {
    if [ "$#" -ne 1 ]; then
        printf "collect_logs: The path to output archive is required\n"
        exit 1
    fi
    local out_file="$1"
    printf "Collecting logs\n"
    journalctl -b --no-pager > systemd_journal.log
    tar --ignore-failed-read -czf "$out_file" \
        --warning=no-failed-read  \
        /var/log/dirsrv \
        "$HTTPD_LOGDIR" \
        /var/log/ipa* \
        /var/log/krb5kdc.log \
        /var/log/pki \
        /var/log/samba \
        "$BIND_DATADIR" \
        systemd_journal.log \
        ||:
}

server_password=Secret123

echo "Installing FreeIPA master for the domain ${IPA_TESTS_DOMAIN} and realm ${IPA_TESTS_REALM}"

case "$IPA_NETWORK_INTERNAL" in
    true )
    AUTO_FORWARDERS='--no-forwarders'
    ;;

    false )
    AUTO_FORWARDERS='--auto-forwarders'
    ;;

    * )
    echo "Unsupported value for IPA_NETWORK_INTERNAL: '$IPA_NETWORK_INTERNAL'"
    exit 1
    ;;
esac

install_result=1
{ ipa-server-install -U \
    --domain "$IPA_TESTS_DOMAIN" \
    --realm "$IPA_TESTS_REALM" \
    -p "$server_password" -a "$server_password" \
    --setup-dns --setup-kra \
    $AUTO_FORWARDERS \
    && install_result=0 ; } || install_result=$?

rm -rf "$IPA_TESTS_LOGSDIR"
mkdir "$IPA_TESTS_LOGSDIR"
pushd "$IPA_TESTS_LOGSDIR"
tests_result=1

if [ "$install_result" -eq 0 ] ; then
    echo "Run IPA tests"
    echo "Installation complete. Performance of individual steps:"
    grep 'service duration:' /var/log/ipaserver-install.log | sed -e 's/DEBUG //g'

    sed -ri "s/mode = production/mode = developer/" /etc/ipa/default.conf
    systemctl restart "$HTTPD_SYSTEMD_NAME"
    # debugging for BIND
    sed -i "s/severity info;/severity debug;/" "$BIND_LOGGING_OPTIONS_CONF"
    cat "$BIND_LOGGING_OPTIONS_CONF"
    systemctl restart "$BIND_SYSTEMD_NAME"

    firewalld_cmd --add-service={freeipa-ldap,freeipa-ldaps,dns}

    echo ${server_password} | kinit admin && ipa ping
    mkdir -p ~/.ipa
    cp -r /etc/ipa/* ~/.ipa/
    echo ${server_password} > ~/.ipa/.dmpw
    echo 'wait_for_dns=5' >> ~/.ipa/default.conf

    ipa-test-config --help
    ipa-test-task --help
    ipa-run-tests --help

    { ipa-run-tests \
        --logging-level=debug \
        --logfile-dir="$IPA_TESTS_LOGSDIR" \
        --verbose \
        -ra \
        --with-xunit \
        $IPA_TESTS_ARGS \
        $IPA_TESTS_TO_IGNORE \
        $IPA_TESTS_TO_RUN && tests_result=0 ; } || \
        tests_result=$?
else
    echo "ipa-server-install failed with code ${install_result}, skip IPA tests"
fi
# let the services gracefully flush their logs
ipactl stop ||:
collect_logs ipaserver_install_logs.tar.gz

echo "Potential Python 3 incompatibilities in the IPA framework:"
grep -n -C5 BytesWarning "$HTTPD_ERRORLOG" || echo "Good, none detected"

echo "State of the directory server instance, httpd databases, PKI CA database:"
ls -laZ \
    /etc/dirsrv/slapd-*/ \
    "${HTTPD_ALIASDIR}/" \
    /var/lib/ \
    /etc/pki/pki-tomcat/alias/ \
  ||:
ls -laZ \
    /var/lib/ipa/certs/ \
    /var/lib/ipa/passwds/ \
    /var/lib/ipa/private/ \
  ||:

echo "Uninstall the server"
ipa-server-install --uninstall -U
# second uninstall to verify that --uninstall without installation works
ipa-server-install --uninstall -U

collect_logs ipaserver_uninstall_logs.tar.gz

if [ "$install_result" -eq 0 ] ; then
    firewalld_cmd --remove-service={freeipa-ldap,freeipa-ldaps,dns}
fi

# Final result depends on the exit code of the ipa-run-tests
test "$tests_result" -eq 0 -a "$install_result" -eq 0
