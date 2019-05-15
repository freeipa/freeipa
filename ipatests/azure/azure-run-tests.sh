#!/bin/bash -ex
server_realm=EXAMPLE.TEST
server_domain=example.test
server_password=Secret123

# Expand list of tests into -k...  -k... -k... .. sequence
# If remaining string still has { or } characters that shell did not expand, remove them
tests_to_run=$(eval "eval echo -k{$(echo $TESTS_TO_RUN | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')

systemctl --now enable firewalld
ipa-server-install -U --domain ${server_domain} --realm ${server_realm} -p ${server_password} -a ${server_password} --setup-dns --setup-kra --auto-forwarders
sed -ri "s/mode = production/mode = development/" /etc/ipa/default.conf
systemctl restart httpd.service
firewall-cmd --add-service={freeipa-ldap,freeipa-ldaps,dns}


cd /freeipa

echo ${server_password} | kinit admin && ipa ping
cp -r /etc/ipa/* ~/.ipa/
echo ${server_password} > ~/.ipa/.dmpw
echo 'wait_for_dns=5' >> ~/.ipa/default.conf
ipa-test-config --help
ipa-test-task --help
ipa-run-tests --with-xunit -k-{test_integration,test_webui,test_ipapython/test_keyring.py,test_dns_soa} -v ${tests_to_run}
grep -n -C5 BytesWarning /var/log/httpd/error_log
ipa-server-install --uninstall -U
# second uninstall to verify that --uninstall without installation works
ipa-server-install --uninstall -U
firewall-cmd --remove-service={freeipa-ldap,freeipa-ldaps,dns}

mkdir -p /freeipa/logs
cd /freeipa/logs
journalctl -b --no-pager > systemd_journal.log
tar --ignore-failed-read -cvf var_log.tar \
    /var/log/dirsrv \
    /var/log/httpd \
    /var/log/ipa* \
    /var/log/krb5kdc.log \
    /var/log/pki \
    systemd_journal.log

ls -laZ /etc/dirsrv/slapd-*/ /etc/httpd/alias/ /etc/pki/pki-tomcat/alias/ || true

