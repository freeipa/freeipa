#!/bin/bash -ex
server_realm=EXAMPLE.TEST
server_domain=example.test
server_password=Secret123

# Normalize spacing and expand the list afterwards. Remove {} for the single list element case
tests_to_run=$(eval "echo {$(echo $TESTS_TO_RUN | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')
tests_to_ignore=$(eval "echo --ignore\ {$(echo $TESTS_TO_IGNORE | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')
tests_to_dedicate=
[[ -n "$TESTS_TO_DEDICATE" ]] && \
tests_to_dedicate=$(eval "echo --slice-dedicated={$(echo $TESTS_TO_DEDICATE | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')

systemctl --now enable firewalld
echo "Installing FreeIPA master for the domain ${server_domain} and realm ${server_realm}"
ipa-server-install -U --domain ${server_domain} --realm ${server_realm} \
                   -p ${server_password} -a ${server_password} \
                   --setup-dns --setup-kra --auto-forwarders

install_result=$?

tests_result=1

mkdir -p /freeipa/$CI_RUNNER_LOGS_DIR
cd /freeipa/$CI_RUNNER_LOGS_DIR

if [ "$install_result" -eq 0 ] ; then
	echo "Run IPA tests"
	echo "Installation complete. Performance of individual steps:"
	grep 'service duration:' /var/log/ipaserver-install.log | sed -e 's/DEBUG //g'

	sed -ri "s/mode = production/mode = development/" /etc/ipa/default.conf
	systemctl restart httpd.service
	firewall-cmd --add-service={freeipa-ldap,freeipa-ldaps,dns}

	echo ${server_password} | kinit admin && ipa ping
	mkdir -p ~/.ipa
	cp -r /etc/ipa/* ~/.ipa/
	echo ${server_password} > ~/.ipa/.dmpw
	echo 'wait_for_dns=5' >> ~/.ipa/default.conf

	ipa-test-config --help
	ipa-test-task --help
	ipa-run-tests --help

	ipa-run-tests ${tests_to_ignore} \
            ${tests_to_dedicate} \
            --slices=${SYSTEM_TOTALJOBSINPHASE:-1} \
            --slice-num=${SYSTEM_JOBPOSITIONINPHASE:-1} \
            --verbose --with-xunit '-k not test_dns_soa' ${tests_to_run}
	tests_result=$?
else
	echo "ipa-server-install failed with code ${save_result}, skip IPA tests"
fi

echo "Potential Python 3 incompatibilities in the IPA framework:"
grep -n -C5 BytesWarning /var/log/httpd/error_log || echo "Good, none detected"

echo "State of the directory server instance, httpd databases, PKI CA database:"
ls -laZ /etc/dirsrv/slapd-*/ /etc/httpd/alias/ /var/lib/ /etc/pki/pki-tomcat/alias/ || true
ls -laZ /var/lib/ipa/certs/ /var/lib/ipa/passwds/ /var/lib/ipa/private/ || true

echo "Uninstall the server"
ipa-server-install --uninstall -U
# second uninstall to verify that --uninstall without installation works
ipa-server-install --uninstall -U


if [ "$install_result" -eq 0 ] ; then
	firewall-cmd --remove-service={freeipa-ldap,freeipa-ldaps,dns}
fi

echo "Collect the logs"
journalctl -b --no-pager > systemd_journal.log
tar --ignore-failed-read -cvf var_log.tar \
    /var/log/dirsrv \
    /var/log/httpd \
    /var/log/ipa* \
    /var/log/krb5kdc.log \
    /var/log/pki \
    /var/log/samba \
    /var/named/data \
    systemd_journal.log

# Final result depends on the exit code of the ipa-run-tests
test "$tests_result" -eq 0 -a "$install_result" -eq 0
