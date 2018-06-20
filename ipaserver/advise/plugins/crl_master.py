#
# Copyright (C) 2018 FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipalib import api
from ipalib.plugable import Registry
from ipaplatform import services
from ipaserver.advise.base import Advice

register = Registry()


@register()
class set_crl_master(Advice):
    """
    Set the CRL master among a list of masters
    """

    description = ("Instructions for configuring an IPA master to generate "
                   "the Certificate Revocation List (CRL). "
                   "Only one master may have this responsibilty at a time.")

    shell = '/bin/bash'

    pki_service_name = services.knownservices.pki_tomcatd.systemd_name

    def get_info(self):
        self.set_local_fn()
        self.get_local_fn()
        self.get_remote_fn()
        self.log.exit_on_nonroot_euid()
        self.parse_arguments()
        self.check_ccache_not_empty()
        self.get_principal()
        self.initialize_local_variables()
        self.check_hostname_is_in_masters()
        self.find_ca_masters()
        self.run_validate()
        self.check_target_is_in_ca_masters()
        self.get_local_enableCRLUpdates_setting()
        self.get_remoteenableCRLUpdates_setting()
        self.check_remote_status()
        self.log.exit_on_predicate(
            '[ ! -z "$REMOTE_ENABLED" ] && [ "$REMOTE_ENABLED" == "false" ]'
            ' && [ "$FORCE" -ne 1 ]',
            ['"$REMOTE_HOSTNAME" is not the CRL master']
        )
        self.set_local_enableCRLUpdates_setting()
        self.set_remote_enableCRLUpdates_setting()
        self.check_rollback()

    def initialize_local_variables(self):
        # SKIP_REMOTE is set if the remote is unavailable and --force
        self.log.command('SKIP_REMOTE=0')
        # ROLLBACK indicates a remote failure needs a local rollback
        self.log.command('ROLLBACK=0')
        # Don't assume that the $HOSTNAME passed in is sane
        self.log.command('HOSTNAME=$(hostname -f)')
        self.log.command('\n')
        self.log.command(
            'if [ $SUDO_ENABLED -eq 1 ]; then\n'
            '    SUDO="sudo"\n'
            '    SSH_CMD="/usr/bin/ssh -t ${PRINCIPAL}@"\n'
            '    echo "Authenticating as ${PRINCIPAL}"\n'
            'else\n'
            '    SUDO=""\n'
            '    SSH_CMD="/usr/bin/ssh root@"\n'
            '    echo "Authenticating as root"\n'
            'fi\n'
        )
        self.log.command('\n')

    def parse_arguments(self):
        self.log.exit_on_failed_command(
            'OPTS=$(getopt -o "" --long force,sudo,validate -- "$@")\n'
            'if [ $? != 0 ] ; then exit 1 ; fi\n'
            'eval set -- "$OPTS"\n'
            'FORCE=0\n'
            'SUDO_ENABLED=0\n'
            'VALIDATE=0\n'

            '# Remote hostname is the remote master we are changing\n'
            'while true; do\n'
            '  case "$1" in\n'
            '    --force ) FORCE=1; shift ;;\n'
            '    --sudo )    SUDO_ENABLED=1; shift ;;\n'
            '    --validate ) VALIDATE=1; shift ;;\n'
            '    -- ) shift; break ;;\n'
            '    * ) break ;;\n'
            '  esac\n'
            'done\n'
            'REMOTE_HOSTNAME=$1',
            ['Usage: $0 [--force] [--sudo] [--validate] IPA_master']
        )
        self.log.exit_on_predicate(
            '[ -z "$REMOTE_HOSTNAME" ]',
            ['Usage: $0 [--force] [--sudo] IPA_master',
             '       $0 [--validate]'])

    def check_ccache_not_empty(self):
        self.log.comment('Check whether the credential cache is not empty')
        self.log.exit_on_failed_command(
            'klist > /dev/null 2>&1',
            [
                "Credential cache is empty",
                'Use kinit as privileged user to obtain Kerberos credentials'
            ])

    def get_principal(self):
        self.log.comment('Get the current prinicipal')
        self.log.command(
            'PRINCIPAL=$(klist | grep "Default principal:" | '
            'awk "{ print \$3 }" | sed "s/@%s//")' % api.env.realm
        )

    def check_hostname_is_in_masters(self):
        self.log.comment('Check whether the host is IPA master')
        self.log.exit_on_failed_command(
            'ipa server-find "$(hostname -f)" > /dev/null 2>&1',
            ["This script can be run on IPA master only"])

    def find_ca_masters(self):
        self.log.comment('Find CA masters')
        self.log.command(
            'output=$(ipa server-find --servroles="CA server" 2>&1 '
            '| grep name: | awk "{ print \$3 }")'
        )
        self.log.exit_on_predicate(
            '[ "$?" -ne "0" ]',
            ['Failed to find CA servers'])
        self.log.command('servers=$output')

    def check_target_is_in_ca_masters(self):
        self.log.comment('Ensure provided hostname is an IPA CA master')
        self.log.command(
            'FOUND=0\n'
            'for server in $servers; do\n'
            '    if [ "$REMOTE_HOSTNAME" == "$server" ]; then FOUND=1; fi\n'
            'done\n\n'
        )
        self.log.exit_on_predicate(
            '[ "$FOUND" == "0" ]',
            ['Failed to find $REMOTE_HOSTNAME in list of CA masters'])

    def set_local_fn(self):
        """Function for setting local value"""
        self.log.command(
            '# Arg order: oldvalue, newvalue\n'
            'set_local()\n'
            '{\n'
            '    sed -i "s/'
            '    ca.crl.MasterCRL.enableCRLUpdates=$1/'
            '    ca.crl.MasterCRL.enableCRLUpdates=$2/" '
            '    /etc/pki/pki-tomcat/ca/CS.cfg\n'
        )
        self.log.command(
            '    if [ "$?" -ne "0" ]; then\n'
            '        echo "Failed to change local CRL master" >&2\n'
            '        echo "Restart the CA manually" >&2\n'
            '        exit 1\n'
            '    fi\n'
        )
        self.log.command('}\n')

    def get_local_fn(self):
        self.log.comment('Get local enableCRLUpdates setting')
        self.log.command(
            'get_local()\n'
            '{\n'
            '    LOCAL_ENABLED=$(grep ca.crl.MasterCRL.enableCRLUpdates '
            '    /etc/pki/pki-tomcat/ca/CS.cfg |'
            '    awk -F= \' { print $2 }\')\n',
        )
        self.log.command(
            '    echo Current setting on "${HOSTNAME}": '
            '    "${LOCAL_ENABLED}" >&2')
        self.log.command('}\n')

    def get_remote_fn(self):
        self.log.comment('Retrieve remote enableCRLUpdates setting')
        self.log.command(
            '# Arg order: $REMOTE_HOST\n'
            'get_remote()\n'
            '{\n'
            '    # We need to capture the output so fake a prompt here\n'
            '    if [ ! -z "${SUDO}" ]; then\n'
            '        echo -n "[sudo]: password for $PRINCIPAL: "\n'
            '    fi\n'
            '    REMOTE_ENABLED=\"$(${SSH_CMD}$1 ${SUDO} grep '
            '    ca.crl.MasterCRL.enableCRLUpdates '
            '    /etc/pki/pki-tomcat/ca/CS.cfg 2>/dev/null | '
            '    awk -F= \'{ print $2 }\')\"\n'
            '    echo \n'
        )
        self.log.command(
            '    echo Current setting on $1: ${REMOTE_ENABLED} >&2'
        )
        self.log.command('}\n')

    def run_validate(self):
        self.log.comment('See if we are doing validation only')
        self.log.command(
            'if [ "$VALIDATE" == "1" ]; then\n'
            '    get_local\n'
            '    for server in $servers; do\n'
            '    if [ "$HOSTNAME" != "$server" ]; then\n'
            '        get_remote $server;\n'
            '    fi\n'
            '    done\n'
            '    exit 0\n'
            'fi')

    def get_local_enableCRLUpdates_setting(self):
        self.log.comment('Get local enableCRLUpdates setting')
        self.log.exit_on_failed_command(
            'LOCAL_ENABLED=$(grep ca.crl.MasterCRL.enableCRLUpdates '
            '/etc/pki/pki-tomcat/ca/CS.cfg |'
            'awk -F= \' { print $2 }\')\n',
            ['Failed to get ca.crl.MasterCRL.enableCRLUpdates']
        )
        self.log.command(
            'echo Current setting on "${HOSTNAME}": "${LOCAL_ENABLED}" >&2')
        self.log.exit_on_predicate(
            '[ "${LOCAL_ENABLED}" == "true" -a "${FORCE}" -ne 1 ]',
            ['$HOSTNAME is already the CRL master']
        )
        self.log.command('echo "Force is enabled, continuing"')

    def get_remoteenableCRLUpdates_setting(self):
        self.log.comment('Get remote enableCRLUpdates setting')
        self.log.command('get_remote $REMOTE_HOSTNAME')

    def check_remote_status(self):
        self.log.comment('See if the remote responded')
        self.log.command(
            'if [ -z "$REMOTE_ENABLED" ]; then\n'
            '    echo "Unable to contact \"$REMOTE_HOSTNAME\"" >&2\n'
            '    if [ "$FORCE" -eq 1 ]; then\n'
            '        echo "Continuing anyway" >&2\n'
            '        SKIP_REMOTE=1\n'
            '    else\n'
            '        exit 1\n'
            '    fi\n'
            'fi\n'
        )

    def set_local_enableCRLUpdates_setting(self):
        self.log.comment('Set the local server to true')
        self.stop_dogtag()
        self.log.command('echo Updating value on "$HOSTNAME" to true >&2')
        self.log.command('set_local "false" "true"')
        self.start_dogtag()

    def set_remote_enableCRLUpdates_setting(self):
        self.log.comment('Set the remote server to false')
        self.log.command(
            'if [ "${SKIP_REMOTE}" -eq 0 ]; then\n'
        )
        self.stop_dogtag(remote=True, eol=' \\')

        self.log.command('echo Updating value on "$1" to false >&2')
        self.log.command(
            '${SSH_CMD}${REMOTE_HOSTNAME} ${SUDO} sed -i "s/'
            'ca.crl.MasterCRL.enableCRLUpdates=true/'
            'ca.crl.MasterCRL.enableCRLUpdates=false/" '
            '/etc/pki/pki-tomcat/ca/CS.cfg 2>/dev/null'
        )
        self.log.command(
            'if [ "$?" -ne "0" ]; then\n'
            '    echo "Failed to change remote CRL master" >&2\n'
            '    ROLLBACK=1\n'
            'fi\n'
        )
        self.start_dogtag(remote=True, eol=' \\')
        self.log.command('fi')
        self.log.comment('# end of SKIP_REMOTE')

    def sleep(self, timeout):
        self.log.command('sleep {}'.format(timeout))

    def stop_dogtag(self, remote=False, eol=''):
        if remote:
            self.log.command('echo Stopping dogtag on '
                             '"${REMOTE_HOSTNAME}" >&2')
            self.log.command(
                '${SSH_CMD}${REMOTE_HOSTNAME} ${SUDO} '
                'systemctl stop %s 2>/dev/null\n' % self.pki_service_name
            )
        else:
            self.log.command('echo Stopping dogtag on "${HOSTNAME}" >&2')
            self.log.command(
                'systemctl stop {}\n'.format(self.pki_service_name)
            )
        self.log.command(
            'if [ "$?" -ne "0" ]; {eol}\n'
            'then {eol}\n'
            '    echo "Failed to stop dogtag." >&2; {eol}\n'
            'exit 1; {eol}\n'
            'fi\n'.format(eol=eol)
        )
        self.sleep(3)

    def start_dogtag(self, remote=False, eol='', amp=''):
        if remote:
            self.log.command(
                'if [ ! -z "${SUDO}" ]; then\n'
                '    echo -n "Password: "\n'
                'fi'
            )
            self.log.command('echo Starting dogtag on '
                             '"${REMOTE_HOSTNAME}" >&2')
            self.log.command(
                '${SSH_CMD}${REMOTE_HOSTNAME} ${SUDO} '
                'systemctl stop %s 2>/dev/null\n' % self.pki_service_name
            )
        else:
            self.log.command('echo Starting dogtag on "${HOSTNAME}" >&2')
            self.log.command(
                'systemctl start {} {}'.format(self.pki_service_name, amp)
            )
        self.log.command(
            'if [ "$?" -ne "0" ]; {eol}\n'
            'then {eol}\n'
            '    echo "Failed to start dogtag." >&2; {eol}\n'.format(eol=eol)
        )
        if remote:
            self.log.command(
                '    ROLLBACK=1; {eol}\n'
                'fi {eol}\n'.format(eol=eol)
            )
        else:
            self.log.command(
                '    exit 1; {eol}\n'
                'fi {eol}\n'.format(eol=eol)
            )

        # TODO: actually wait until dogtag is responsive
        self.sleep(10)

    def check_rollback(self):
        self.log.comment('Rollback to previous state if necessary')
        self.log.command('if [ "$ROLLBACK" == "0" ] ; then exit 0; fi')
        self.log.command('echo Rolling back local value >&2')
        self.stop_dogtag()
        self.log.command('set_local "true" "$LOCAL_ENABLED"')
        self.start_dogtag()
