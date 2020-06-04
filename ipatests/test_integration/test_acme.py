#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import time

import pytest

from ipalib.constants import IPA_CA_RECORD
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.osinfo import osinfo


# RHEL does not have certbot.  EPEL's version is broken with
# python-cryptography-2.3; likewise recent PyPI releases.
# So for now, on RHEL we suppress tests that use certbot.
skip_certbot_tests = osinfo.id not in ['fedora',]


class TestACME(IntegrationTest):
    """
    Test the FreeIPA ACME service by using ACME clients on a FreeIPA client.

    Right now the only thing we test is the Certbot client using
    http-01 challenge with Certbot's standalone HTTP server.
    We can add tests for DNS challenges later.

    """

    num_replicas = 0
    num_clients = 1

    @classmethod
    def install(cls, mh):
        # cache the acme service uri
        acme_host = f'{IPA_CA_RECORD}.{cls.master.domain.name}'
        cls.acme_server = f'https://{acme_host}/acme/directory'

        # install packages before client install in case of IPA DNS problems
        if not skip_certbot_tests:
            cls.clients[0].run_command(['dnf', 'install', '-y', 'certbot'])
        cls.clients[0].run_command(['dnf', 'install', '-y', 'mod_md'])

        tasks.install_master(cls.master, setup_dns=True)

        tasks.install_client(cls.master, cls.clients[0])
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.clients[0]
        )

    #####################
    # Enable ACME service
    #####################

    def test_acme_service_not_yet_enabled(self):
        # --fail makes curl exit code 22 when response status >= 400.
        # ACME service should return 503 because it was not enabled yet.
        self.clients[0].run_command(
            ['curl', '--fail', self.acme_server],
            ok_returncode=22,
        )

    def test_enable_acme_service(self):
        self.master.run_command(['ipa-acme-manage', 'enable'])

        # wait a short time for Dogtag ACME service to observe config
        # change and reconfigure itself to service requests
        exc = None
        for _i in range(5):
            time.sleep(2)
            try:
                self.clients[0].run_command(
                    ['curl', '--fail', self.acme_server])
                break
            except Exception as e:
                exc = e
        else:
            raise exc

    ###############
    # Certbot tests
    ###############

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_certbot_register(self):
        # service is enabled; registration should succeed
        self.clients[0].run_command(
            [
                'certbot',
                '--server', self.acme_server,
                'register',
                '-m', 'nobody@example.test',
                '--agree-tos',
                '--no-eff-email',
            ],
        )

    @pytest.mark.skipif(skip_certbot_tests, reason='certbot not available')
    def test_certbot_certonly_standalone(self):
        # Get a cert from ACME service using HTTP challenge and Certbot's
        # standalone HTTP server mode
        self.clients[0].run_command(
            [
                'certbot',
                '--server', self.acme_server,
                'certonly',
                '--domain', self.clients[0].hostname,
                '--standalone',
            ],
        )

    ##############
    # mod_md tests
    ##############

    # TODO!

    ######################
    # Disable ACME service
    ######################

    def test_disable_acme_service(self):
        """
        Disable ACME service again, and observe that it no longer services
        requests.

        """
        self.master.run_command(['ipa-acme-manage', 'disable'])

        # wait a short time for Dogtag ACME service to observe config
        # change and reconfigure itself to no longer service requests
        time.sleep(3)

        # should fail now
        self.clients[0].run_command(
            ['curl', '--fail', self.acme_server],
            ok_returncode=22,
        )
