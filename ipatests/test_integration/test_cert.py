#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various certificate
related scenarios.
"""
from __future__ import absolute_import

import pytest
import re

from ipaplatform.paths import paths

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

DEFAULT_RA_AGENT_SUBMITTED_VAL = '19700101000000'


def get_certmonger_fs_id(input_str):
    """Get certmonger FS ID
    from the `getcert list -f /var/lib/ipa/ra-agent.pem` output
    command output

    :return request ID string
    """
    request_id = re.findall(r'\d+', input_str)
    return request_id[1]


def get_certmonger_request_value(host, requestid, state):
    """Get certmonger submitted value from
    /var/lib/certmonger/requests/<timestamp>

    :return submitted timestamp value
    """
    result = host.run_command(
        ['grep', '-rl', 'id={0}'.format(requestid),
         paths.CERTMONGER_REQUESTS_DIR]
    )
    assert result.stdout_text is not None
    filename = result.stdout_text.strip()
    request_file = host.get_file_contents(filename, encoding='utf-8')
    val = None
    for line in request_file.split('\n'):
        if line.startswith('%s=' % state):
            _unused, val = line.partition("=")[::2]
            break
    return val


class TestCertmongerInterruption(IntegrationTest):
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_replica(cls.master, cls.replicas[0])

    def test_certmomger_tracks_renewed_certs_during_interruptions(self):
        """Test that CA renewal handles early CA_WORKING and restarts

        A non-renewal master CA might submit a renewal request before
        the renewal master actually updating the certs. This is expected.
        The tracking request will result in CA_WORKING.

        This would trigger a different path within the IPA renewal
        scripts which differentiate between a SUBMIT (new request) and
        a POLL (resume request). The script was requiring a cookie
        value for POLL requests which wasn't available and was
        erroring out unrecoverably without restarting certmonger.

        Submit a request for renewal early and wait for it to go into
        CA_WORKING. Resubmit the request to ensure that the request
        remains in CA_WORKING without reporting any ca_error like
        Invalid cookie: ''

        Use the submitted value in the certmonger request to validate
        that the request was resubmitted and not rely on catching
        the states directly.

        Pagure Issue: https://pagure.io/freeipa/issue/8164
        """
        cmd = ['getcert', 'list', '-f', paths.RA_AGENT_PEM]
        result = self.replicas[0].run_command(cmd)

        # Get Request ID and Submitted Values
        request_id = get_certmonger_fs_id(result.stdout_text)
        start_val = get_certmonger_request_value(self.replicas[0],
                                                 request_id, "submitted")

        # at this point submitted value for RA agent cert should be
        # 19700101000000 since it has never been submitted for renewal.
        assert start_val == DEFAULT_RA_AGENT_SUBMITTED_VAL

        cmd = ['getcert', 'resubmit', '-f', paths.RA_AGENT_PEM]
        self.replicas[0].run_command(cmd)

        tasks.wait_for_certmonger_status(self.replicas[0],
                                         ('CA_WORKING', 'MONITORING'),
                                         request_id)

        resubmit_val = get_certmonger_request_value(self.replicas[0],
                                                    request_id,
                                                    "submitted")

        if resubmit_val == DEFAULT_RA_AGENT_SUBMITTED_VAL:
            pytest.fail("Request was not resubmitted")

        ca_error = get_certmonger_request_value(self.replicas[0],
                                                request_id, "ca_error")
        state = get_certmonger_request_value(self.replicas[0],
                                             request_id, "state")

        assert ca_error is None
        assert state == 'CA_WORKING'

        cmd = ['getcert', 'resubmit', '-f', paths.RA_AGENT_PEM]
        self.replicas[0].run_command(cmd)

        tasks.wait_for_certmonger_status(self.replicas[0],
                                         ('CA_WORKING', 'MONITORING'),
                                         request_id)

        resubmit2_val = get_certmonger_request_value(self.replicas[0],
                                                     request_id,
                                                     "submitted")

        if resubmit_val == DEFAULT_RA_AGENT_SUBMITTED_VAL:
            pytest.fail("Request was not resubmitted")

        assert resubmit2_val > resubmit_val

        ca_error = get_certmonger_request_value(self.replicas[0],
                                                request_id, "ca_error")
        state = get_certmonger_request_value(self.replicas[0],
                                             request_id, "state")

        assert ca_error is None
        assert state == 'CA_WORKING'
