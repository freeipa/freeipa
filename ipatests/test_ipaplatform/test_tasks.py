#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import os

from ipaplatform.tasks import tasks


def test_detect_container():
    container = None
    # naive detection, may fail for OpenVZ and other container runtimes
    if os.path.isfile('/run/systemd/container'):
        with open('/run/systemd/container') as f:
            container = f.read().strip()
    elif os.geteuid() == 0:
        with open('/proc/1/environ') as f:
            environ = f.read()
        for item in environ.split('\x00'):
            if not item:
                continue
            k, v = item.split('=', 1)
            if k == 'container':
                container = v

    detected = tasks.detect_container()
    if container == 'oci':
        # systemd doesn't know about podman
        assert detected in {'container-other', container}
    else:
        assert detected == container
