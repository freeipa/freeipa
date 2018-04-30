#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging
import os
import time

import gssapi

from ipaplatform.paths import paths
from ipapython.ipautil import run

logger = logging.getLogger(__name__)

# Cannot contact any KDC for requested realm
KRB5_KDC_UNREACH = 2529639068

# A service is not available that s required to process the request
KRB5KDC_ERR_SVC_UNAVAILABLE = 2529638941


def kinit_keytab(principal, keytab, ccache_name, config=None, attempts=1):
    """
    Given a ccache_path, keytab file and a principal kinit as that user.

    The optional parameter 'attempts' specifies how many times the credential
    initialization should be attempted in case of non-responsive KDC.
    """
    errors_to_retry = {KRB5KDC_ERR_SVC_UNAVAILABLE,
                       KRB5_KDC_UNREACH}
    logger.debug("Initializing principal %s using keytab %s",
                 principal, keytab)
    logger.debug("using ccache %s", ccache_name)
    for attempt in range(1, attempts + 1):
        old_config = os.environ.get('KRB5_CONFIG')
        if config is not None:
            os.environ['KRB5_CONFIG'] = config
        else:
            os.environ.pop('KRB5_CONFIG', None)
        try:
            name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
            store = {'ccache': ccache_name,
                     'client_keytab': keytab}
            cred = gssapi.Credentials(name=name, store=store, usage='initiate')
            logger.debug("Attempt %d/%d: success", attempt, attempts)
            return cred
        except gssapi.exceptions.GSSError as e:
            if e.min_code not in errors_to_retry:  # pylint: disable=no-member
                raise
            logger.debug("Attempt %d/%d: failed: %s", attempt, attempts, e)
            if attempt == attempts:
                logger.debug("Maximum number of attempts (%d) reached",
                             attempts)
                raise
            logger.debug("Waiting 5 seconds before next retry")
            time.sleep(5)
        finally:
            if old_config is not None:
                os.environ['KRB5_CONFIG'] = old_config
            else:
                os.environ.pop('KRB5_CONFIG', None)

def kinit_password(principal, password, ccache_name, config=None,
                   armor_ccache_name=None, canonicalize=False,
                   enterprise=False, lifetime=None):
    """
    perform interactive kinit as principal using password. If using FAST for
    web-based authentication, use armor_ccache_path to specify http service
    ccache.
    """
    logger.debug("Initializing principal %s using password", principal)
    args = [paths.KINIT, principal, '-c', ccache_name]
    if armor_ccache_name is not None:
        logger.debug("Using armor ccache %s for FAST webauth",
                     armor_ccache_name)
        args.extend(['-T', armor_ccache_name])

    if lifetime:
        args.extend(['-l', lifetime])

    if canonicalize:
        logger.debug("Requesting principal canonicalization")
        args.append('-C')

    if enterprise:
        logger.debug("Using enterprise principal")
        args.append('-E')

    env = {'LC_ALL': 'C'}
    if config is not None:
        env['KRB5_CONFIG'] = config

    # this workaround enables us to capture stderr and put it
    # into the raised exception in case of unsuccessful authentication
    result = run(args, stdin=password, env=env, raiseonerr=False,
                 capture_error=True)
    if result.returncode:
        raise RuntimeError(result.error_output)


def kinit_armor(ccache_name, pkinit_anchors=None):
    """
    perform anonymous pkinit to obtain anonymous ticket to be used as armor
    for FAST.

    :param ccache_name: location of the armor ccache
    :param pkinit_anchor: if not None, the location of PKINIT anchor file to
        use. Otherwise the value from Kerberos client library configuration is
        used

    :raises: CalledProcessError if the anonymous PKINIT fails
    """
    logger.debug("Initializing anonymous ccache")

    env = {'LC_ALL': 'C'}
    args = [paths.KINIT, '-n', '-c', ccache_name]

    if pkinit_anchors is not None:
        for pkinit_anchor in pkinit_anchors:
            args.extend(['-X', 'X509_anchors=FILE:{}'.format(pkinit_anchor)])

    # this workaround enables us to capture stderr and put it
    # into the raised exception in case of unsuccessful authentication
    run(args, env=env, raiseonerr=True, capture_error=True)
