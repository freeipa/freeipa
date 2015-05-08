# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import httplib
import xml.dom.minidom
import ConfigParser
from urllib import urlencode

import nss.nss as nss

from ipalib import api, errors
from ipalib.errors import NetworkError
from ipalib.text import _
from ipapython import nsslib, ipautil
from ipaplatform.paths import paths
from ipapython.ipa_log_manager import *

# IPA can use either Dogtag version 9 or 10.
#
# Install tools should use the constants from install_constants, so that they
# install with version 10 if it is available, and with 9 if not.
# After IPA installation, the Dogtag version used is stored in the
# "dogtag_version" config option. (If that is missing, version 9 is assumed.)
# The configured_constants() function below provides constants relevant to
# the configured version.


INCLUDED_PROFILES = {
    # ( profile_id    ,         description      ,      store_issued)
    (u'caIPAserviceCert', u'Standard profile for network services', True),
    }

DEFAULT_PROFILE = u'caIPAserviceCert'

class Dogtag10Constants(object):
    DOGTAG_VERSION = 10
    UNSECURE_PORT = 8080
    AGENT_SECURE_PORT = 8443
    EE_SECURE_PORT = 8443
    AJP_PORT = 8009
    DS_PORT = 389
    DS_SECURE_PORT = 636

    SPAWN_BINARY = paths.PKISPAWN
    DESTROY_BINARY = paths.PKIDESTROY

    SERVER_ROOT = paths.VAR_LIB_PKI_DIR
    PKI_INSTALL_LOG = paths.PKI_CA_INSTALL_LOG
    PKI_INSTANCE_NAME = 'pki-tomcat'
    PKI_LOG_TOP_LEVEL = os.path.join(paths.VAR_LOG_PKI_DIR, PKI_INSTANCE_NAME)
    PKI_ROOT = '%s/%s' % (SERVER_ROOT, PKI_INSTANCE_NAME)
    CRL_PUBLISH_PATH = paths.PKI_CA_PUBLISH_DIR
    CS_CFG_PATH = '%s/conf/ca/CS.cfg' % PKI_ROOT
    PASSWORD_CONF_PATH = '%s/conf/password.conf' % PKI_ROOT
    SERVICE_PROFILE_DIR = '%s/ca/profiles/ca' % PKI_ROOT
    ALIAS_DIR = paths.PKI_TOMCAT_ALIAS_DIR.rstrip('/')
    SYSCONFIG_FILE_PATH = '%s/%s' % (paths.ETC_SYSCONFIG_DIR, PKI_INSTANCE_NAME)
    KRA_CS_CFG_PATH = '%s/conf/kra/CS.cfg' % PKI_ROOT

    SERVICE_NAME = 'pki_tomcatd'

    RACERT_LINE_SEP = '\n'

    SIGN_PROFILE = '%s/caJarSigningCert.cfg' % SERVICE_PROFILE_DIR
    SHARED_DB = True
    DS_USER = "dirsrv"
    DS_NAME = "dirsrv"


class Dogtag9Constants(object):
    DOGTAG_VERSION = 9
    UNSECURE_PORT = 9180
    AGENT_SECURE_PORT = 9443
    EE_SECURE_PORT = 9444
    AJP_PORT = 9447
    DS_PORT = 7389
    DS_SECURE_PORT = 7636

    SPAWN_BINARY = paths.PKICREATE
    DESTROY_BINARY = paths.PKISILENT

    SERVER_ROOT = paths.VAR_LIB
    PKI_INSTALL_LOG = paths.PKI_CA_INSTALL_LOG
    PKI_INSTANCE_NAME = 'pki-ca'
    PKI_LOG_TOP_LEVEL = paths.PKI_CA_LOG_DIR
    PKI_ROOT = '%s/%s' % (SERVER_ROOT, PKI_INSTANCE_NAME)
    CRL_PUBLISH_PATH = paths.PKI_CA_PUBLISH_DIR
    CS_CFG_PATH = '%s/conf/CS.cfg' % PKI_ROOT
    PASSWORD_CONF_PATH = '%s/conf/password.conf' % PKI_ROOT
    SERVICE_PROFILE_DIR = '%s/profiles/ca' % PKI_ROOT
    ALIAS_DIR = '%s/alias' % PKI_ROOT
    SYSCONFIG_FILE_PATH = '%s/%s' % (paths.ETC_SYSCONFIG_DIR, PKI_INSTANCE_NAME)

    SERVICE_NAME = 'pki-cad'

    RACERT_LINE_SEP = '\r\n'

    ADMIN_SECURE_PORT = 9445
    EE_CLIENT_AUTH_PORT = 9446
    TOMCAT_SERVER_PORT = 9701

    SIGN_PROFILE = '%s/caJarSigningCert.cfg' % SERVICE_PROFILE_DIR
    SHARED_DB = False
    DS_USER = "pkisrv"
    DS_NAME = "PKI-IPA"

if os.path.exists(paths.PKISPAWN):
    install_constants = Dogtag10Constants
else:
    install_constants = Dogtag9Constants


def _get_configured_version(api):
    """Get the version of Dogtag IPA is configured to use

    If an API is given, use information in its environment.
    Otherwise, use information from the global config file.
    """
    if api:
        return int(api.env.dogtag_version)
    else:
        p = ConfigParser.SafeConfigParser()
        p.read(paths.IPA_DEFAULT_CONF)
        try:
            version = p.get('global', 'dogtag_version')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            return 9
        else:
            return int(version)


def configured_constants(api=None):
    """Get the name of the Dogtag CA instance

    See get_configured_version
    """
    if _get_configured_version(api) >= 10:
        return Dogtag10Constants
    else:
        return Dogtag9Constants


def error_from_xml(doc, message_template):
    try:
        item_node = doc.getElementsByTagName("Error")
        reason = item_node[0].childNodes[0].data
        return errors.RemoteRetrieveError(reason=reason)
    except Exception, e:
        return errors.RemoteRetrieveError(reason=message_template % e)


def get_ca_certchain(ca_host=None, dogtag_constants=None):
    """
    Retrieve the CA Certificate chain from the configured Dogtag server.
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    if dogtag_constants is None:
        dogtag_constants = configured_constants()
    chain = None
    conn = httplib.HTTPConnection(
        ca_host,
        api.env.ca_install_port or dogtag_constants.UNSECURE_PORT)
    conn.request("GET", "/ca/ee/ca/getCertChain")
    res = conn.getresponse()
    doc = None
    if res.status == 200:
        data = res.read()
        conn.close()
        try:
            doc = xml.dom.minidom.parseString(data)
            try:
                item_node = doc.getElementsByTagName("ChainBase64")
                chain = item_node[0].childNodes[0].data
            except IndexError:
                raise error_from_xml(
                    doc, _("Retrieving CA cert chain failed: %s"))
        finally:
            if doc:
                doc.unlink()
    else:
        raise errors.RemoteRetrieveError(
            reason=_("request failed with HTTP status %d") % res.status)

    return chain


def _parse_ca_status(body):
    doc = xml.dom.minidom.parseString(body)
    try:
        item_node = doc.getElementsByTagName("XMLResponse")[0]
        item_node = item_node.getElementsByTagName("Status")[0]
        return item_node.childNodes[0].data
    except IndexError:
        raise error_from_xml(doc, _("Retrieving CA status failed: %s"))


def ca_status(ca_host=None, use_proxy=True):
    """Return the status of the CA, and the httpd proxy in front of it

    The returned status can be:
    - running
    - starting
    - Service Temporarily Unavailable
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    if use_proxy:
        # Use port 443 to test the proxy as well
        ca_port = 443
    else:
        ca_port = 8443
    status, reason, headers, body = unauthenticated_https_request(
        ca_host, ca_port, '/ca/admin/ca/getStatus')
    if status == 503:
        # Service temporarily unavailable
        return reason
    elif status != 200:
        raise errors.RemoteRetrieveError(
            reason=_("Retrieving CA status failed: %s") % reason)
    return _parse_ca_status(body)


def https_request(host, port, url, secdir, password, nickname,
        method='POST', headers=None, body=None, **kw):
    """
    :param method: HTTP request method (defalut: 'POST')
    :param url: The path (not complete URL!) to post to.
    :param body: The request body (encodes kw if None)
    :param kw:  Keyword arguments to encode into POST body.
    :return:   (http_status, http_reason_phrase, http_headers, http_body)
               as (integer, unicode, dict, str)

    Perform a client authenticated HTTPS request
    """

    def connection_factory(host, port):
        conn = nsslib.NSSConnection(host, port, dbdir=secdir,
                                    tls_version_min=api.env.tls_version_min,
                                    tls_version_max=api.env.tls_version_max)
        conn.set_debuglevel(0)
        conn.connect()
        conn.sock.set_client_auth_data_callback(
            nsslib.client_auth_data_callback,
            nickname, password, nss.get_default_certdb())
        return conn

    if body is None:
        body = urlencode(kw)
    return _httplib_request(
        'https', host, port, url, connection_factory, body,
        method=method, headers=headers)


def http_request(host, port, url, **kw):
    """
    :param url: The path (not complete URL!) to post to.
    :param kw: Keyword arguments to encode into POST body.
    :return:   (http_status, http_reason_phrase, http_headers, http_body)
                as (integer, unicode, dict, str)

    Perform an HTTP request.
    """
    body = urlencode(kw)
    return _httplib_request(
        'http', host, port, url, httplib.HTTPConnection, body)


def unauthenticated_https_request(host, port, url, **kw):
    """
    :param url: The path (not complete URL!) to post to.
    :param kw: Keyword arguments to encode into POST body.
    :return:   (http_status, http_reason_phrase, http_headers, http_body)
                as (integer, unicode, dict, str)

    Perform an unauthenticated HTTPS request.
    """
    body = urlencode(kw)
    return _httplib_request(
        'https', host, port, url, httplib.HTTPSConnection, body)


def _httplib_request(
        protocol, host, port, path, connection_factory, request_body,
        method='POST', headers=None):
    """
    :param request_body: Request body
    :param connection_factory: Connection class to use. Will be called
        with the host and port arguments.
    :param method: HTTP request method (default: 'POST')

    Perform a HTTP(s) request.
    """
    if isinstance(host, unicode):
        host = host.encode('utf-8')
    uri = '%s://%s%s' % (protocol, ipautil.format_netloc(host, port), path)
    root_logger.debug('request %r', uri)
    root_logger.debug('request body %r', request_body)

    headers = headers or {}
    if (
        method == 'POST'
        and 'content-type' not in (str(k).lower() for k in headers.viewkeys())
    ):
        headers['content-type'] = 'application/x-www-form-urlencoded'

    try:
        conn = connection_factory(host, port)
        conn.request(method, uri, body=request_body, headers=headers)
        res = conn.getresponse()

        http_status = res.status
        http_reason_phrase = unicode(res.reason, 'utf-8')
        http_headers = res.msg.dict
        http_body = res.read()
        conn.close()
    except Exception, e:
        raise NetworkError(uri=uri, error=str(e))

    root_logger.debug('request status %d',        http_status)
    root_logger.debug('request reason_phrase %r', http_reason_phrase)
    root_logger.debug('request headers %s',       http_headers)
    root_logger.debug('request body %r',          http_body)

    return http_status, http_reason_phrase, http_headers, http_body
