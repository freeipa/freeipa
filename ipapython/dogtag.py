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
from nss.error import NSPRError

from ipalib import api, errors
from ipalib.errors import NetworkError, CertificateOperationError
from ipalib.text import _
from ipapython import nsslib, ipautil
from ipapython.ipa_log_manager import *

# IPA can use either Dogtag version 9 or 10.
#
# Install tools should use the constants from install_constants, so that they
# install with version 10 if it is available, and with 9 if not.
# After IPA installation, the Dogtag version used is stored in the
# "dogtag_version" config option. (If that is missing, version 9 is assumed.)
# The configured_constants() function below provides constants relevant to
# the configured version.

class Dogtag10Constants(object):
    DOGTAG_VERSION = 10
    UNSECURE_PORT = 8080
    AGENT_SECURE_PORT = 8443
    EE_SECURE_PORT = 8443
    AJP_PORT = 8009

    SPAWN_BINARY = '/usr/sbin/pkispawn'
    DESTROY_BINARY = '/usr/sbin/pkidestroy'

    SERVER_ROOT = '/var/lib/pki'
    PKI_INSTANCE_NAME = 'pki-tomcat'
    PKI_ROOT = '%s/%s' % (SERVER_ROOT, PKI_INSTANCE_NAME)
    CRL_PUBLISH_PATH = '/var/lib/ipa/pki-ca/publish'
    CS_CFG_PATH = '%s/conf/ca/CS.cfg' % PKI_ROOT
    PASSWORD_CONF_PATH = '%s/conf/password.conf' % PKI_ROOT
    SERVICE_PROFILE_DIR = '%s/ca/profiles/ca' % PKI_ROOT
    ALIAS_DIR = '/etc/pki/pki-tomcat/alias'

    RACERT_LINE_SEP = '\n'

    IPA_SERVICE_PROFILE = '%s/caIPAserviceCert.cfg' % SERVICE_PROFILE_DIR
    SIGN_PROFILE = '%s/caJarSigningCert.cfg' % SERVICE_PROFILE_DIR

class Dogtag9Constants(object):
    DOGTAG_VERSION = 9
    UNSECURE_PORT = 9180
    AGENT_SECURE_PORT = 9443
    EE_SECURE_PORT = 9444
    AJP_PORT = 9447

    SPAWN_BINARY = '/bin/pkicreate'
    DESTROY_BINARY = '/bin/pkisilent'

    SERVER_ROOT = '/var/lib'
    PKI_INSTANCE_NAME = 'pki-ca'
    PKI_ROOT = '%s/%s' % (SERVER_ROOT, PKI_INSTANCE_NAME)
    CRL_PUBLISH_PATH = '/var/lib/ipa/pki-ca/publish'
    CS_CFG_PATH = '%s/conf/CS.cfg' % PKI_ROOT
    PASSWORD_CONF_PATH = '%s/conf/password.conf' % PKI_ROOT
    SERVICE_PROFILE_DIR = '%s/profiles/ca' % PKI_ROOT
    ALIAS_DIR = '%s/alias' % PKI_ROOT

    RACERT_LINE_SEP = '\r\n'

    ADMIN_SECURE_PORT = 9445
    EE_CLIENT_AUTH_PORT = 9446
    TOMCAT_SERVER_PORT = 9701

    IPA_SERVICE_PROFILE = '%s/caIPAserviceCert.cfg' % SERVICE_PROFILE_DIR
    SIGN_PROFILE = '%s/caJarSigningCert.cfg' % SERVICE_PROFILE_DIR


if os.path.exists('/usr/sbin/pkispawn'):
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
        p.read("/etc/ipa/default.conf")
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


def get_ca_certchain(ca_host=None):
    """
    Retrieve the CA Certificate chain from the configured Dogtag server.
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    chain = None
    conn = httplib.HTTPConnection(ca_host,
        api.env.ca_install_port or configured_constants().UNSECURE_PORT)
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
                try:
                    item_node = doc.getElementsByTagName("Error")
                    reason = item_node[0].childNodes[0].data
                    raise errors.RemoteRetrieveError(reason=reason)
                except Exception, e:
                    raise errors.RemoteRetrieveError(
                        reason=_("Retrieving CA cert chain failed: %s") % e)
        finally:
            if doc:
                doc.unlink()
    else:
        raise errors.RemoteRetrieveError(
            reason=_("request failed with HTTP status %d") % res.status)

    return chain

def https_request(host, port, url, secdir, password, nickname, **kw):
    """
    :param url: The URL to post to.
    :param kw:  Keyword arguments to encode into POST body.
    :return:   (http_status, http_reason_phrase, http_headers, http_body)
               as (integer, unicode, dict, str)

    Perform a client authenticated HTTPS request
    """
    if isinstance(host, unicode):
        host = host.encode('utf-8')
    uri = 'https://%s%s' % (ipautil.format_netloc(host, port), url)
    post = urlencode(kw)
    root_logger.debug('https_request %r', uri)
    root_logger.debug('https_request post %r', post)
    request_headers = {"Content-type": "application/x-www-form-urlencoded",
                       "Accept": "text/plain"}
    try:
        conn = nsslib.NSSConnection(host, port, dbdir=secdir)
        conn.set_debuglevel(0)
        conn.connect()
        conn.sock.set_client_auth_data_callback(nsslib.client_auth_data_callback,
                                                nickname,
                                                password, nss.get_default_certdb())
        conn.request("POST", url, post, request_headers)

        res = conn.getresponse()

        http_status = res.status
        http_reason_phrase = unicode(res.reason, 'utf-8')
        http_headers = res.msg.dict
        http_body = res.read()
        conn.close()
    except Exception, e:
        raise NetworkError(uri=uri, error=str(e))

    return http_status, http_reason_phrase, http_headers, http_body

def http_request(host, port, url, **kw):
        """
        :param url: The URL to post to.
        :param kw: Keyword arguments to encode into POST body.
        :return:   (http_status, http_reason_phrase, http_headers, http_body)
                   as (integer, unicode, dict, str)

        Perform an HTTP request.
        """
        if isinstance(host, unicode):
            host = host.encode('utf-8')
        uri = 'http://%s%s' % (ipautil.format_netloc(host, port), url)
        post = urlencode(kw)
        root_logger.info('request %r', uri)
        root_logger.debug('request post %r', post)
        conn = httplib.HTTPConnection(host, port)
        try:
            conn.request('POST', url,
                body=post,
                headers={'Content-type': 'application/x-www-form-urlencoded'},
            )
            res = conn.getresponse()

            http_status = res.status
            http_reason_phrase = unicode(res.reason, 'utf-8')
            http_headers = res.msg.dict
            http_body = res.read()
            conn.close()
        except NSPRError, e:
            raise NetworkError(uri=uri, error=str(e))

        root_logger.debug('request status %d',        http_status)
        root_logger.debug('request reason_phrase %r', http_reason_phrase)
        root_logger.debug('request headers %s',       http_headers)
        root_logger.debug('request body %r',          http_body)

        return http_status, http_reason_phrase, http_headers, http_body
