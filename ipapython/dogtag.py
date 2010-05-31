# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

from ipalib import api, errors
import httplib
import xml.dom.minidom
from ipapython import nsslib
import nss.nss as nss
from nss.error import NSPRError
from ipalib.errors import NetworkError, CertificateOperationError
from urllib import urlencode
import logging

def get_ca_certchain(ca_host=None):
    """
    Retrieve the CA Certificate chain from the configured Dogtag server.
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    chain = None
    conn = httplib.HTTPConnection(ca_host, api.env.ca_port)
    conn.request("GET", "/ca/ee/ca/getCertChain")
    res = conn.getresponse()
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
                    raise errors.RemoteRetrieveError(reason="Retrieving CA cert chain failed: %s" % str(e))
        finally:
            doc.unlink()

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
    uri = 'https://%s:%d%s' % (host, port, url)
    post = urlencode(kw)
    logging.info('sslget %r', uri)
    logging.debug('sslget post %r', post)
    request_headers = {"Content-type": "application/x-www-form-urlencoded",
                       "Accept": "text/plain"}
    try:
        conn = nsslib.NSSConnection(host, port, dbdir=secdir)
        conn.sock.set_client_auth_data_callback(nsslib.client_auth_data_callback,
                                                nickname,
                                                password, nss.get_default_certdb())
        conn.set_debuglevel(0)
        conn.connect()
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
        uri = 'http://%s:%s%s' % (host, port, url)
        post = urlencode(kw)
        logging.info('request %r', uri)
        logging.debug('request post %r', post)
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

        logging.debug('request status %d',        http_status)
        logging.debug('request reason_phrase %r', http_reason_phrase)
        logging.debug('request headers %s',       http_headers)
        logging.debug('request body %r',          http_body)

        return http_status, http_reason_phrase, http_headers, http_body
