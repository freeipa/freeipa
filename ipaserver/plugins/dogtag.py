# Authors:
#   Ade Lee <alee@redhat.com>
#   Andrew Wnuk <awnuk@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@@redhat.com>
#   John Dennis <jdennis@redhat.com>
#   Fraser Tweedale <ftweedal@redhat.com>
#   Abhijeet Kasurde <akasurde@redhat.com>
#
# Copyright (C) 2014-2016  Red Hat, Inc.
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

r'''

==============================================
Backend plugin for RA using Dogtag (e.g. CMS)
==============================================

Overview of interacting with CMS:
---------------------------------

CMS stands for "Certificate Management System". It has been released under a
variety of names, the open source version is called "dogtag".

IPA now uses the python API provided by dogtag, as documented at
https://github.com/dogtagpki/pki/wiki/Client-API

The below is still relevant in places, particularly with data handling.
This history of Javascript parsing and using the optional XML is left
for historical purposes and for the last-used xml-based call that
IPA makes (updateCRL).

CMS consists of a number of servlets which in rough terms can be thought of as
RPC commands. A servlet is invoked by making an HTTP request to a specific URL
and passing URL arguments. Normally CMS responds with an HTTP response consisting
of HTML to be rendered by a web browser. This HTTP HTML response has both
Javascript SCRIPT components and HTML rendering code. One of the Javascript
SCRIPT blocks holds the data for the result. The rest of the response is derived
from templates associated with the servlet which may be customized. The
templates pull the result data from Javascript variables.

One way to get the result data is to parse the HTML looking for the Javascript
variable initializations. Simple string searches are not a robust method. First of
all one must be sure the string is only found in a Javascript SCRIPT block and
not somewhere else in the HTML document. Some of the Javascript variable
initializations are rather complex (e.g. lists of structures). It would be hard
to correctly parse such complex and diverse Javascript. Existing Javascript
parsers are not generally available. Finally, it's important to know the
character encoding for strings. There is a somewhat complex set of precedent
rules for determining the current character encoding from the HTTP header,
meta-equiv tags, mime Content-Type and charset attributes on HTML elements. All
of this means trying to read the result data from a CMS HTML response is
difficult to do robustly.

However, CMS also supports returning the result data as a XML document
(distinct from an XHTML document which would be essentially the same as
described above). There are a wide variety of tools to robustly parse
XML. Because XML is so well defined things like escapes, character encodings,
etc. are automatically handled by the tools.

Thus we never try to parse Javascript, instead we always ask CMS to return us an
XML document by passing the URL argument xml="true". The body of the HTTP
response is an XML document rather than HTML with embedded Javascript.

To parse the XML documents we use the Python lxml package which is a Python
binding around the libxml2 implementation. libxml2 is a very fast, standard
compliant, feature full XML implementation. libxml2 is the XML library of choice
for many projects. One of the features in lxml and libxml2 that is particularly
valuable to us is the XPath implementation. We make heavy use of XPath to find
data in the XML documents we're parsing.

Parse Results vs. IPA command results:
--------------------------------------

CMS results will now always be python native objects, decoded from JSON.

There was a time where the data come from either HTML, XML or JSON
and therefore some massaging of data was required. During the rewrite
to use the python API the IPA API expectations generally remained the
same and these classes were modified to return what it expected. This
also ensures that an older IPA client or server will continue to work
as well.

Serial Numbers:
---------------

Serial numbers are integral values of any magnitude because they are based on
ASN.1 integers. CMS uses the Java BigInteger to represent these. Fortunately
Python also has support for big integers via the Python long() object. Any
BigIntegers we receive from CMS as a string can be parsed into a Python long
without loss of information.

However Python has a neat trick. It normally represents integers via the int
object which internally uses the native C long type. If you create an int
object by passing the int constructor a string it will check the magnitude of
the value. If it would fit in a C long then it returns you an int
object. However if the value is too big for a C long type then it returns you
a Python long object instead. This is a very nice property because it's much
more efficient to use C long types when possible (e.g. Python int), but when
necessary you'll get a Python long() object to handle large magnitude
values. Python also nicely handles type promotion transparently between int
and long objects. For example if you multiply two int objects you may get back
a long object if necessary. In general Python int and long objects may be
freely mixed without the programmer needing to be aware of which type of
integral object is being operated on.

The leads to the following rule, always parse a string representing an
integral value using the int() constructor even if it might have large
magnitude because Python will return either an int or a long automatically. By
the same token don't test for type of an object being int exclusively because
it could either be an int or a long object.

Internally we should always being using int or long object to hold integral
values. This is because we should be able to compare them correctly, be free
from concerns about having the know the radix of the string, perform
arithmetic operations, and convert to string representation (with correct
radix) when necessary. In other words internally we should never handle
integral values as strings.

However, the XMLRPC transport cannot properly handle a Python long object. The
XMLRPC encoder upon seeing a Python long will test to see if the value fits
within the range of an 32-bit integer, if so it passes the integer parameter
otherwise it raises an Overflow exception. The XMLRPC specification does
permit 64-bit integers (e.g. i8) and the Python XMLRPC module could allow long
values within the 64-bit range to be passed if it were patched, however this
only moves the problem, it does not solve passing big integers through
XMLRPC. Thus we must always pass big integers as a strings through the XMLRPC
interface. But upon receiving that value from XMLRPC we should convert it back
into an int or long object. Recall also that Python will automatically perform
a conversion to string if you output the int or long object in a string context.

Radix Issues:
-------------

CMS uses the following conventions: Serial numbers are always returned as
hexadecimal strings without a radix prefix. When CMS takes a serial number as
input it accepts the value in either decimal or hexadecimal utilizing the radix
prefix (e.g. 0x) to determine how to parse the value.

IPA has adopted the convention that all integral values in the user interface
will use base 10 decimal radix.

Basic rules on handling these values

1. Reading a serial number from CMS requires conversion from hexadecimal
   by converting it into a Python int or long object, use the int constructor:

        serial_number = int(serial_number, 16)

2. Big integers passed to XMLRPC must be decimal strings

       str(serial_number)

3. Big integers received from XMLRPC must be converted back to int or long
   objects from the decimal string representation.

       serial_number = int(serial_number)

'''

from __future__ import absolute_import

import base64
import json
import logging

from lxml import etree
import time
import contextlib


from ipalib import Backend, api, x509
from ipapython.dn import DN
from ipapython import dogtag
from ipapython.ipautil import log_level_override
from ipaserver.masters import find_providing_server

import requests.exceptions

import pki
import pki.authority
import pki.ca
import pki.cert
import pki.client
import pki.info
import pki.profile
import pki.subsystem
import pki.system

from pki.cert import CertRequestStatus
import pki.crypto as cryptoutil
from pki.kra import KRAClient

logger = logging.getLogger(__name__)

# These are general status return values used when
# CMSServlet.outputError() is invoked.
CMS_SUCCESS      = 0
CMS_FAILURE      = 1
CMS_AUTH_FAILURE = 2

# CMS (Certificate Management System) status return values
# These are requestStatus return values used with templates
CMS_STATUS_UNAUTHORIZED = 1
CMS_STATUS_SUCCESS      = 2
CMS_STATUS_PENDING      = 3
CMS_STATUS_SVC_PENDING  = 4
CMS_STATUS_REJECTED     = 5
CMS_STATUS_ERROR        = 6
CMS_STATUS_EXCEPTION    = 7


def cms_request_status_to_string(request_status):
    '''
    :param request_status: The integral request status value
    :return:               String name of request status
    '''
    return {
    1 : 'UNAUTHORIZED',
    2 : 'SUCCESS',
    3 : 'PENDING',
    4 : 'SVC_PENDING',
    5 : 'REJECTED',
    6 : 'ERROR',
    7 : 'EXCEPTION',
    }.get(request_status, "unknown(%d)" % request_status)

def get_request_status_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   request status as an integer

    Returns the request status from a CMS operation. May be one of:

    - CMS_STATUS_UNAUTHORIZED = 1
    - CMS_STATUS_SUCCESS      = 2
    - CMS_STATUS_PENDING      = 3
    - CMS_STATUS_SVC_PENDING  = 4
    - CMS_STATUS_REJECTED     = 5
    - CMS_STATUS_ERROR        = 6
    - CMS_STATUS_EXCEPTION    = 7

    CMS will often fail to return requestStatus when the status is
    SUCCESS. Therefore if we fail to find a requestStatus field we default the
    result to CMS_STATUS_SUCCESS.
    '''

    request_status = doc.xpath('//xml/fixed/requestStatus[1]')
    if len(request_status) == 1:
        request_status = int(request_status[0].text)
    else:
        # When a request is successful CMS often omits the requestStatus
        request_status = CMS_STATUS_SUCCESS

    # However, if an error string was returned it's an error no
    # matter what CMS returned as requestStatus.
    # Just to make life interesting CMS sometimes returns an empty error string
    # when nothing wrong occurred.
    error_detail = doc.xpath('//xml/fixed/errorDetails[1]')
    if len(error_detail) == 1 and len(error_detail[0].text.strip()) > 0:
        # There was a non-empty error string, if the status was something
        # other than error or exception then force it to be an error.
        if not (request_status in (CMS_STATUS_ERROR, CMS_STATUS_EXCEPTION)):
            request_status = CMS_STATUS_ERROR

    return request_status


def parse_error_template_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict

    CMS currently returns errors via XML as either a "template" document
    (generated by CMSServlet.outputXML() or a "response" document (generated by
    CMSServlet.outputError()).

    This routine is used to parse a "template" style error or exception
    document.

    This routine should be use when the CMS requestStatus is ERROR or
    EXCEPTION. It is capable of parsing both. A CMS ERROR occurs when a known
    anticipated error condition occurs (e.g. asking for an item which does not
    exist). A CMS EXCEPTION occurs when an exception is thrown in the CMS server
    and it's not caught and converted into an ERROR. Think of EXCEPTIONS as the
    "catch all" error situation.

    ERROR's and EXCEPTIONS's both have error message strings associated with
    them. For an ERROR it's errorDetails, for an EXCEPTION it's
    unexpectedError. In addition an EXCEPTION may include an array of additional
    error strings in it's errorDescription field.

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    +----------------+---------------+------------------+---------------+
    |cms name        |cms type       |result name       |result type    |
    +================+===============+==================+===============+
    |requestStatus   |int            |request_status    |int            |
    +----------------+---------------+------------------+---------------+
    |errorDetails    |string         |error_string [1]_ |str            |
    +----------------+---------------+------------------+---------------+
    |unexpectedError |string         |error_string [1]_ |str            |
    +----------------+---------------+------------------+---------------+
    |errorDescription|[string]       |error_descriptions|[str]          |
    +----------------+---------------+------------------+---------------+
    |authority       |string         |authority         |str            |
    +----------------+---------------+------------------+---------------+

    .. [1] errorDetails is the error message string when the requestStatus
           is ERROR. unexpectedError is the error message string when
           the requestStatus is EXCEPTION. This routine recognizes both
           ERROR's and EXCEPTION's and depending on which is found folds
           the error message into the error_string result value.
    '''

    response = {}
    response['request_status'] = CMS_STATUS_ERROR # assume error


    request_status = doc.xpath('//xml/fixed/requestStatus[1]')
    if len(request_status) == 1:
        request_status = int(request_status[0].text)
        response['request_status'] = request_status

    error_descriptions = []
    for description in doc.xpath('//xml/records[*]/record/errorDescription'):
        error_descriptions.append(etree.tostring(description, method='text',
                                                 encoding=str).strip())
    if len(error_descriptions) > 0:
        response['error_descriptions'] = error_descriptions

    authority = doc.xpath('//xml/fixed/authorityName[1]')
    if len(authority) == 1:
        authority = etree.tostring(authority[0], method='text',
                                   encoding=str).strip()
        response['authority'] = authority

    # Should never get both errorDetail and unexpectedError
    error_detail = doc.xpath('//xml/fixed/errorDetails[1]')
    if len(error_detail) == 1:
        error_detail = etree.tostring(error_detail[0], method='text',
                                      encoding=str).strip()
        response['error_string'] = error_detail

    unexpected_error = doc.xpath('//xml/fixed/unexpectedError[1]')
    if len(unexpected_error) == 1:
        unexpected_error = etree.tostring(unexpected_error[0], method='text',
                                          encoding=str).strip()
        response['error_string'] = unexpected_error

    return response


def parse_updateCRL_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found
    in the result dict. If a CMS data item is absent it will also be absent in
    the result dict.

    If the requestStatus is not SUCCESS then the response dict will have the
    contents described in `parse_error_template_xml`.

    +-----------------+-------------+-----------------------+---------------+
    |cms name         |cms type     |result name            |result type    |
    +=================+=============+=======================+===============+
    |crlIssuingPoint  |string       |crl_issuing_point      |str            |
    +-----------------+-------------+-----------------------+---------------+
    |crlUpdate        |string       |crl_update [1]         |str            |
    +-----------------+-------------+-----------------------+---------------+

    .. [1] crlUpdate may be one of:

           - "Success"
           - "Failure"
           - "missingParameters"
           - "testingNotEnabled"
           - "testingInProgress"
           - "Scheduled"
           - "inProgress"
           - "disabled"
           - "notInitialized"

    '''

    request_status = get_request_status_xml(doc)

    if request_status != CMS_STATUS_SUCCESS:
        response = parse_error_template_xml(doc)
        return response

    response = {}
    response['request_status'] = request_status

    crl_issuing_point = doc.xpath('//xml/header/crlIssuingPoint[1]')
    if len(crl_issuing_point) == 1:
        crl_issuing_point = etree.tostring(
            crl_issuing_point[0], method='text',
            encoding=str).strip()
        response['crl_issuing_point'] = crl_issuing_point

    crl_update = doc.xpath('//xml/header/crlUpdate[1]')
    if len(crl_update) == 1:
        crl_update = etree.tostring(crl_update[0], method='text',
                                    encoding=str).strip()
        response['crl_update'] = crl_update

    return response


#-------------------------------------------------------------------------------

from ipalib import Registry, errors, SkipPluginModule

# We only load the dogtag RA plugin if it is necessary to do so.
# This is legacy code from when multiple RA backends were supported.
#
# If the plugins are loaded by the server then load the RA backend.
#
if api.isdone("finalize") and not (
    api.env.ra_plugin == 'dogtag' or api.env.context == 'installer'
):
    # In this case, abort loading this plugin module...
    raise SkipPluginModule(reason='Not loading dogtag RA plugin')
import os
from ipaserver.plugins import rabase
from ipalib.constants import TYPE_ERROR
from ipalib import _
from ipaplatform.paths import paths

register = Registry()


def support_v2(pki_client):
    """Ignore PKI failover and do it ourselves.

       PKI API failover is completely determined by the remote
       server version. In IPA it is possible that a 11.7.0 CA has
       been deployed but not upgraded so it doesn't expose the v2
       API. This will allow the connection to fall back to v1.

       This is not ideal as v1 relies on VLV which we are trying to
       move away from but let's not punish users too much.
    """
    pki_client.api_path = 'v2'
    pki_client.api_version = 'v2'
    try:
        pki_client.info_client.get_info()
    except Exception:  # yes, PKI can raise a raw exception here
        pki_client.api_path = 'rest'
        pki_client.api_version = 'v1'
    logger.debug("PKI detected API %s", pki_client.api_version)
    return pki_client


class APIClient(Backend):
    """Simple Dogtag API client to be subclassed by other backends.

    This class is a context manager.  Authenticated calls must be
    executed in a ``with`` suite::

        @register()
        class ra_certprofile(APIClient):
            path = 'profile'
            ...

        with api.Backend.ra_certprofile as profile_api:
            # REST client is now logged in
            profile_api.create_profile(...)

    """
    DEFAULT_PROFILE = dogtag.DEFAULT_PROFILE
    KDC_PROFILE = dogtag.KDC_PROFILE
    OCSP_PROFILE = dogtag.OCSP_PROFILE
    SUBSYSTEM_PROFILE = dogtag.SUBSYSTEM_PROFILE
    AUDIT_PROFILE = dogtag.AUDIT_PROFILE
    CACERT_PROFILE = dogtag.CACERT_PROFILE
    CASERVER_PROFILE = dogtag.CASERVER_PROFILE
    KRA_AUDIT_PROFILE = dogtag.KRA_AUDIT_PROFILE
    KRA_STORAGE_PROFILE = dogtag.KRA_STORAGE_PROFILE
    KRA_TRANSPORT_PROFILE = dogtag.KRA_TRANSPORT_PROFILE

    def raise_certificate_operation_exception(self, func_name, exc):
        """
        :param func_name: function name where error occurred

        :param exc:       the exception being raised

        Raise an appropriate exception and log the error message.

        This differs from the ra class raise_certificate_operation_error
        in that it takes a raw exception instead of an error message and
        attempts to return the correct exception type, which may not
        be a CertificateOperationError
        """

        if exc is None:
            err_msg = _('Unable to communicate with CMS')
        elif hasattr(exc, 'message'):
            err_msg = exc.message
        else:
            err_msg = str(exc)

        logger.error('%s.%s(): %s', type(self).__name__, func_name, err_msg)
        if type(exc) in (
            pki.ProfileNotFoundException, pki.BadRequestException,
            pki.ResourceNotFoundException,
        ):
            raise errors.NotFound(reason=err_msg)
        raise errors.CertificateOperationError(error=err_msg)

    def __init__(self, api):
        self.pki_client = None
        self.client = None
        self._ca_host = None
        self.override_port = None
        if api.env.in_tree:
            self.client_certfile = os.path.join(
                api.env.dot_ipa, 'ra-agent.pem')

            self.client_keyfile = os.path.join(
                api.env.dot_ipa, 'ra-agent.key')
        else:
            self.client_certfile = paths.RA_AGENT_PEM
            self.client_keyfile = paths.RA_AGENT_KEY
        super(APIClient, self).__init__(api)
        self.ca_cert = api.env.tls_ca_cert

    @property
    def ca_host(self):
        if self._ca_host is not None:
            return self._ca_host

        preferred = [api.env.ca_host]
        if api.env.host != api.env.ca_host:
            preferred.append(api.env.host)
        ca_host = find_providing_server(
            'CA', conn=self.api.Backend.ldap2, preferred_hosts=preferred,
            api=self.api
        )
        if ca_host is None:
            # TODO: need during installation, CA is not yet set as enabled
            ca_host = api.env.ca_host
        object.__setattr__(self, '_ca_host', ca_host)
        return ca_host

    def __enter__(self):
        # Refresh the ca_host property
        object.__setattr__(self, '_ca_host', None)
        port = self.override_port or "443"

        pki_client = pki.client.PKIClient(
            url=f'https://{self.ca_host}:{port}', ca_bundle=self.ca_cert)
        pki_client = support_v2(pki_client)
        object.__setattr__(self, 'pki_client', pki_client)
        self.pki_client.set_client_auth(
            client_cert=paths.RA_AGENT_PEM,
            client_key=paths.RA_AGENT_KEY)

        try:
            with log_level_override():
                api_path = self.pki_client.get_api_path()
        except requests.exceptions.RequestException as e:
            raise errors.RemoteRetrieveError(reason=e.args[0])
        path = '/ca/%s/account/login' % api_path

        try:
            response = self.pki_client.connection.get(path)
        except requests.exceptions.HTTPError as e:
            logger.debug("PKI API login failed %s", e)
            if e.response.status_code == 401:
                raise errors.RemoteRetrieveError(
                    reason=_("PKI API login failed: invalid authentication"))
            else:
                raise errors.RemoteRetrieveError(reason=e.args[0])
        except requests.exceptions.RequestException as e:
            raise errors.RemoteRetrieveError(reason=e.args[0])

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.pki_client is None:
            return

        api_path = self.pki_client.get_api_path()
        path = '/ca/%s/account/logout' % api_path
        try:
            self.pki_client.connection.get(path)
        except Exception as e:
            # this shouldn't fail but it also shouldn't fail the call
            logger.debug("ra_lightweight_ca: logout failed %s", e)


@register()
class ra(rabase.rabase, APIClient):
    """
    Request Authority backend plugin.
    """
    DEFAULT_PROFILE = dogtag.DEFAULT_PROFILE

    def __init__(self, api):
        super(ra, self).__init__(api)
        self.client = None

    def get_client(self):
        port = self.override_port or "443"
        pki_client = pki.client.PKIClient(
            url=f'https://{self.ca_host}:{port}', ca_bundle=self.ca_cert)
        pki_client = support_v2(pki_client)
        pki_client.set_client_auth(
            client_cert=paths.RA_AGENT_PEM,
            client_key=paths.RA_AGENT_KEY)
        ca_client = pki.ca.CAClient(pki_client)
        client = pki.cert.CertClient(ca_client)
        object.__setattr__(self, 'client', client)

    def raise_certificate_operation_error(
        self, func_name, err_msg=None, detail=None
    ):
        """
        :param func_name: function name where error occurred

        :param err_msg:   diagnostic error message, if not supplied it will be
                          'Unable to communicate with CMS'
        :param detail:    extra information that will be appended to err_msg
                          inside a parenthesis. This may be an HTTP status msg

        Raise a CertificateOperationError and log the error message.
        """

        if err_msg is None:
            err_msg = _('Unable to communicate with CMS')

        if detail is not None:
            err_msg = '%s (%s)' % (err_msg, detail)

        logger.error('%s.%s(): %s', type(self).__name__, func_name, err_msg)
        if detail == 404:
            raise errors.NotFound(reason=err_msg)
        raise errors.CertificateOperationError(error=err_msg)

    def check_request_status(self, request_id):
        """
        :param request_id: request ID

        Check status of a certificate signing request.

        The command returns a pki.cert.CertRequestInfo object with
        these attributes we care about.

        Some values may not be present based on the status.

        The function returns a simple dictionary consisting of:
        +-------------------+---------------+---------------+
        |result name        |result type    |comments       |
        +===================+===============+===============+
        |serial_number      |str [1]_       |               |
        +-------------------+---------------+---------------+
        |request_id         |str [1]_       |               |
        +-------------------+---------------+---------------+
        |cert_request_status|str [2]_       |               |
        +-------------------+---------------+---------------+
        |request_type       |str [3]_       |               |
        +-------------------+---------------+---------------+

        .. [1] The certID and requestId values are returned as
               string hex regardless of what the request contains.
               They are converted to decimal in the return value.

        .. [2] request_status may be one of:

               - "begin"
               - "pending"
               - "approved"
               - "svc_pending"
               - "canceled"
               - "rejected"
               - "complete"

        .. [3] request_type is not necessarily an enrollment request.
               If can, for example, be a revocation request. We don't
               limit that here. It is the caller's responsibility.
        """
        logger.debug('%s.check_request_status()', type(self).__name__)

        # Convert serial number to integral type from string to properly handle
        # radix issues. Note: the int object constructor will properly handle
        # large magnitude integral values by returning a Python long type when
        # necessary.
        request_id = int(request_id, 0)

        self.get_client()
        try:
            with log_level_override():
                request = self.client.get_request(request_id)
        except pki.RequestNotFoundException:
            raise errors.NotFound(
                reason="Request ID %s not found" % hex(request_id))
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise errors.NotFound(
                    reason="Request ID %s not found" % hex(request_id))
            else:
                self.raise_certificate_operation_error(
                    'check_request_status',
                    err_msg=e.args[0],
                    detail=e.response.status_code
                )

        if request.operation_result != "success":
            self.raise_certificate_operation_error(
                'check_request_status',
                request.operation_result,
                request.error_message)

        # reformat the response to what IPA expects
        cmd_result = {}
        if request.cert_id:  # the cert may not have been issued
            cmd_result['serial_number'] = int(request.cert_id, 16)
        cmd_result['request_id'] = int(request.request_id)
        cmd_result['cert_request_status'] = request.request_status
        cmd_result['request_type'] = request.request_type

        return cmd_result

    def get_certificate(self, serial_number):
        """
        Retrieve an existing certificate.

        :param serial_number: Certificate serial number.  May be int,
                              decimal string, or hex string with "0x"
                              prefix.


        The call returns a pki.cert.CertData object with the
        following attributes we care about:

        Some key/value pairs may be absent. Not all available attributes
        display by default due to overridden __repr__.


        The function returns a simple dictionary consisting of:
        +-----------------+---------------+---------------+
        |result name      |result type    |comments       |
        +=================+===============+===============+
        |certificate      |str [1]_       |               |
        +-----------------+---------------+---------------+
        |serial_number    |str [2]_       |               |
        +-----------------+---------------+---------------+
        |serial_number_hex|str [2]_       |               |
        +-----------------+---------------+---------------+
        |revocation_reason|int [3]_       |               |
        +-----------------+---------------+---------------+

        .. [1] PEM-encoded string

        .. [2] Always a string hex value.

        .. [3] revocation reason may be one of:

               - 0 = UNSPECIFIED
               - 1 = KEY_COMPROMISE
               - 2 = CA_COMPROMISE
               - 3 = AFFILIATION_CHANGED
               - 4 = SUPERSEDED
               - 5 = CESSATION_OF_OPERATION
               - 6 = CERTIFICATE_HOLD
               - 8 = REMOVE_FROM_CRL
               - 9 = PRIVILEGE_WITHDRAWN
               - 10 = AA_COMPROMISE

        """
        logger.debug('%s.get_certificate()', type(self).__name__)
        if isinstance(serial_number, str):
            serial_number = int(serial_number, 0)

        self.get_client()
        try:
            with log_level_override():
                cert = self.client.get_cert(serial_number)
        except pki.CertNotFoundException:
            raise errors.NotFound(
                reason="Certificate ID %s not found" % hex(serial_number))
        except Exception as e:
            logger.debug("%s", e)
            self.raise_certificate_operation_error(
                'get_certificate',
                detail="Failed to retrieve certificate: %s" % e
            )

        # Return command result
        cmd_result = {}

        s = cert.encoded
        # The 'cert' plugin expects the result to be base64-encoded
        # X.509 DER. PKI returns the cert as PEM. We have to
        # strip the PEM headers and we use PEM_CERT_REGEX to do it.
        match = x509.PEM_CERT_REGEX.search(s.encode('utf-8'))
        if match:
            s = match.group(2).decode('utf-8')
        cmd_result['certificate'] = s.strip()

        hex_value = cert.serial_number[2:]
        cmd_result['serial_number'] = int(hex_value, 16)
        cmd_result['serial_number_hex'] = cert.serial_number

        if hasattr(cert, 'RevocationReason'):
            cmd_result['revocation_reason'] = cert.RevocationReason

        return cmd_result

    def request_certificate(
            self, csr, profile_id, ca_id, request_type='pkcs10'):
        """
        :param csr: The certificate signing request.
        :param profile_id: The profile to use for the request.
        :param ca_id: The Authority ID to send request to. ``None`` is allowed.
        :param request_type: The request type (defaults to ``'pkcs10'``).

        Submit certificate signing request.

        The command returns a list of pki.cert.CertEnrollmentResult objects
        with the following attributes we care about:

        Some key/value pairs may be absent. Not all available attributes
        display by default due to overridden __repr__.

        For our purposes we only handle one CSR at a time so only
        examine the first request.

        The function returns a simple dictionary consisting of:
        +-----------------+---------------+---------------+
        |result name      |result type    |comments       |
        +=================+===============+===============+
        |certificate      |str [1]_       |               |
        +-----------------+---------------+---------------+
        |request_id       |str [2]_       |               |
        +-----------------+---------------+---------------+

        .. [1] base64-encoded value of the certificate

        .. [2] The request_id

        """
        logger.debug('%s.request_certificate()', type(self).__name__)

        inputs = dict()
        inputs['cert_request_type'] = 'pkcs10'
        inputs['cert_request'] = csr

        self.get_client()
        try:
            with log_level_override():
                result = self.client.enroll_cert(profile_id, inputs, ca_id)
        except pki.PKIException as e:
            raise errors.CertificateOperationError(error=e.message)
        except Exception as e:
            raise errors.CertificateOperationError(error=e)

        if len(result) != 1:
            raise errors.CertificateOperationError(
                error="Expected one certificate and got %d" % len(result))
        result = result[0]

        request_data = result.request
        if request_data.request_status != CertRequestStatus.COMPLETE:
            raise errors.CertificateOperationError(
                error=request_data.error_message)
        s = result.cert.encoded
        match = x509.PEM_CERT_REGEX.search(s.encode('utf-8'))
        if match:
            s = match.group(2).decode('utf-8')

        cmd_result = {}
        cmd_result['certificate'] = ''.join(s.splitlines())
        cmd_result['request_id'] = result.request.request_id
        cmd_result['cert_request_status'] = result.request.request_status

        return cmd_result

    def get_pki_version(self):
        """
        Retrieve the version of a remote PKI server.

        Returns a version string like "11.6.0"
        """
        port = self.override_port or "443"
        pki_client = pki.client.PKIClient(
            url=f'https://{self.ca_host}:{port}', ca_bundle=self.ca_cert)
        info_client = pki.info.InfoClient(pki_client)

        try:
            with log_level_override():
                pki_version = str(info_client.get_version())
        except Exception as e:
            self.raise_certificate_operation_error('get_pki_version',
                                                   detail=e)

        return pki_version

    def revoke_certificate(self, serial_number, revocation_reason=0):
        """
        :param serial_number: Certificate serial number. Must be a string value
                              because serial numbers may be of any magnitude
                              The string value should be decimal, but may
                              optionally be prefixed with a hex radix prefix
                              if the integral value is represented as
                              hexadecimal. If no radix prefix is supplied
                              the string will be interpreted as decimal.
        :param revocation_reason: Integer code of revocation reason.

        Revoke a certificate.

        The command returns a CertRequestInfo object. This is used to
        confirm that the revocation was successful.

        The function returns a simple dictionary consisting of:
        +---------------+---------------+---------------+
        |result name    |result type    |comments       |
        +---------------+---------------+---------------+
        |revoked        |bool           |               |
        +---------------+---------------+---------------+
        """
        reasons = ["Unspecified",
                   "Key_Compromise",
                   "CA_Compromise",
                   "Affiliation_Changed",
                   "Superseded",
                   "Cessation_of_Operation",
                   "Certificate_Hold",
                   "NOTUSED",  # value 7 is not used
                   "Remove_from_CRL",
                   "Privilege_Withdrawn",
                   "AA_Compromise"]

        logger.debug('%s.revoke_certificate()', type(self).__name__)
        if type(revocation_reason) is not int:
            raise TypeError(TYPE_ERROR % ('revocation_reason', int, revocation_reason, type(revocation_reason)))

        if revocation_reason == 7:
            self.raise_certificate_operation_error(
                'revoke_certificate',
                detail='7 is not a valid revocation reason'
            )

        self.get_client()
        try:
            with log_level_override():
                result = self.client.revoke_cert(
                    serial_number,
                    revocation_reason=reasons[revocation_reason]
                )
        except pki.BadRequestException as e:
            # for some reason PKI returns with a # instead of a a hex:
            # certificate #f5aa3399f725feb... has already been revoked
            message = e.message.replace('#', '0x')
            self.raise_certificate_operation_error('revoke_certificate',
                                                   detail=message)
        except Exception as e:
            self.raise_certificate_operation_error('revoke_certificate',
                                                   detail=str(e))

        request_status = result.operation_result
        if request_status != 'success':
            self.raise_certificate_operation_error(
                'revoke_certificate',
                request_status,
                result.error_message
            )

        # Return command result
        cmd_result = {}

        # We can assume the revocation was successful because if it failed
        # then REST will return a non-200 or operationalResult will not
        # be 'success'.
        cmd_result['revoked'] = True

        return cmd_result

    def take_certificate_off_hold(self, serial_number):
        """
        :param serial_number: Certificate serial number. Must be a string value
                              because serial numbers may be of any magnitude.
                              The string value should be decimal, but
                              may optionally be prefixed with a hex radix
                              prefix if the integral value is represented as
                              hexadecimal. If no radix prefix is supplied
                              the string will be interpreted as decimal.

        Take revoked certificate off hold.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +---------------+---------------+---------------+
        |result name    |result type    |comments       |
        +===============+===============+===============+
        |unrevoked      |boolean        |               |
        +---------------+---------------+---------------+
        |error_string   |str            |               |
        +---------------+---------------+---------------+
        """

        logger.debug('%s.take_certificate_off_hold()', type(self).__name__)

        # Convert serial number to integral type from string to properly handle
        # radix issues. Note: the int object constructor will properly handle
        # large magnitude integral values by returning a Python long type when
        # necessary.
        serial_number = int(serial_number, 0)

        self.get_client()
        try:
            with log_level_override():
                result = self.client.unrevoke_cert(serial_number)
        except pki.CertNotFoundException:
            raise errors.NotFound(
                reason="Certificate ID %s not found" % hex(serial_number))
        except Exception as e:
            self.raise_certificate_operation_error(
                'take_certificate_off_hold',
                e)

        request_status = result.operation_result
        if request_status != 'success':
            self.raise_certificate_operation_error(
                'take_certificate_off_hold',
                result.error_message
            )

        # Return command result
        cmd_result = {}

        if result.error_message:
            cmd_result['error_string'] = result.error_message

        # We can assume the un-revocation was successful because if it failed
        # then REST will return a non-200 or operationalResult will not
        # be 'success'.
        cmd_result['unrevoked'] = True

        return cmd_result

    def find(self, options):
        """
        Search for certificates

        :param options: dictionary of search options
        """

        def convert_time(value):
            """
            Convert time to milliseconds to pass to dogtag
            """
            ts = time.strptime(value, '%Y-%m-%d')
            return int(time.mktime(ts) * 1000)

        logger.debug('%s.find()', type(self).__name__)

        cert_search_request = dict()

        # option_types is a tuple that consists of:
        #   1. attribute name passed from IPA API
        #   2. attribute name used by PKI python API

        option_types = (
            ('exactly', 'match_exactly'),
            ('subject', 'common_name'),
            ('issuer', 'issued_by'),
            ('revocation_reason', 'revocation_reason'),
            ('min_serial_number', 'serial_from'),
            ('max_serial_number', 'serial_to'),
            ('status', 'status'),
        )

        for (attr, dattr) in option_types:
            if attr in options:
                cert_search_request[dattr] = options[attr]

        # date_types is a tuple that consists of:
        #   1. attribute name passed from IPA API
        #   2. attribute name used by PKI python API
        #   the date value is converted to a form that PKI wants

        date_types = (
            ('validnotbefore_from', 'valid_not_before_from'),
            ('validnotbefore_to', 'valid_not_before_to'),
            ('validnotafter_from', 'valid_not_after_from'),
            ('validnotafter_to', 'valid_not_after_to'),
            ('issuedon_from', 'issued_on_from'),
            ('issuedon_to', 'issued_on_to'),
            ('revokedon_from', 'revoked_on_from'),
            ('revokedon_to', 'revoked_on_to'),
        )

        for (attr, dattr) in date_types:
            if attr in options:
                epoch = convert_time(options[attr])
                cert_search_request[dattr] = str(epoch)

        payload = json.dumps(cert_search_request, sort_keys=True)
        logger.debug('%s.find(): request: %s', type(self).__name__, payload)

        self.get_client()
        sizelimit = options.get('sizelimit', 0)
        if sizelimit == 0:
            sizelimit = 0x7fffffff
        try:
            with log_level_override():
                result = self.client.list_certs(
                    size=sizelimit,
                    **cert_search_request
                )
        except Exception as e:
            self.raise_certificate_operation_error(
                'find',
                err_msg=str(e))

        # Grab all the certificates
        certs = result.cert_data_info_list

        results = []

        for cert in certs:
            response_request = {}
            response_request['serial_number'] = int(cert.serial_number, 16)
            response_request["serial_number_hex"] = (cert.serial_number)
            response_request['subject'] = cert.subject_dn
            response_request['issuer'] = cert.issuer_dn
            response_request['valid_not_before'] = cert.not_valid_before
            response_request['valid_not_after'] = cert.not_valid_after
            response_request['status'] = cert.status
            results.append(response_request)

        return results

    def updateCRL(self, wait='false'):
        """
        Force update of the CRL

        :param wait: if true, the call will be synchronous and return only
                     when the CRL has been generated
        """
        def _sslget(url, port, **kw):
            """
            :param url: The URL to post to.
            :param kw:  Keyword arguments to encode into POST body.
            :return:   (http_status, http_headers, http_body)
                       as (integer, dict, str)

            Perform an HTTPS request
            """
            return dogtag.https_request(
                self.ca_host, port, url,
                cafile=self.ca_cert,
                client_certfile=self.client_certfile,
                client_keyfile=self.client_keyfile,
                **kw)

        def get_parse_result_xml(xml_text, parse_func):
            '''
            :param xml_text:   The XML text to parse
            :param parse_func: The XML parsing function to apply to the
                               parsed DOM tree.
            :return:           parsed result dict

            Utility routine which parses the input text into an XML DOM tree
            and then invokes the parsing function on the DOM tree in order
            to get the parsing result as a dict of key/value pairs.
            '''
            parser = etree.XMLParser()
            try:
                doc = etree.fromstring(xml_text, parser)
            except etree.XMLSyntaxError as e:
                self.raise_certificate_operation_error(
                    'get_parse_result_xml',
                    detail=str(e))
            result = parse_func(doc)

            logger.debug(
                "%s() xml_text:\n%r\nparse_result:\n%r",
                parse_func.__name__, xml_text, result)
            return result

        logger.debug('%s.updateCRL()', type(self).__name__)
        # Call CMS
        http_status, _http_headers, http_body = (
            _sslget('/ca/agent/ca/updateCRL',
                    self.override_port or 443,
                    crlIssuingPoint='MasterCRL',
                    waitForUpdate=wait,
                    xml='true')
        )

        # Parse and handle errors
        if http_status != 200:
            self.raise_certificate_operation_error('updateCRL',
                                                   detail=http_status)

        parse_result = get_parse_result_xml(http_body,
                                            parse_updateCRL_xml)
        request_status = parse_result['request_status']
        if request_status != CMS_STATUS_SUCCESS:
            self.raise_certificate_operation_error(
                'updateCRL',
                cms_request_status_to_string(request_status),
                parse_result.get('error_string'))

        # Return command result
        cmd_result = {}

        if 'crl_issuing_point' in parse_result:
            cmd_result['crlIssuingPoint'] = parse_result['crl_issuing_point']
        if 'crl_update' in parse_result:
            cmd_result['crlUpdate'] = parse_result['crl_update']

        return cmd_result


# ----------------------------------------------------------------------------
@register()
class kra(Backend):
    """
    KRA backend plugin (for Vault)
    """

    def __init__(self, api, kra_port=443):
        self.kra_port = kra_port
        super(kra, self).__init__(api)

    @property
    def kra_host(self):
        """
        :return:   host
                   as str

        Select our KRA host.
        """
        preferred = [api.env.ca_host]
        if api.env.host != api.env.ca_host:
            preferred.append(api.env.host)

        kra_host = find_providing_server(
            'KRA', self.api.Backend.ldap2, preferred_hosts=preferred,
            api=self.api
        )
        if kra_host is None:
            # TODO: need during installation, KRA is not yet set as enabled
            kra_host = api.env.ca_host
        return kra_host

    @contextlib.contextmanager
    def get_client(self):
        """
        Returns an authenticated KRA client to access KRA services.

        Raises a generic exception if KRA is not enabled.
        """

        if not self.api.Command.kra_is_enabled()['result']:
            # TODO: replace this with a more specific exception
            raise RuntimeError('KRA service is not enabled')

        crypto = cryptoutil.CryptographyCryptoProvider(
            transport_cert_nick="ra_agent",
            transport_cert=x509.load_certificate_from_file(
                paths.RA_AGENT_PEM).cert
        )

        # TODO: obtain KRA host & port from IPA service list or point to KRA load balancer
        # https://fedorahosted.org/freeipa/ticket/4557
        pki_client = pki.client.PKIClient(
            url=f'https://{self.kra_host}:{self.kra_port}',
            ca_bundle=paths.IPA_CA_CRT)
        pki_client = support_v2(pki_client)
        pki_client.set_client_auth(
            client_cert=paths.RA_AGENT_PEM,
            client_key=paths.RA_AGENT_KEY)
        yield KRAClient(pki_client.connection, crypto)


@register()
class ra_certprofile(APIClient):
    """
    Profile management backend plugin.
    """
    def __enter__(self):
        super().__enter__()
        sub_client = pki.subsystem.SubsystemClient(self.pki_client, 'ca')
        client = pki.profile.ProfileClient(sub_client)
        object.__setattr__(self, 'client', client)

        return self

    def create_profile(self, profile_data):
        """
        Import the profile into Dogtag
        """
        try:
            self.client.create_profile(profile_data, raw=True)
        except pki.ConflictingOperationException as e:
            # profile exists
            raise errors.RemoteRetrieveError(reason=str(e))
        except Exception as e:
            self.raise_certificate_operation_exception(
                'create_profile', e)

    def read_profile(self, profile_id):
        """
        Read the profile configuration from Dogtag
        """
        try:
            profile = self.client.get_profile(profile_id, raw=True)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'read_profile', e)
        return profile.encode("utf-8")

    def update_profile(self, profile_id, profile_data):
        """
        Update the profile configuration in Dogtag
        """
        try:
            self.client.modify_profile(profile_data, profile_id=profile_id,
                                       raw=True)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'update_profile', e)

    def enable_profile(self, profile_id):
        """
        Enable the profile in Dogtag
        """
        try:
            self.client.enable_profile(profile_id)
        except pki.ConflictingOperationException as e:
            raise errors.RemoteRetrieveError(reason=str(e))
        except Exception as e:
            self.raise_certificate_operation_exception(
                'enable_profile', e)

    def disable_profile(self, profile_id):
        """
        Enable the profile in Dogtag
        """
        try:
            self.client.disable_profile(profile_id)
        except pki.ConflictingOperationException as e:
            raise errors.RemoteRetrieveError(reason=str(e))
        except Exception as e:
            self.raise_certificate_operation_exception(
                'disable_profile', e)

    def delete_profile(self, profile_id):
        """
        Delete the profile from Dogtag
        """
        try:
            self.client.delete_profile(profile_id)
        except pki.ProfileNotFoundException:
            raise errors.NotFound(
                reason="Profile ID %s not found" % profile_id)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'delete_profile', e)

    def list_profiles(self):
        profiles = self.client.list_profiles()

        results = []
        for profile in profiles:
            response = {}
            response['profile_id'] = profile.profile_id
            response['profile_name'] = profile.profile_name
            response['profile_enabled'] = str(profile.profileEnable)
            results.append(response)

        return results


@register()
class ra_lightweight_ca(APIClient):
    """
    Lightweight CA management backend plugin.
    """
    def __enter__(self):
        super().__enter__()
        sub_client = pki.subsystem.SubsystemClient(self.pki_client, 'ca')
        client = pki.authority.AuthorityClient(sub_client)
        object.__setattr__(self, 'client', client)

        return self

    def create_ca(self, dn):
        """Create CA with the given DN.

        New CA is issued by IPA CA.  Nested sub-CAs and unrelated
        root CAs are not yet supported.

        Return the (parsed) JSON response from server.

        """
        assert isinstance(dn, DN)

        host_ca = None
        authorities = self.client.list_cas()
        for ca in authorities.ca_list:
            if ca.is_host_authority:
                host_ca = ca
                break

        if not host_ca:
            logger.debug('No host ca found')
            raise errors.NotFound(
                reason=("No host ca found")
            )

        authority_data = {
            'dn': str(dn),
            'description': str(dn),
            'parent_aid': host_ca.aid
        }
        data = pki.authority.AuthorityData(**authority_data)

        try:
            subca = self.client.create_ca(data)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'create_ca', e)

        newca = self.client.get_ca(subca.aid)
        response = dict()
        response['id'] = subca.aid
        response['issuerDN'] = host_ca.dn
        response['dn'] = newca.dn
        return response

    def read_ca(self, ca_id):
        try:
            subca = self.client.get_ca(ca_id)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'read_ca', e)

        # reformat the response to what IPA expects
        response = dict()
        response['id'] = subca.aid
        # Note that issuerDN is not present in the __repr__ class
        response['issuerDN'] = subca.issuerDN  # pylint: disable=no-member
        response['dn'] = subca.dn
        response['enabled'] = subca.enabled

        return response

    def read_ca_cert(self, ca_id):
        try:
            subca = self.client.get_ca(ca_id)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'read_ca_cert', e)
        try:
            cert = self.client.get_cert(subca.aid, "PEM")
        except Exception as e:
            self.raise_certificate_operation_exception(
                'read_ca_cert', e)
        c = x509.load_pem_x509_certificate(cert.encode("utf-8"))
        return c.public_bytes(x509.Encoding.DER)

    def read_ca_chain(self, ca_id):
        try:
            subca = self.client.get_ca(ca_id)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'read_ca_chain', e)
        # The PKCS7 format from PKI doesn't seem to be correct. So
        # retrieve it as PEM and decode it into DER here instead.
        try:
            chain = self.client.get_chain(subca.aid, "PEM")
        except Exception as e:
            self.raise_certificate_operation_exception(
                'read_ca_chain', e)
        chain = chain.replace(r"----BEGIN PKCS7----", "")
        chain = chain.replace(r"----END PKCS7----", "")
        chain = base64.b64decode(chain)
        return chain

    def disable_ca(self, ca_id):
        try:
            subca = self.client.get_ca(ca_id)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'disable_ca', e)

        try:
            self.client.disable_ca(subca.aid)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'disable_ca', e)

    def enable_ca(self, ca_id):
        try:
            subca = self.client.get_ca(ca_id)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'enable_ca', e)

        try:
            self.client.enable_ca(subca.aid)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'enable_ca', e)

    def delete_ca(self, ca_id):
        try:
            subca = self.client.get_ca(ca_id)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'enable_ca', e)
        try:
            self.client.delete_ca(subca.aid)
        except Exception as e:
            self.raise_certificate_operation_exception(
                'enable_ca', e)


@register()
class ra_securitydomain(APIClient):
    """
    Security domain management backend plugin.

    Dogtag handles the creation of securitydomain entries
    we need to clean them up when an IPA server is removed.
    """
    def __enter__(self):
        super().__enter__()
        sub_client = pki.subsystem.SubsystemClient(self.pki_client, 'ca')
        self.client = pki.system.SecurityDomainClient(sub_client)

        return self

    def delete_domain(self, hostname, type):
        """
        Delete a security domain
        """
        self.client.remove_host(hostname, type.lower(), '443')
