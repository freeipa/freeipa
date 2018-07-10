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

'''

==============================================
Backend plugin for RA using Dogtag (e.g. CMS)
==============================================

Overview of interacting with CMS:
---------------------------------

CMS stands for "Certificate Management System". It has been released under a
variety of names, the open source version is called "dogtag".

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

CMS results can be parsed from either HTML or XML. CMS unfortunately is not
consistent with how it names items or how it utilizes data types. IPA has strict
rules about data types. Also IPA would like to see a more consistent view CMS
data. Therefore we split the task of parsing CMS results out from the IPA
command code. The parse functions normalize the result data by using a
consistent set of names and data types. The IPA command only deals with the
normalized parse results. This also allow us to use different parsers if need be
(i.e. if we had to parse Javascript for some reason). The parse functions
attempt to parse as must information from the CMS result as is possible. It puts
the parse result into a dict whose normalized key/value pairs are easy to
access. IPA commands do not need to return all the parsed results, it can pick
and choose what it wants to return in the IPA command result from the parse
result. It also rest assured the values in the parse result will be the correct
data type. Thus the general sequence of steps for an IPA command talking to CMS
are:

#. Receive IPA arguments from IPA command
#. Formulate URL with arguments for CMS
#. Make request to CMS server
#. Extract XML document from HTML body returned by CMS
#. Parse XML document using matching parse routine which returns response dict
#. Extract relevant items from parse result and insert into command result
#. Return command result

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

2. Big integers passed to XMLRPC must be decimal unicode strings

       unicode(serial_number)

3. Big integers received from XMLRPC must be converted back to int or long
   objects from the decimal string representation.

       serial_number = int(serial_number)

Xpath pattern matching on node names:
-------------------------------------

There are many excellent tutorial on how to use xpath to find items in an XML
document, as such there is no need to repeat this information here. However,
most xpath tutorials make the assumption the node names you're searching for are
fixed. For example:

    doc.xpath('//book/chapter[*]/section[2]')

Selects the second section of every chapter of the book. In this example the
node names 'book', 'chapter', 'section' are fixed. But what if the XML document
embedded the chapter number in the node name, for example 'chapter1',
'chapter2', etc.? (If you're thinking this would be incredibly lame, you're
right, but sadly people do things like this). Thus in this case you can't use
the node name 'chapter' in the xpath location step because it's not fixed and
hence won't match 'chapter1', 'chapter2', etc. The solution to this seems
obvious, use some type of pattern matching on the node name. Unfortunately this
advanced use of xpath is seldom discussed in tutorials and it's not obvious how
to do it. Here are some hints.

Use the built-in xpath string functions. Most of the examples illustrate the
string function being passed the text *contents* of the node via '.' or
string(.). However we don't want to pass the contents of the node, instead we
want to pass the node name. To do this use the name() function. One way we could
solve the chapter problem above is by using a predicate which says if the node
name begins with 'chapter' it's a match. Here is how you can do that.

        doc.xpath("//book/*[starts-with(name(), 'chapter')]/section[2]")

The built-in starts-with() returns true if its first argument starts with its
second argument. Thus the example above says if the node name of the second
location step begins with 'chapter' consider it a match and the search
proceeds to the next location step, which in this example is any node named
'section'.

But what if we would like to utilize the power of regular expressions to perform
the test against the node name? In this case we can use the EXSLT regular
expression extension. EXSLT extensions are accessed by using XML
namespaces. The regular expression name space identifier is 're:' In lxml we
need to pass a set of namespaces to XPath object constructor in order to allow
it to bind to those namespaces during its evaluation. Then we just use the
EXSLT regular expression match() function on the node name. Here is how this is
done:

        regexpNS = "http://exslt.org/regular-expressions"
        find = etree.XPath("//book/*[re:match(name(), '^chapter(_\d+)$')]/section[2]",
                           namespaces={'re':regexpNS}
        find(doc)

What is happening here is that etree.XPath() has returned us an evaluator
function which we bind to the name 'find'. We've passed it a set of namespaces
as a dict via the 'namespaces' keyword parameter of etree.XPath(). The predicate
for the second location step uses the 're:' namespace to find the function name
'match'. The re:match() takes a string to search as its first argument and a
regular expression pattern as its second argument. In this example the string
to search is the node name of the location step because we called the built-in
node() function of XPath. The regular expression pattern we've passed says it's
a match if the string begins with 'chapter' is followed by any number of
digits and nothing else follows.

'''

from __future__ import absolute_import

import datetime
import json
import logging

from lxml import etree
import time
import contextlib

import six

from ipalib import Backend, api
from ipapython.dn import DN
import ipapython.cookie
from ipapython import dogtag, ipautil, certdb

if api.env.in_server:
    import pki
    from pki.client import PKIConnection
    import pki.crypto as cryptoutil
    from pki.kra import KRAClient

if six.PY3:
    unicode = str

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

def cms_error_code_to_string(error_code):
    '''
    :param error_code: The integral error code value
    :return:           String name of the error code
    '''
    return {
    0 : 'SUCCESS',
    1 : 'FAILURE',
    2 : 'AUTH_FAILURE',
    }.get(error_code, "unknown(%d)" % error_code)

def parse_and_set_boolean_xml(node, response, response_name):
    '''
    :param node:          xml node object containing value to parse for boolean result
    :param response:      response dict to set boolean result in
    :param response_name: name of the response value to set
    :except ValueError:

    Read the value out of a xml text node and interpret it as a boolean value.
    The text values are stripped of whitespace and converted to lower case
    prior to interpretation.

    If the value is recognized the response dict is updated using the
    request_name as the key and the value is set to the bool value of either
    True or False depending on the interpretation of the text value. If the text
    value is not recognized a ValueError exception is thrown.

    Text values which result in True:

    - true
    - yes
    - on

    Text values which result in False:

    - false
    - no
    - off
    '''
    value = node.text.strip().lower()
    if value == 'true' or value == 'yes':
        value = True
    elif value == 'false' or value == 'no':
        value = False
    else:
        raise ValueError('expected true|false|yes|no|on|off for "%s", but got "%s"' % \
                             (response_name, value))
    response[response_name] = value

def get_error_code_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   error code as an integer or None if not found

    Returns the error code when the servlet replied with
    CMSServlet.outputError()

    The possible error code values are:

    - CMS_SUCCESS      = 0
    - CMS_FAILURE      = 1
    - CMS_AUTH_FAILURE = 2

    However, profileSubmit sometimes also returns these values:

    - EXCEPTION = 1
    - DEFERRED  = 2
    - REJECTED  = 3

    '''

    error_code = doc.xpath('//XMLResponse/Status[1]')
    if len(error_code) == 1:
        error_code =  int(error_code[0].text)
    else:
        # If error code wasn't present, but error string was
        # then it's an error.
        error_string = doc.xpath('//XMLResponse/Error[1]')
        if len(error_string) == 1:
            error_code = CMS_FAILURE
        else:
            # no status and no error string, assume success
            error_code = CMS_SUCCESS

    return error_code

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
    |errorDetails    |string         |error_string [1]_ |unicode        |
    +----------------+---------------+------------------+---------------+
    |unexpectedError |string         |error_string [1]_ |unicode        |
    +----------------+---------------+------------------+---------------+
    |errorDescription|[string]       |error_descriptions|[unicode]      |
    +----------------+---------------+------------------+---------------+
    |authority       |string         |authority         |unicode        |
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
                                                 encoding=unicode).strip())
    if len(error_descriptions) > 0:
        response['error_descriptions'] = error_descriptions

    authority = doc.xpath('//xml/fixed/authorityName[1]')
    if len(authority) == 1:
        authority = etree.tostring(authority[0], method='text',
                                   encoding=unicode).strip()
        response['authority'] = authority

    # Should never get both errorDetail and unexpectedError
    error_detail = doc.xpath('//xml/fixed/errorDetails[1]')
    if len(error_detail) == 1:
        error_detail = etree.tostring(error_detail[0], method='text',
                                      encoding=unicode).strip()
        response['error_string'] = error_detail

    unexpected_error = doc.xpath('//xml/fixed/unexpectedError[1]')
    if len(unexpected_error) == 1:
        unexpected_error = etree.tostring(unexpected_error[0], method='text',
                                          encoding=unicode).strip()
        response['error_string'] = unexpected_error

    return response


def parse_error_response_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict

    CMS currently returns errors via XML as either a "template" document
    (generated by CMSServlet.outputXML() or a "response" document (generated by
    CMSServlet.outputError()).

    This routine is used to parse a "response" style error document.

    +---------------+---------------+---------------+---------------+
    |cms name       |cms type       |result name    |result type    |
    +===============+===============+===============+===============+
    |Status         |int            |error_code     |int [1]_       |
    +---------------+---------------+---------------+---------------+
    |Error          |string         |error_string   |unicode        |
    +---------------+---------------+---------------+---------------+
    |RequestID      |string         |request_id     |string         |
    +---------------+---------------+---------------+---------------+

    .. [1] error code may be one of:

           - CMS_SUCCESS      = 0
           - CMS_FAILURE      = 1
           - CMS_AUTH_FAILURE = 2

           However, profileSubmit sometimes also returns these values:

           - EXCEPTION = 1
           - DEFERRED  = 2
           - REJECTED  = 3

    '''

    response = {}
    response['error_code'] = CMS_FAILURE # assume error

    error_code = doc.xpath('//XMLResponse/Status[1]')
    if len(error_code) == 1:
        error_code = int(error_code[0].text)
        response['error_code'] = error_code

    error_string = doc.xpath('//XMLResponse/Error[1]')
    if len(error_string) == 1:
        error_string = etree.tostring(error_string[0], method='text',
                                      encoding=unicode).strip()
        response['error_string'] = error_string

    request_id = doc.xpath('//XMLResponse/RequestId[1]')
    if len(request_id) == 1:
        request_id = etree.tostring(request_id[0], method='text',
                                    encoding=unicode).strip()
        response['request_id'] = request_id

    return response


def parse_check_request_result_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    If the requestStatus is not SUCCESS then the response dict will have the
    contents described in `parse_error_template_xml`.

    +-------------------------+---------------+-------------------+-----------------+
    |cms name                 |cms type       |result name        |result type      |
    +=========================+===============+===================+=================+
    |authority                |string         |authority          |unicode          |
    +-------------------------+---------------+-------------------+-----------------+
    |requestId                |string         |request_id         |string           |
    +-------------------------+---------------+-------------------+-----------------+
    |status                   |string         |cert_request_status|unicode [1]_     |
    +-------------------------+---------------+-------------------+-----------------+
    |createdOn                |long, timestamp|created_on         |datetime.datetime|
    +-------------------------+---------------+-------------------+-----------------+
    |updatedOn                |long, timestamp|updated_on         |datetime.datetime|
    +-------------------------+---------------+-------------------+-----------------+
    |requestNotes             |string         |request_notes      |unicode          |
    +-------------------------+---------------+-------------------+-----------------+
    |pkcs7ChainBase64         |string         |pkcs7_chain        |unicode [2]_     |
    +-------------------------+---------------+-------------------+-----------------+
    |cmcFullEnrollmentResponse|string         |full_response      |unicode [2]_     |
    +-------------------------+---------------+-------------------+-----------------+
    |records[].serialNumber   |BigInteger     |serial_numbers     |[int|long]       |
    +-------------------------+---------------+-------------------+-----------------+

    .. [1] cert_request_status may be one of:

           - "begin"
           - "pending"
           - "approved"
           - "svc_pending"
           - "canceled"
           - "rejected"
           - "complete"

    .. [2] Base64 encoded

    '''
    request_status = get_request_status_xml(doc)

    if request_status != CMS_STATUS_SUCCESS:
        response = parse_error_template_xml(doc)
        return response

    response = {}
    response['request_status'] = request_status

    cert_request_status = doc.xpath('//xml/header/status[1]')
    if len(cert_request_status) == 1:
        cert_request_status = etree.tostring(cert_request_status[0], method='text',
                                             encoding=unicode).strip()
        response['cert_request_status'] = cert_request_status

    request_id = doc.xpath('//xml/header/requestId[1]')
    if len(request_id) == 1:
        request_id = etree.tostring(request_id[0], method='text',
                                    encoding=unicode).strip()
        response['request_id'] = request_id

    authority = doc.xpath('//xml/header/authority[1]')
    if len(authority) == 1:
        authority = etree.tostring(authority[0], method='text',
                                   encoding=unicode).strip()
        response['authority'] = authority

    updated_on = doc.xpath('//xml/header/updatedOn[1]')
    if len(updated_on) == 1:
        updated_on = datetime.datetime.utcfromtimestamp(int(updated_on[0].text))
        response['updated_on'] = updated_on

    created_on = doc.xpath('//xml/header/createdOn[1]')
    if len(created_on) == 1:
        created_on = datetime.datetime.utcfromtimestamp(int(created_on[0].text))
        response['created_on'] = created_on

    request_notes = doc.xpath('//xml/header/requestNotes[1]')
    if len(request_notes) == 1:
        request_notes = etree.tostring(request_notes[0], method='text',
                                       encoding=unicode).strip()
        response['request_notes'] = request_notes

    pkcs7_chain = doc.xpath('//xml/header/pkcs7ChainBase64[1]')
    if len(pkcs7_chain) == 1:
        pkcs7_chain = etree.tostring(pkcs7_chain[0], method='text',
                                     encoding=unicode).strip()
        response['pkcs7_chain'] = pkcs7_chain

    full_response = doc.xpath('//xml/header/cmcFullEnrollmentResponse[1]')
    if len(full_response) == 1:
        full_response = etree.tostring(full_response[0], method='text',
                                       encoding=unicode).strip()
        response['full_response'] = full_response

    serial_numbers = []
    response['serial_numbers'] = serial_numbers
    for serial_number in doc.xpath('//xml/records[*]/record/serialNumber'):
        serial_number = int(serial_number.text, 16) # parse as hex
        serial_numbers.append(serial_number)

    return response

def parse_display_cert_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    If the requestStatus is not SUCCESS then the response dict will have the
    contents described in `parse_error_template_xml`.

    +----------------+---------------+-----------------+---------------+
    |cms name        |cms type       |result name      |result type    |
    +================+===============+=================+===============+
    |emailCert       |Boolean        |email_cert       |bool           |
    +----------------+---------------+-----------------+---------------+
    |noCertImport    |Boolean        |no_cert_import   |bool           |
    +----------------+---------------+-----------------+---------------+
    |revocationReason|int            |revocation_reason|int [1]_       |
    +----------------+---------------+-----------------+---------------+
    |certPrettyPrint |string         |cert_pretty      |unicode        |
    +----------------+---------------+-----------------+---------------+
    |authorityid     |string         |authority        |unicode        |
    +----------------+---------------+-----------------+---------------+
    |certFingerprint |string         |fingerprint      |unicode        |
    +----------------+---------------+-----------------+---------------+
    |certChainBase64 |string         |certificate      |unicode [2]_   |
    +----------------+---------------+-----------------+---------------+
    |serialNumber    |string         |serial_number    |int|long       |
    +----------------+---------------+-----------------+---------------+
    |pkcs7ChainBase64|string         |pkcs7_chain      |unicode [2]_   |
    +----------------+---------------+-----------------+---------------+

    .. [1] revocation reason may be one of:

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

    .. [2] Base64 encoded

    '''

    request_status = get_request_status_xml(doc)

    if request_status != CMS_STATUS_SUCCESS:
        response = parse_error_template_xml(doc)
        return response

    response = {}
    response['request_status'] = request_status

    email_cert = doc.xpath('//xml/header/emailCert[1]')
    if len(email_cert) == 1:
        parse_and_set_boolean_xml(email_cert[0], response, 'email_cert')

    no_cert_import = doc.xpath('//xml/header/noCertImport[1]')
    if len(no_cert_import) == 1:
        parse_and_set_boolean_xml(no_cert_import[0], response, 'no_cert_import')

    revocation_reason = doc.xpath('//xml/header/revocationReason[1]')
    if len(revocation_reason) == 1:
        revocation_reason = int(revocation_reason[0].text)
        response['revocation_reason'] = revocation_reason

    cert_pretty = doc.xpath('//xml/header/certPrettyPrint[1]')
    if len(cert_pretty) == 1:
        cert_pretty = etree.tostring(cert_pretty[0], method='text',
                                     encoding=unicode).strip()
        response['cert_pretty'] = cert_pretty

    authority = doc.xpath('//xml/header/authorityid[1]')
    if len(authority) == 1:
        authority = etree.tostring(authority[0], method='text',
                                   encoding=unicode).strip()
        response['authority'] = authority

    fingerprint = doc.xpath('//xml/header/certFingerprint[1]')
    if len(fingerprint) == 1:
        fingerprint = etree.tostring(fingerprint[0], method='text',
                                     encoding=unicode).strip()
        response['fingerprint'] = fingerprint

    certificate = doc.xpath('//xml/header/certChainBase64[1]')
    if len(certificate) == 1:
        certificate = etree.tostring(certificate[0], method='text',
                                     encoding=unicode).strip()
        response['certificate'] = certificate

    serial_number = doc.xpath('//xml/header/serialNumber[1]')
    if len(serial_number) == 1:
        serial_number = int(serial_number[0].text, 16) # parse as hex
        response['serial_number'] = serial_number
        response['serial_number_hex'] = u'0x%X' % serial_number

    pkcs7_chain = doc.xpath('//xml/header/pkcs7ChainBase64[1]')
    if len(pkcs7_chain) == 1:
        pkcs7_chain = etree.tostring(pkcs7_chain[0], method='text',
                                     encoding=unicode).strip()
        response['pkcs7_chain'] = pkcs7_chain

    return response

def parse_revoke_cert_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    If the requestStatus is not SUCCESS then the response dict will have the
    contents described in `parse_error_template_xml`.

    +----------------------+----------------+-----------------------+---------------+
    |cms name              |cms type        |result name            |result type    |
    +======================+================+=======================+===============+
    |dirEnabled            |string [1]_     |dir_enabled            |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |certsUpdated          |int             |certs_updated          |int            |
    +----------------------+----------------+-----------------------+---------------+
    |certsToUpdate         |int             |certs_to_update        |int            |
    +----------------------+----------------+-----------------------+---------------+
    |error                 |string [2]_     |error_string           |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |revoked               |string [3]_     |revoked                |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |totalRecordCount      |int             |total_record_count     |int            |
    +----------------------+----------------+-----------------------+---------------+
    |updateCRL             |string [1]_ [4]_|update_crl             |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |updateCRLSuccess      |string [1]_ [4]_|update_crl_success     |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |updateCRLError        |string [4]_     |update_crl_error       |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |publishCRLSuccess     |string [1]_[4]_ |publish_crl_success    |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |publishCRLError       |string [4]_     |publish_crl_error      |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |crlUpdateStatus       |string [1]_ [5]_|crl_update_status      |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |crlUpdateError        |string [5]_     |crl_update_error       |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |crlPublishStatus      |string [1]_ [5]_|crl_publish_status     |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |crlPublishError       |string [5]_     |crl_publish_error      |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |records[].serialNumber|BigInteger      |records[].serial_number|int|long       |
    +----------------------+----------------+-----------------------+---------------+
    |records[].error       |string [2]_     |records[].error_string |unicode        |
    +----------------------+----------------+-----------------------+---------------+

    .. [1] String value is either "yes" or "no"
    .. [2] Sometimes the error string is empty (null)
    .. [3] revoked may be one of:

           - "yes"
           - "no"
           - "begin"
           - "pending"
           - "approved"
           - "svc_pending"
           - "canceled"
           - "rejected"
           - "complete"

    .. [4] Only sent if CRL update information is available.
           If sent it's only value is "yes".
           If sent then the following values may also be sent,
           otherwise they will be absent:

           - updateCRLSuccess
           - updateCRLError
           - publishCRLSuccess
           - publishCRLError

    .. [5] The cms name varies depending on whether the issuing point is MasterCRL
           or not. If the issuing point is not the MasterCRL then the cms name
           will be appended with an underscore and the issuing point name.
           Thus for example the cms name crlUpdateStatus will be crlUpdateStatus
           if the issuing point is the MasterCRL. However if the issuing point
           is "foobar" then crlUpdateStatus will be crlUpdateStatus_foobar.
           When we return the response dict the key will always be the "base"
           name without the _issuing_point suffix. Thus crlUpdateStatus_foobar
           will appear in the response dict under the key 'crl_update_status'

    '''

    request_status = get_request_status_xml(doc)

    if request_status != CMS_STATUS_SUCCESS:
        response = parse_error_template_xml(doc)
        return response

    response = {}
    response['request_status'] = request_status

    records = []
    response['records'] = records

    dir_enabled = doc.xpath('//xml/header/dirEnabled[1]')
    if len(dir_enabled) == 1:
        parse_and_set_boolean_xml(dir_enabled[0], response, 'dir_enabled')

    certs_updated = doc.xpath('//xml/header/certsUpdated[1]')
    if len(certs_updated) == 1:
        certs_updated = int(certs_updated[0].text)
        response['certs_updated'] = certs_updated

    certs_to_update = doc.xpath('//xml/header/certsToUpdate[1]')
    if len(certs_to_update) == 1:
        certs_to_update = int(certs_to_update[0].text)
        response['certs_to_update'] = certs_to_update

    error_string = doc.xpath('//xml/header/error[1]')
    if len(error_string) == 1:
        error_string = etree.tostring(error_string[0], method='text',
                                      encoding=unicode).strip()
        response['error_string'] = error_string

    revoked = doc.xpath('//xml/header/revoked[1]')
    if len(revoked) == 1:
        revoked = etree.tostring(revoked[0], method='text',
                                 encoding=unicode).strip()
        response['revoked'] = revoked

    total_record_count = doc.xpath('//xml/header/totalRecordCount[1]')
    if len(total_record_count) == 1:
        total_record_count = int(total_record_count[0].text)
        response['total_record_count'] = total_record_count

    update_crl = doc.xpath('//xml/header/updateCRL[1]')
    if len(update_crl) == 1:
        parse_and_set_boolean_xml(update_crl[0], response, 'update_crl')

    update_crl_success = doc.xpath('//xml/header/updateCRLSuccess[1]')
    if len(update_crl_success) == 1:
        parse_and_set_boolean_xml(update_crl_success[0], response, 'update_crl_success')

    update_crl_error = doc.xpath('//xml/header/updateCRLError[1]')
    if len(update_crl_error) == 1:
        update_crl_error = etree.tostring(update_crl_error[0], method='text',
                                          encoding=unicode).strip()
        response['update_crl_error'] = update_crl_error

    publish_crl_success = doc.xpath('//xml/header/publishCRLSuccess[1]')
    if len(publish_crl_success) == 1:
        parse_and_set_boolean_xml(publish_crl_success[0], response, 'publish_crl_success')

    publish_crl_error = doc.xpath('//xml/header/publishCRLError[1]')
    if len(publish_crl_error) == 1:
        publish_crl_error = etree.tostring(publish_crl_error[0], method='text',
                                           encoding=unicode).strip()
        response['publish_crl_error'] = publish_crl_error

    crl_update_status = doc.xpath("//xml/header/*[starts-with(name(), 'crlUpdateStatus')][1]")
    if len(crl_update_status) == 1:
        parse_and_set_boolean_xml(crl_update_status[0], response, 'crl_update_status')

    crl_update_error = doc.xpath("//xml/header/*[starts-with(name(), 'crlUpdateError')][1]")
    if len(crl_update_error) == 1:
        crl_update_error = etree.tostring(crl_update_error[0], method='text',
                                          encoding=unicode).strip()
        response['crl_update_error'] = crl_update_error

    crl_publish_status = doc.xpath("//xml/header/*[starts-with(name(), 'crlPublishStatus')][1]")
    if len(crl_publish_status) == 1:
        parse_and_set_boolean_xml(crl_publish_status[0], response, 'crl_publish_status')

    crl_publish_error = doc.xpath("//xml/header/*[starts-with(name(), 'crlPublishError')][1]")
    if len(crl_publish_error) == 1:
        crl_publish_error = etree.tostring(crl_publish_error[0], method='text',
                                           encoding=unicode).strip()
        response['crl_publish_error'] = crl_publish_error

    for record in doc.xpath('//xml/records[*]/record'):
        response_record = {}
        records.append(response_record)

        serial_number = record.xpath('serialNumber[1]')
        if len(serial_number) == 1:
            serial_number = int(serial_number[0].text, 16) # parse as hex
            response_record['serial_number'] = serial_number
            response['serial_number_hex'] = u'0x%X' % serial_number

        error_string = record.xpath('error[1]')
        if len(error_string) == 1:
            error_string = etree.tostring(error_string[0], method='text',
                                          encoding=unicode).strip()
            response_record['error_string'] = error_string

    return response

def parse_unrevoke_cert_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    If the requestStatus is not SUCCESS then the response dict will have the
    contents described in `parse_error_template_xml`.

    +----------------------+----------------+-----------------------+---------------+
    |cms name              |cms type        |result name            |result type    |
    +======================+================+=======================+===============+
    |dirEnabled            |string [1]_     |dir_enabled            |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |dirUpdated            |string [1]_     |dir_updated            |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |error                 |string          |error_string           |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |unrevoked             |string [3]_     |unrevoked              |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |updateCRL             |string [1]_ [4]_|update_crl             |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |updateCRLSuccess      |string [1]_ [4]_|update_crl_success     |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |updateCRLError        |string [4]_     |update_crl_error       |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |publishCRLSuccess     |string [1]_ [4]_|publish_crl_success    |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |publishCRLError       |string [4]_     |publish_crl_error      |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |crlUpdateStatus       |string [1]_ [5]_|crl_update_status      |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |crlUpdateError        |string [5]_     |crl_update_error       |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |crlPublishStatus      |string [1]_ [5]_|crl_publish_status     |bool           |
    +----------------------+----------------+-----------------------+---------------+
    |crlPublishError       |string [5]_     |crl_publish_error      |unicode        |
    +----------------------+----------------+-----------------------+---------------+
    |serialNumber          |BigInteger      |serial_number          |int|long       |
    +----------------------+----------------+-----------------------+---------------+

    .. [1] String value is either "yes" or "no"
    .. [3] unrevoked may be one of:

           - "yes"
           - "no"
           - "pending"

    .. [4] Only sent if CRL update information is available.
           If sent it's only value is "yes".
           If sent then the following values may also be sent,
           otherwise they will be absent:

           - updateCRLSuccess
           - updateCRLError
           - publishCRLSuccess
           - publishCRLError

    .. [5] The cms name varies depending on whether the issuing point is MasterCRL
           or not. If the issuing point is not the MasterCRL then the cms name
           will be appended with an underscore and the issuing point name.
           Thus for example the cms name crlUpdateStatus will be crlUpdateStatus
           if the issuing point is the MasterCRL. However if the issuing point
           is "foobar" then crlUpdateStatus will be crlUpdateStatus_foobar.
           When we return the response dict the key will always be the "base"
           name without the _issuing_point suffix. Thus crlUpdateStatus_foobar
           will appear in the response dict under the key 'crl_update_status'

    '''

    request_status = get_request_status_xml(doc)

    if request_status != CMS_STATUS_SUCCESS:
        response = parse_error_template_xml(doc)
        return response

    response = {}
    response['request_status'] = request_status

    dir_enabled = doc.xpath('//xml/header/dirEnabled[1]')
    if len(dir_enabled) == 1:
        parse_and_set_boolean_xml(dir_enabled[0], response, 'dir_enabled')

    dir_updated = doc.xpath('//xml/header/dirUpdated[1]')
    if len(dir_updated) == 1:
        parse_and_set_boolean_xml(dir_updated[0], response, 'dir_updated')

    error_string = doc.xpath('//xml/header/error[1]')
    if len(error_string) == 1:
        error_string = etree.tostring(error_string[0], method='text',
                                      encoding=unicode).strip()
        response['error_string'] = error_string

    unrevoked = doc.xpath('//xml/header/unrevoked[1]')
    if len(unrevoked) == 1:
        unrevoked = etree.tostring(unrevoked[0], method='text',
                                   encoding=unicode).strip()
        response['unrevoked'] = unrevoked

    update_crl = doc.xpath('//xml/header/updateCRL[1]')
    if len(update_crl) == 1:
        parse_and_set_boolean_xml(update_crl[0], response, 'update_crl')

    update_crl_success = doc.xpath('//xml/header/updateCRLSuccess[1]')
    if len(update_crl_success) == 1:
        parse_and_set_boolean_xml(update_crl_success[0], response, 'update_crl_success')

    update_crl_error = doc.xpath('//xml/header/updateCRLError[1]')
    if len(update_crl_error) == 1:
        update_crl_error = etree.tostring(update_crl_error[0], method='text',
                                          encoding=unicode).strip()
        response['update_crl_error'] = update_crl_error

    publish_crl_success = doc.xpath('//xml/header/publishCRLSuccess[1]')
    if len(publish_crl_success) == 1:
        parse_and_set_boolean_xml(publish_crl_success[0], response, 'publish_crl_success')

    publish_crl_error = doc.xpath('//xml/header/publishCRLError[1]')
    if len(publish_crl_error) == 1:
        publish_crl_error = etree.tostring(publish_crl_error[0], method='text',
                                           encoding=unicode).strip()
        response['publish_crl_error'] = publish_crl_error

    crl_update_status = doc.xpath("//xml/header/*[starts-with(name(), 'crlUpdateStatus')][1]")
    if len(crl_update_status) == 1:
        parse_and_set_boolean_xml(crl_update_status[0], response, 'crl_update_status')

    crl_update_error = doc.xpath("//xml/header/*[starts-with(name(), 'crlUpdateError')][1]")
    if len(crl_update_error) == 1:
        crl_update_error = etree.tostring(crl_update_error[0], method='text',
                                          encoding=unicode).strip()
        response['crl_update_error'] = crl_update_error

    crl_publish_status = doc.xpath("//xml/header/*[starts-with(name(), 'crlPublishStatus')][1]")
    if len(crl_publish_status) == 1:
        parse_and_set_boolean_xml(crl_publish_status[0], response, 'crl_publish_status')

    crl_publish_error = doc.xpath("//xml/header/*[starts-with(name(), 'crlPublishError')][1]")
    if len(crl_publish_error) == 1:
        crl_publish_error = etree.tostring(crl_publish_error[0], method='text',
                                           encoding=unicode).strip()
        response['crl_publish_error'] = crl_publish_error

    serial_number = doc.xpath('//xml/header/serialNumber[1]')
    if len(serial_number) == 1:
        serial_number = int(serial_number[0].text, 16) # parse as hex
        response['serial_number'] = serial_number
        response['serial_number_hex'] = u'0x%X' % serial_number

    return response


def host_has_service(host, ldap2, service='CA'):
    """
    :param host: A host which might be a master for a service.
    :param ldap2: connection to the local database
    :param service: The service for which the host might be a master.
    :return:   (true, false)

    Check if a specified host is a master for a specified service.
    """
    base_dn = DN(('cn', host), ('cn', 'masters'), ('cn', 'ipa'),
                 ('cn', 'etc'), api.env.basedn)
    filter_attrs = {
        'objectClass': 'ipaConfigObject',
        'cn': service,
        'ipaConfigString': 'enabledService',
        }
    query_filter = ldap2.make_filter(filter_attrs, rules='&')
    try:
        ent, _trunc = ldap2.find_entries(filter=query_filter, base_dn=base_dn)
        if len(ent):
            return True
    except Exception:
        pass
    return False


def select_any_master(ldap2, service='CA'):
    """
    :param ldap2: connection to the local database
    :param service: The service for which we're looking for a master.
    :return:   host as str

    Select any host which is a master for a specified service.
    """
    base_dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
                  api.env.basedn)
    filter_attrs = {
         'objectClass': 'ipaConfigObject',
         'cn': service,
         'ipaConfigString': 'enabledService',}
    query_filter = ldap2.make_filter(filter_attrs, rules='&')
    try:
        ent, _trunc = ldap2.find_entries(filter=query_filter, base_dn=base_dn)
        if len(ent):
            entry = random.choice(ent)
            return entry.dn[1].value
    except Exception:
        pass
    return None

#-------------------------------------------------------------------------------

from ipalib import Registry, errors, SkipPluginModule
if api.env.ra_plugin != 'dogtag':
    # In this case, abort loading this plugin module...
    raise SkipPluginModule(reason='dogtag not selected as RA plugin')
import os
import random
from ipaserver.plugins import rabase
from ipalib.constants import TYPE_ERROR
from ipalib import _
from ipaplatform.paths import paths

register = Registry()


class RestClient(Backend):
    """Simple Dogtag REST client to be subclassed by other backends.

    This class is a context manager.  Authenticated calls must be
    executed in a ``with`` suite::

        @register()
        class ra_certprofile(RestClient):
            path = 'profile'
            ...

        with api.Backend.ra_certprofile as profile_api:
            # REST client is now logged in
            profile_api.create_profile(...)

    """
    DEFAULT_PROFILE = dogtag.DEFAULT_PROFILE
    KDC_PROFILE = dogtag.KDC_PROFILE
    path = None

    @staticmethod
    def _parse_dogtag_error(body):
        try:
            return pki.PKIException.from_json(
                json.loads(ipautil.decode_json(body)))
        except Exception:
            return None

    def __init__(self, api):
        self.ca_cert = api.env.tls_ca_cert
        if api.env.in_tree:
            self.client_certfile = os.path.join(
                api.env.dot_ipa, 'ra-agent.pem')

            self.client_keyfile = os.path.join(
                api.env.dot_ipa, 'ra-agent.key')
        else:
            self.client_certfile = paths.RA_AGENT_PEM
            self.client_keyfile = paths.RA_AGENT_KEY
        super(RestClient, self).__init__(api)

        self._ca_host = None
        # session cookie
        self.override_port = None
        self.cookie = None

    @property
    def ca_host(self):
        """
        :returns: FQDN of a host hopefully providing a CA service

        Select our CA host, cache it for the first time.
        """
        if self._ca_host is not None:
            return self._ca_host

        ldap2 = self.api.Backend.ldap2
        if host_has_service(api.env.ca_host, ldap2, "CA"):
            object.__setattr__(self, '_ca_host', api.env.ca_host)
        elif api.env.host != api.env.ca_host:
            if host_has_service(api.env.host, ldap2, "CA"):
                object.__setattr__(self, '_ca_host', api.env.host)
        else:
            object.__setattr__(self, '_ca_host', select_any_master(ldap2))
        if self._ca_host is None:
            object.__setattr__(self, '_ca_host', api.env.ca_host)
        return self._ca_host

    def __enter__(self):
        """Log into the REST API"""
        if self.cookie is not None:
            return None

        # Refresh the ca_host property
        object.__setattr__(self, '_ca_host', None)

        status, resp_headers, _resp_body = dogtag.https_request(
            self.ca_host, self.override_port or self.env.ca_agent_port,
            url='/ca/rest/account/login',
            cafile=self.ca_cert,
            client_certfile=self.client_certfile,
            client_keyfile=self.client_keyfile,
            method='GET'
        )
        cookies = ipapython.cookie.Cookie.parse(resp_headers.get('set-cookie', ''))
        if status != 200 or len(cookies) == 0:
            raise errors.RemoteRetrieveError(reason=_('Failed to authenticate to CA REST API'))
        object.__setattr__(self, 'cookie', str(cookies[0]))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Log out of the REST API"""
        dogtag.https_request(
            self.ca_host, self.override_port or self.env.ca_agent_port,
            url='/ca/rest/account/logout',
            cafile=self.ca_cert,
            client_certfile=self.client_certfile,
            client_keyfile=self.client_keyfile,
            method='GET'
        )
        object.__setattr__(self, 'cookie', None)

    def _ssldo(self, method, path, headers=None, body=None, use_session=True):
        """
        Perform an HTTPS request.

        :param method: HTTP method to use
        :param path: Path component. This will *extend* the path defined for
            the class (if any).
        :param headers: Additional headers to include in the request.
        :param body: Request body.
        :param use_session: If ``True``, session cookie is added to request
            (client must be logged in).

        :return:   (http_status, http_headers, http_body)
                   as (integer, dict, str)

        :raises: ``RemoteRetrieveError`` if ``use_session`` is not ``False``
            and client is not logged in.

        """
        headers = headers or {}

        if use_session:
            if self.cookie is None:
                raise errors.RemoteRetrieveError(
                    reason=_("REST API is not logged in."))
            headers['Cookie'] = self.cookie

        resource = '/ca/rest'
        if self.path is not None:
            resource = os.path.join(resource, self.path)
        if path is not None:
            resource = os.path.join(resource, path)

        # perform main request
        status, resp_headers, resp_body = dogtag.https_request(
            self.ca_host, self.override_port or self.env.ca_agent_port,
            url=resource,
            cafile=self.ca_cert,
            client_certfile=self.client_certfile,
            client_keyfile=self.client_keyfile,
            method=method, headers=headers, body=body
        )
        if status < 200 or status >= 300:
            explanation = self._parse_dogtag_error(resp_body) or ''
            raise errors.HTTPRequestError(
                status=status,
                reason=_('Non-2xx response from CA REST API: %(status)d. %(explanation)s')
                % {'status': status, 'explanation': explanation}
            )
        return (status, resp_headers, resp_body)


@register()
class ra(rabase.rabase, RestClient):
    """
    Request Authority backend plugin.
    """
    DEFAULT_PROFILE = dogtag.DEFAULT_PROFILE

    def raise_certificate_operation_error(self, func_name, err_msg=None, detail=None):
        """
        :param func_name: function name where error occurred

        :param err_msg:   diagnostic error message, if not supplied it will be
                          'Unable to communicate with CMS'
        :param detail:    extra information that will be appended to err_msg
                          inside a parenthesis

        Raise a CertificateOperationError and log the error message.
        """

        if err_msg is None:
            err_msg = _('Unable to communicate with CMS')

        if detail is not None:
            err_msg = u'%s (%s)' % (err_msg, detail)

        logger.error('%s.%s(): %s', type(self).__name__, func_name, err_msg)
        raise errors.CertificateOperationError(error=err_msg)

    def _request(self, url, port, **kw):
        """
        :param url: The URL to post to.
        :param kw: Keyword arguments to encode into POST body.
        :return:   (http_status, http_headers, http_body)
                   as (integer, dict, str)

        Perform an HTTP request.
        """
        return dogtag.http_request(self.ca_host, port, url, **kw)

    def _sslget(self, url, port, **kw):
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

    def get_parse_result_xml(self, xml_text, parse_func):
        '''
        :param xml_text:   The XML text to parse
        :param parse_func: The XML parsing function to apply to the parsed DOM tree.
        :return:           parsed result dict

        Utility routine which parses the input text into an XML DOM tree
        and then invokes the parsing function on the DOM tree in order
        to get the parsing result as a dict of key/value pairs.
        '''
        parser = etree.XMLParser()
        try:
            doc = etree.fromstring(xml_text, parser)
        except etree.XMLSyntaxError as e:
            self.raise_certificate_operation_error('get_parse_result_xml',
                                                   detail=str(e))
        result = parse_func(doc)
        logger.debug(
            "%s() xml_text:\n%r\nparse_result:\n%r",
            parse_func.__name__, xml_text, result)
        return result

    def check_request_status(self, request_id):
        """
        :param request_id: request ID

        Check status of a certificate signing request.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +-------------------+---------------+---------------+
        |result name        |result type    |comments       |
        +===================+===============+===============+
        |serial_number      |unicode [1]_   |               |
        +-------------------+---------------+---------------+
        |request_id         |unicode        |               |
        +-------------------+---------------+---------------+
        |cert_request_status|unicode [2]_   |               |
        +-------------------+---------------+---------------+

        .. [1] Passed through XMLRPC as decimal string. Can convert to
               optimal integer type (int or long) via int(serial_number)

        .. [2] cert_request_status may be one of:

               - "begin"
               - "pending"
               - "approved"
               - "svc_pending"
               - "canceled"
               - "rejected"
               - "complete"


        """
        logger.debug('%s.check_request_status()', type(self).__name__)

        # Call CMS
        http_status, _http_headers, http_body = (
            self._request('/ca/ee/ca/checkRequest',
                          self.env.ca_port,
                          requestId=request_id,
                          xml='true')
        )

        # Parse and handle errors
        if http_status != 200:
            self.raise_certificate_operation_error('check_request_status',
                                                   detail=http_status)

        parse_result = self.get_parse_result_xml(http_body, parse_check_request_result_xml)
        request_status = parse_result['request_status']
        if request_status != CMS_STATUS_SUCCESS:
            self.raise_certificate_operation_error('check_request_status',
                                                   cms_request_status_to_string(request_status),
                                                   parse_result.get('error_string'))

        # Return command result
        cmd_result = {}
        if 'serial_numbers' in parse_result and len(parse_result['serial_numbers']) > 0:
            # see module documentation concerning serial numbers and XMLRPC
            cmd_result['serial_number'] = unicode(parse_result['serial_numbers'][0])

        if 'request_id' in parse_result:
            cmd_result['request_id'] = parse_result['request_id']

        if 'cert_request_status' in parse_result:
            cmd_result['cert_request_status'] = parse_result['cert_request_status']

        return cmd_result

    def get_certificate(self, serial_number):
        """
        Retrieve an existing certificate.

        :param serial_number: Certificate serial number. Must be a string value
                              because serial numbers may be of any magnitude and
                              XMLRPC cannot handle integers larger than 64-bit.
                              The string value should be decimal, but may optionally
                              be prefixed with a hex radix prefix if the integral value
                              is represented as hexadecimal. If no radix prefix is
                              supplied the string will be interpreted as decimal.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +-----------------+---------------+---------------+
        |result name      |result type    |comments       |
        +=================+===============+===============+
        |certificate      |unicode [1]_   |               |
        +-----------------+---------------+---------------+
        |serial_number    |unicode [2]_   |               |
        +-----------------+---------------+---------------+
        |revocation_reason|int [3]_       |               |
        +-----------------+---------------+---------------+

        .. [1] Base64 encoded

        .. [2] Passed through XMLRPC as decimal string. Can convert to
               optimal integer type (int or long) via int(serial_number)

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

        # Convert serial number to integral type from string to properly handle
        # radix issues. Note: the int object constructor will properly handle large
        # magnitude integral values by returning a Python long type when necessary.
        serial_number = int(serial_number, 0)

        # Call CMS
        http_status, _http_headers, http_body = (
            self._sslget('/ca/agent/ca/displayBySerial',
                         self.env.ca_agent_port,
                         serialNumber=str(serial_number),
                         xml='true')
        )


        # Parse and handle errors
        if http_status != 200:
            self.raise_certificate_operation_error('get_certificate',
                                                   detail=http_status)

        parse_result = self.get_parse_result_xml(http_body, parse_display_cert_xml)
        request_status = parse_result['request_status']
        if request_status != CMS_STATUS_SUCCESS:
            self.raise_certificate_operation_error('get_certificate',
                                                   cms_request_status_to_string(request_status),
                                                   parse_result.get('error_string'))

        # Return command result
        cmd_result = {}

        if 'certificate' in parse_result:
            cmd_result['certificate'] = parse_result['certificate']

        if 'serial_number' in parse_result:
            # see module documentation concerning serial numbers and XMLRPC
            cmd_result['serial_number'] = unicode(parse_result['serial_number'])
            cmd_result['serial_number_hex'] = u'0x%X' % int(cmd_result['serial_number'])

        if 'revocation_reason' in parse_result:
            cmd_result['revocation_reason'] = parse_result['revocation_reason']

        return cmd_result


    def request_certificate(
            self, csr, profile_id, ca_id, request_type='pkcs10'):
        """
        :param csr: The certificate signing request.
        :param profile_id: The profile to use for the request.
        :param ca_id: The Authority ID to send request to. ``None`` is allowed.
        :param request_type: The request type (defaults to ``'pkcs10'``).

        Submit certificate signing request.

        The command returns a dict with these key/value pairs:

        ``serial_number``
            ``unicode``, decimal representation
        ``serial_number_hex``
            ``unicode``, hex representation with ``'0x'`` leader
        ``certificate``
            ``unicode``, base64-encoded DER
        ``request_id``
            ``unicode``, decimal representation

        """
        logger.debug('%s.request_certificate()', type(self).__name__)

        # Call CMS
        template = u'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <CertEnrollmentRequest>
                <ProfileID>{profile}</ProfileID>
                <Input id="i1">
                    <ClassID>certReqInputImpl</ClassID>
                    <Attribute name="cert_request_type">
                        <Value>{req_type}</Value>
                    </Attribute>
                    <Attribute name="cert_request">
                        <Value>{req}</Value>
                    </Attribute>
                </Input>
            </CertEnrollmentRequest>'''
        data = template.format(
            profile=profile_id,
            req_type=request_type,
            req=csr,
        )

        path = 'certrequests'
        if ca_id:
            path += '?issuer-id={}'.format(ca_id)

        _http_status, _http_headers, http_body = self._ssldo(
            'POST', path,
            headers={
                'Content-Type': 'application/xml',
                'Accept': 'application/json',
            },
            body=data,
            use_session=False,
        )

        try:
            resp_obj = json.loads(ipautil.decode_json(http_body))
        except ValueError:
            raise errors.RemoteRetrieveError(reason=_("Response from CA was not valid JSON"))

        # Return command result
        cmd_result = {}

        entries = resp_obj.get('entries', [])

        # ipa cert-request only handles a single PKCS #10 request so
        # there's only one certinfo in the result.
        if len(entries) < 1:
            return cmd_result
        certinfo = entries[0]

        if certinfo['requestStatus'] != 'complete':
            raise errors.CertificateOperationError(
                    error=certinfo.get('errorMessage'))

        if 'certId' in certinfo:
            cmd_result = self.get_certificate(certinfo['certId'])
            cert = ''.join(cmd_result['certificate'].splitlines())
            cmd_result['certificate'] = cert

        if 'requestURL' in certinfo:
            cmd_result['request_id'] = certinfo['requestURL'].split('/')[-1]

        return cmd_result


    def revoke_certificate(self, serial_number, revocation_reason=0):
        """
        :param serial_number: Certificate serial number. Must be a string value
                              because serial numbers may be of any magnitude and
                              XMLRPC cannot handle integers larger than 64-bit.
                              The string value should be decimal, but may optionally
                              be prefixed with a hex radix prefix if the integral value
                              is represented as hexadecimal. If no radix prefix is
                              supplied the string will be interpreted as decimal.
        :param revocation_reason: Integer code of revocation reason.

        Revoke a certificate.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +---------------+---------------+---------------+
        |result name    |result type    |comments       |
        +===============+===============+===============+
        |revoked        |bool           |               |
        +---------------+---------------+---------------+

        """
        logger.debug('%s.revoke_certificate()', type(self).__name__)
        if type(revocation_reason) is not int:
            raise TypeError(TYPE_ERROR % ('revocation_reason', int, revocation_reason, type(revocation_reason)))

        # Convert serial number to integral type from string to properly handle
        # radix issues. Note: the int object constructor will properly handle large
        # magnitude integral values by returning a Python long type when necessary.
        serial_number = int(serial_number, 0)

        # Call CMS
        http_status, _http_headers, http_body = \
            self._sslget('/ca/agent/ca/doRevoke',
                         self.env.ca_agent_port,
                         op='revoke',
                         revocationReason=revocation_reason,
                         revokeAll='(certRecordId=%s)' % str(serial_number),
                         totalRecordCount=1,
                         xml='true')

        # Parse and handle errors
        if http_status != 200:
            self.raise_certificate_operation_error('revoke_certificate',
                                                   detail=http_status)

        parse_result = self.get_parse_result_xml(http_body, parse_revoke_cert_xml)
        request_status = parse_result['request_status']
        if request_status != CMS_STATUS_SUCCESS:
            self.raise_certificate_operation_error('revoke_certificate',
                                                   cms_request_status_to_string(request_status),
                                                   parse_result.get('error_string'))

        # Return command result
        cmd_result = {}

        cmd_result['revoked'] = parse_result.get('revoked') == 'yes'

        return cmd_result

    def take_certificate_off_hold(self, serial_number):
        """
        :param serial_number: Certificate serial number. Must be a string value
                              because serial numbers may be of any magnitude and
                              XMLRPC cannot handle integers larger than 64-bit.
                              The string value should be decimal, but may optionally
                              be prefixed with a hex radix prefix if the integral value
                              is represented as hexadecimal. If no radix prefix is
                              supplied the string will be interpreted as decimal.

        Take revoked certificate off hold.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +---------------+---------------+---------------+
        |result name    |result type    |comments       |
        +===============+===============+===============+
        |unrevoked      |bool           |               |
        +---------------+---------------+---------------+
        |error_string   |unicode        |               |
        +---------------+---------------+---------------+
        """

        logger.debug('%s.take_certificate_off_hold()', type(self).__name__)

        # Convert serial number to integral type from string to properly handle
        # radix issues. Note: the int object constructor will properly handle large
        # magnitude integral values by returning a Python long type when necessary.
        serial_number = int(serial_number, 0)

        # Call CMS
        http_status, _http_headers, http_body = (
            self._sslget('/ca/agent/ca/doUnrevoke',
                         self.env.ca_agent_port,
                         serialNumber=str(serial_number),
                         xml='true')
        )

        # Parse and handle errors
        if http_status != 200:
            self.raise_certificate_operation_error('take_certificate_off_hold',
                                                   detail=http_status)


        parse_result = self.get_parse_result_xml(http_body, parse_unrevoke_cert_xml)
        request_status = parse_result['request_status']
        if request_status != CMS_STATUS_SUCCESS:
            self.raise_certificate_operation_error('take_certificate_off_hold',
                                                   cms_request_status_to_string(request_status),
                                                   parse_result.get('error_string'))

        # Return command result
        cmd_result = {}

        if 'error_string' in parse_result:
            cmd_result['error_string'] = parse_result['error_string']

        cmd_result['unrevoked'] = parse_result.get('unrevoked') == 'yes'

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

        # Create the root element
        page = etree.Element('CertSearchRequest')

        # Make a new document tree
        doc = etree.ElementTree(page)

        # This matches the default configuration of the pki tool.
        booloptions = {'serialNumberRangeInUse': True,
                       'subjectInUse': False,
                       'matchExactly': False,
                       'revokedByInUse': False,
                       'revokedOnInUse': False,
                       'revocationReasonInUse': False,
                       'issuedByInUse': False,
                       'issuedOnInUse': False,
                       'validNotBeforeInUse': False,
                       'validNotAfterInUse': False,
                       'validityLengthInUse': False,
                       'certTypeInUse': False}

        if options.get('exactly', False):
            booloptions['matchExactly'] = True

        if 'subject' in options:
            node = etree.SubElement(page, 'commonName')
            node.text = options['subject']
            booloptions['subjectInUse'] = True

        if 'issuer' in options:
            node = etree.SubElement(page, 'issuerDN')
            node.text = options['issuer']

        if 'revocation_reason' in options:
            node = etree.SubElement(page, 'revocationReason')
            node.text = unicode(options['revocation_reason'])
            booloptions['revocationReasonInUse'] = True

        if 'min_serial_number' in options:
            node = etree.SubElement(page, 'serialFrom')
            node.text = unicode(options['min_serial_number'])

        if 'max_serial_number' in options:
            node = etree.SubElement(page, 'serialTo')
            node.text = unicode(options['max_serial_number'])

        # date_types is a tuple that consists of:
        #   1. attribute name passed from IPA API
        #   2. attribute name used by REST API
        #   3. boolean to set in the REST API

        date_types = (
          ('validnotbefore_from', 'validNotBeforeFrom', 'validNotBeforeInUse'),
          ('validnotbefore_to', 'validNotBeforeTo', 'validNotBeforeInUse'),
          ('validnotafter_from', 'validNotAfterFrom', 'validNotAfterInUse'),
          ('validnotafter_to', 'validNotAfterTo', 'validNotAfterInUse'),
          ('issuedon_from', 'issuedOnFrom','issuedOnInUse'),
          ('issuedon_to', 'issuedOnTo','issuedOnInUse'),
          ('revokedon_from', 'revokedOnFrom','revokedOnInUse'),
          ('revokedon_to', 'revokedOnTo','revokedOnInUse'),
        )

        for (attr, dattr, battr) in date_types:
            if attr in options:
                epoch = convert_time(options[attr])
                node = etree.SubElement(page, dattr)
                node.text = unicode(epoch)
                booloptions[battr] = True

        # Add the boolean options to our XML document
        for opt in booloptions:
            e = etree.SubElement(page, opt)
            e.text = str(booloptions[opt]).lower()

        payload = etree.tostring(doc, pretty_print=False,
                                 xml_declaration=True, encoding='UTF-8')
        logger.debug('%s.find(): request: %s', type(self).__name__, payload)

        # pylint: disable=unused-variable
        status, _, data = dogtag.https_request(
            self.ca_host, 443,
            url='/ca/rest/certs/search?size=%d' % (
                 options.get('sizelimit', 0x7fffffff)),
            client_certfile=None,
            client_keyfile=None,
            cafile=self.ca_cert,
            method='POST',
            headers={'Accept-Encoding': 'gzip, deflate',
                     'User-Agent': 'IPA',
                     'Content-Type': 'application/xml'},
            body=payload
        )

        if status != 200:
            self.raise_certificate_operation_error('find',
                                                   detail=status)

        logger.debug('%s.find(): response: %s', type(self).__name__, data)
        parser = etree.XMLParser()
        try:
            doc = etree.fromstring(data, parser)
        except etree.XMLSyntaxError as e:
            self.raise_certificate_operation_error('find',
                                                   detail=e.msg)

        # Grab all the certificates
        certs = doc.xpath('//CertDataInfo')

        results = []

        for cert in certs:
            response_request = {}
            response_request['serial_number'] = int(cert.get('id'), 16) # parse as hex
            response_request['serial_number_hex'] = u'0x%X' % response_request['serial_number']

            dn = cert.xpath('SubjectDN')
            if len(dn) == 1:
                response_request['subject'] = unicode(dn[0].text)

            issuer_dn = cert.xpath('IssuerDN')
            if len(issuer_dn) == 1:
                response_request['issuer'] = unicode(issuer_dn[0].text)

            not_valid_before = cert.xpath('NotValidBefore')
            if len(not_valid_before) == 1:
                response_request['valid_not_before'] = (
                    unicode(not_valid_before[0].text))

            not_valid_after = cert.xpath('NotValidAfter')
            if len(not_valid_after) == 1:
                response_request['valid_not_after'] = (
                    unicode(not_valid_after[0].text))

            status = cert.xpath('Status')
            if len(status) == 1:
                response_request['status'] = unicode(status[0].text)
            results.append(response_request)

        return results


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
        ldap2 = self.api.Backend.ldap2
        if host_has_service(api.env.ca_host, ldap2, "KRA"):
            return api.env.ca_host
        if api.env.host != api.env.ca_host:
            if host_has_service(api.env.host, ldap2, "KRA"):
                return api.env.host
        host = select_any_master(ldap2, "KRA")
        if host:
            return host
        else:
            return api.env.ca_host

    @contextlib.contextmanager
    def get_client(self):
        """
        Returns an authenticated KRA client to access KRA services.

        Raises a generic exception if KRA is not enabled.
        """

        if not self.api.Command.kra_is_enabled()['result']:
            # TODO: replace this with a more specific exception
            raise RuntimeError('KRA service is not enabled')

        tempdb = certdb.NSSDatabase()
        tempdb.create_db()
        crypto = cryptoutil.NSSCryptoProvider(
            tempdb.secdir,
            password_file=tempdb.pwd_file)

        # TODO: obtain KRA host & port from IPA service list or point to KRA load balancer
        # https://fedorahosted.org/freeipa/ticket/4557
        connection = PKIConnection(
            'https',
            self.kra_host,
            str(self.kra_port),
            'kra')

        connection.session.cert = (paths.RA_AGENT_PEM, paths.RA_AGENT_KEY)
        # uncomment the following when this commit makes it to release
        # https://git.fedorahosted.org/cgit/pki.git/commit/?id=71ae20c
        # connection.set_authentication_cert(paths.RA_AGENT_PEM,
        #                                    paths.RA_AGENT_KEY)

        try:
            yield KRAClient(connection, crypto)
        finally:
            tempdb.close()


@register()
class ra_certprofile(RestClient):
    """
    Profile management backend plugin.
    """
    path = 'profiles'

    def create_profile(self, profile_data):
        """
        Import the profile into Dogtag
        """
        self._ssldo('POST', 'raw',
            headers={
                'Content-type': 'application/xml',
                'Accept': 'application/json',
            },
            body=profile_data
        )

    def read_profile(self, profile_id):
        """
        Read the profile configuration from Dogtag
        """
        _status, _resp_headers, resp_body = self._ssldo(
            'GET', profile_id + '/raw')
        return resp_body

    def update_profile(self, profile_id, profile_data):
        """
        Update the profile configuration in Dogtag
        """
        self._ssldo('PUT', profile_id + '/raw',
            headers={
                'Content-type': 'application/xml',
                'Accept': 'application/json',
            },
            body=profile_data
        )

    def enable_profile(self, profile_id):
        """
        Enable the profile in Dogtag
        """
        self._ssldo('POST', profile_id + '?action=enable')

    def disable_profile(self, profile_id):
        """
        Enable the profile in Dogtag
        """
        self._ssldo('POST', profile_id + '?action=disable')

    def delete_profile(self, profile_id):
        """
        Delete the profile from Dogtag
        """
        self._ssldo('DELETE', profile_id, headers={'Accept': 'application/json'})


@register()
class ra_lightweight_ca(RestClient):
    """
    Lightweight CA management backend plugin.
    """
    path = 'authorities'

    def create_ca(self, dn):
        """Create CA with the given DN.

        New CA is issued by IPA CA.  Nested sub-CAs and unrelated
        root CAs are not yet supported.

        Return the (parsed) JSON response from server.

        """

        assert isinstance(dn, DN)
        _status, _resp_headers, resp_body = self._ssldo(
            'POST', None,
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
            },
            body=json.dumps({"parentID": "host-authority", "dn": unicode(dn)}),
        )
        try:
            return json.loads(ipautil.decode_json(resp_body))
        except Exception as e:
            logger.debug('%s', e, exc_info=True)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON"))

    def read_ca(self, ca_id):
        _status, _resp_headers, resp_body = self._ssldo(
            'GET', ca_id, headers={'Accept': 'application/json'})
        try:
            return json.loads(ipautil.decode_json(resp_body))
        except Exception as e:
            logger.debug('%s', e, exc_info=True)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON"))

    def read_ca_cert(self, ca_id):
        _status, _resp_headers, resp_body = self._ssldo(
            'GET', '{}/cert'.format(ca_id),
            headers={'Accept': 'application/pkix-cert'})
        return resp_body

    def read_ca_chain(self, ca_id):
        _status, _resp_headers, resp_body = self._ssldo(
            'GET', '{}/chain'.format(ca_id),
            headers={'Accept': 'application/pkcs7-mime'})
        return resp_body

    def disable_ca(self, ca_id):
        self._ssldo(
            'POST', ca_id + '/disable',
            headers={'Accept': 'application/json'},
        )

    def enable_ca(self, ca_id):
        self._ssldo(
            'POST', ca_id + '/enable',
            headers={'Accept': 'application/json'},
        )

    def delete_ca(self, ca_id):
        self._ssldo('DELETE', ca_id)
