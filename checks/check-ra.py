#!/usr/bin/python
# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
#

"""
This tests the api.Backend.ra plugin against a test CA server awnuk has runnig.
It's only accessible from inside the Red Hat firewall.  Obviously this needs
work so the community can also run this test, but it's a start.

Also, awnuk had to help me register the IPA instance I'm running with his
server.  I don't exactly remember the steps, so ping him for help.

    --jderose 2009-02-13
"""

from os import path
import sys
parent = path.dirname(path.dirname(path.abspath(__file__)))
sys.path.insert(0, parent)
verbose = True

from base64 import b64encode, b64decode
from ipalib import api

subject = u'CN=vm-070.idm.lab.bos.redhat.com'
csr = '\
MIIBZzCB0QIBADAoMSYwJAYDVQQDEx12bS0wNzAuaWRtLmxhYi5ib3MucmVkaGF0\n\
LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAriTSlAG+/xkvtxliWMeO\n\
Qu+vFQTz+/fgy7xWIg6WR2At6j/9eJ7LUYhqguqevOAQpuePxY4/FEfpmQ6PTgs/\n\
LXKa0vhIkXzkmMjKynUIWHYeaZekcXxye1dV/PdNB6H801xs60YjbScOJj3Hexvm\n\
hOKsdmwO1ukqTTEKDXrr3c8CAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4GBAG4pTLrE\n\
cvrkQXVdMOjgAVJ6KZYl/caIOYhIlcJ3jhf95Bv/Zs3lpfHjXnM8jj4EWfyd0lZx\n\
2EUytXXubKJUpjUCeBp4oaQ2Ahvdxo++oUcbXkKxtCOUB6Mw8XEIVYaldZlcHDHM\n\
dysLdrZ3K9HOzoeSq2e0m+trQaWnBQG47O7F\n\
'

reference_decode = {
    'certificate' : b64decode
}

trial_decode = {
    'certificate' : b64decode
}

api.bootstrap(
    in_server=True,
    enable_ra=True,
    ra_plugin='dogtag',
    ca_host='vm-070.idm.lab.bos.redhat.com',
    debug=True,
    in_tree=True,
)
api.finalize()
ra = api.Backend.ra

def assert_equal(trial, reference):
    keys = reference.keys()
    keys.sort()
    for key in keys:
        reference_val = reference[key]
        trial_val = trial[key]

        if reference_decode.has_key(key):
            reference_val = reference_decode[key](reference_val)

        if trial_decode.has_key(key):
            trial_val = trial_decode[key](trial_val)

        assert reference_val == trial_val, \
            '%s: not equal\n\nreference_val:\n%r\ntrial_val:\n%r' % \
            (key, reference[key], trial[key])


api.log.info('******** Testing ra.request_certificate() ********')
request_result = ra.request_certificate(csr)
if verbose: print "request_result=\n%s" % request_result
assert_equal(request_result,
             {'subject' : subject,
              })

api.log.info('******** Testing ra.check_request_status() ********')
status_result = ra.check_request_status(request_result['request_id'])
if verbose: print "status_result=\n%s" % status_result
assert_equal(status_result,
             {'serial_number'       : request_result['serial_number'],
              'request_id'          : request_result['request_id'],
              'cert_request_status' : u'complete',
              })

api.log.info('******** Testing ra.get_certificate() ********')
get_result = ra.get_certificate(request_result['serial_number'])
if verbose: print "get_result=\n%s" % get_result
assert_equal(get_result,
             {'serial_number' : request_result['serial_number'],
              'certificate'   : request_result['certificate'],
              })

api.log.info('******** Testing ra.revoke_certificate() ********')
revoke_result = ra.revoke_certificate(request_result['serial_number'],
                                      revocation_reason=6)  # Put on hold
if verbose: print "revoke_result=\n%s" % revoke_result
assert_equal(revoke_result,
             {'revoked' : True
              })


api.log.info('******** Testing ra.take_certificate_off_hold() ********')
unrevoke_result = ra.take_certificate_off_hold(request_result['serial_number'])
if verbose: print "unrevoke_result=\n%s" % unrevoke_result
assert_equal(unrevoke_result,
             {'unrevoked' : True
              })

