# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""
Test the `pkcs10.py` module.
"""

import os
import sys
import nose
from tests.util import raises, PluginTester
from ipalib import pkcs10
from ipapython import ipautil

class test_update(object):
    """
    Test the PKCS#10 Parser.
    """

    def setUp(self):
        if ipautil.file_exists("test0.csr"):
            self.testdir="./"
        elif ipautil.file_exists("tests/test_pkcs10/test0.csr"):
            self.testdir= "./tests/test_pkcs10/"
        else:
            raise nose.SkipTest("Unable to find test update files")

    def read_file(self, filename):
        fp = open(self.testdir + filename, "r")
        data = fp.read()
        fp.close()
        return data

    def test_0(self):
        """
        Test simple CSR with no attributes
        """
        csr = self.read_file("test0.csr")
        request = pkcs10.load_certificate_request(csr)

        attributes = request.get_attributes()
        subject = request.get_subject()
        components = subject.get_components()
        compdict = dict(components)

        assert(attributes == ())
        assert(compdict['CN'] == u'test.example.com')
        assert(compdict['ST'] == u'California')
        assert(compdict['C'] == u'US')

    def test_1(self):
        """
        Test CSR with subject alt name
        """
        csr = self.read_file("test1.csr")
        request = pkcs10.load_certificate_request(csr)

        attributes = request.get_attributes()
        subject = request.get_subject()
        components = subject.get_components()
        compdict = dict(components)
        attrdict = dict(attributes)

        assert(compdict['CN'] == u'test.example.com')
        assert(compdict['ST'] == u'California')
        assert(compdict['C'] == u'US')

        extensions = attrdict['1.2.840.113549.1.9.14']

        for ext in range(len(extensions)):
            if extensions[ext][0] == '2.5.29.17':
                names = extensions[ext][2]
                # check the dNSName field
                assert(names[2] == [u'testlow.example.com'])

    def test_2(self):
        """
        Test CSR with subject alt name and a list of CRL distribution points
        """
        csr = self.read_file("test2.csr")
        request = pkcs10.load_certificate_request(csr)

        attributes = request.get_attributes()
        subject = request.get_subject()
        components = subject.get_components()
        compdict = dict(components)
        attrdict = dict(attributes)

        assert(compdict['CN'] == u'test.example.com')
        assert(compdict['ST'] == u'California')
        assert(compdict['C'] == u'US')

        extensions = attrdict['1.2.840.113549.1.9.14']

        for ext in range(len(extensions)):
            if extensions[ext][0] == '2.5.29.17':
                names = extensions[ext][2]
                # check the dNSName field
                assert(names[2] == [u'testlow.example.com'])
            if extensions[ext][0] == '2.5.29.31':
                urls = extensions[ext][2]
                assert(len(urls) == 2)
                assert(urls[0] == u'http://ca.example.com/my.crl')
                assert(urls[1] == u'http://other.example.com/my.crl')
