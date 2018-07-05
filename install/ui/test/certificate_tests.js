/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

define(['freeipa/ipa',
        'freeipa/jquery',
        'freeipa/certificate'],
    function(IPA, $) {
        return function() {

QUnit.module('certificate');

QUnit.test("Testing certificate_parse_dn().", function(assert) {

    assert.deepEqual(
        IPA.cert.parse_dn(), {},
        "Checking IPA.cert.parse_dn()");

    assert.deepEqual(
        IPA.cert.parse_dn(''), {},
        "Checking IPA.cert.parse_dn('')");

    assert.deepEqual(
        IPA.cert.parse_dn('c=US'), {'c': 'US'},
        "Checking IPA.cert.parse_dn('c=US')");

    assert.deepEqual(
        IPA.cert.parse_dn('st=TX,c=US'), {'st': 'TX','c': 'US'},
        "Checking IPA.cert.parse_dn('st=TX,c=US')");

    assert.deepEqual(
        IPA.cert.parse_dn('c=US,st=TX'), {'st': 'TX','c': 'US'},
        "Checking IPA.cert.parse_dn('c=US,st=TX')");

    assert.deepEqual(
        IPA.cert.parse_dn(' st = New Mexico , c = US '), {'st': 'New Mexico','c': 'US'},
        "Checking IPA.cert.parse_dn(' st = New Mexico , c = US ')");

    assert.deepEqual(
        IPA.cert.parse_dn('ST=TX,C=US'), {'st': 'TX','c': 'US'},
        "Checking IPA.cert.parse_dn('ST=TX,C=US')");

    assert.deepEqual(
        IPA.cert.parse_dn('cn=dev.example.com,ou=Engineering,o=Example,l=Austin,ST=TX,C=US'),
        {   'cn': 'dev.example.com',
            'ou': 'Engineering',
            'o': 'Example',
            'l': 'Austin',
            'st': 'TX',
            'c': 'US'
        },
        "Checking IPA.cert.parse_dn('cn=dev.example.com,ou=Engineering,o=Example,l=Austin,ST=TX,C=US')");

    assert.deepEqual(
        IPA.cert.parse_dn('cn=John Smith,ou=Developers,ou=Users,dc=example,dc=com'),
        {
            'cn': 'John Smith',
            'ou': ['Developers','Users'],
            'dc': ['example', 'com']
        },
        "Checking IPA.cert.parse_dn('cn=John Smith,ou=Developers,ou=Users,dc=example,dc=com')");
});

};});
