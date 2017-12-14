/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
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

define(['freeipa/ipa', 'freeipa/net'], function(IPA, NET) {
    return function() {

QUnit.module('ip-addresses');

var get_reverse = function(str) {
    var address = NET.ip_address(str);
    return address.get_reverse();
};

QUnit.test('Testing correct IPv4 addresses', function(assert) {

    var address = NET.ip_address('255.0.173.1');
    assert.ok(address.valid, 'Dotted decimal - 255.0.173.1');
    assert.deepEqual(address.parts, ['255', '0', '173', '1'], 'Checking parts');

    address = NET.ip_address('0377.0.0255.01');
    assert.ok(address.valid, 'Dotted octal - 0377.0.0255.01');
    assert.deepEqual(address.parts, ['255', '0', '173', '1'], 'Checking parts');

    address = NET.ip_address('0xFF.0x0.0xAD.0x1');
    assert.ok(address.valid, 'Dotted hexadecimal - 0xFF.0x.0xAD.0x1');
    assert.deepEqual(address.parts, ['255', '0', '173', '1'], 'Checking parts');

    address = NET.ip_address('4294967295');
    assert.ok(address.valid, 'Max decimal - 4294967295');
    assert.deepEqual(address.parts, ['255', '255', '255', '255'], 'Checking parts');

    address = NET.ip_address('037777777777');
    assert.ok(address.valid, 'Max octal - 037777777777');
    assert.deepEqual(address.parts, ['255', '255', '255', '255'], 'Checking parts');

    address = NET.ip_address('0xFFFFFFFF');
    assert.ok(address.valid, 'Max hexadecimal - 0xFFFFFFFF');
    assert.deepEqual(address.parts, ['255', '255', '255', '255'], 'Checking parts');

    address = NET.ip_address('255.0.0xAD.01');
    assert.ok(address.valid, 'Dotted mixed - 255.0.0xAD.01');
    assert.deepEqual(address.parts, ['255', '0', '173', '1'], 'Checking parts');

    address = NET.ip_address('0');
    assert.ok(address.valid, 'Zero decimal - 0');
    assert.deepEqual(address.parts, ['0', '0', '0', '0'], 'Checking parts');

    address = NET.ip_address('00');
    assert.ok(address.valid, 'Zero octal - 00');
    assert.deepEqual(address.parts, ['0', '0', '0', '0'], 'Checking parts');

    address = NET.ip_address('0X0');
    assert.ok(address.valid, 'Zero hexa - 0X0');
    assert.deepEqual(address.parts, ['0', '0', '0', '0'], 'Checking parts');
});

QUnit.test('Testing incorrect IPv4 addresses', function(assert) {

    var address = NET.ip_address('256.0.0.1');
    assert.ok(!address.valid, 'Out of range - 256.0.0.1');

    address = NET.ip_address('0x100.0.0.1');
    assert.ok(!address.valid, 'Out of range - 0x100.0.0.1');

    address = NET.ip_address('0400.0.0.1');
    assert.ok(!address.valid, 'Out of range - 0400.0.0.1');


    address = NET.ip_address('0x100000000');
    assert.ok(!address.valid, 'Out of range - 0x100000000');

    address = NET.ip_address('040000000000');
    assert.ok(!address.valid, 'Out of range - 040000000000');

    address = NET.ip_address('4294967296');
    assert.ok(!address.valid, 'Out of range - 4294967296');

    address = NET.ip_address('250.0.173');
    assert.ok(!address.valid, '3 parts - 250.0.173');

    address = NET.ip_address('250.0.173.21.21');
    assert.ok(!address.valid, '5 parts - 250.0.173.21.21');

    address = NET.ip_address('250.001.173.21');
    assert.ok(!address.valid, 'Trailing zeros - 250.001.173.21');

    address = NET.ip_address('250.001.173.FF');
    assert.ok(!address.valid, 'Bad hexapart - 250.01.173.FF');

    address = NET.ip_address('abcd');
    assert.ok(!address.valid, 'Word - abcd');

    address = NET.ip_address('192.168 .0.21');
    assert.ok(!address.valid, 'With space - 192.168 .0.21');

    address = NET.ip_address(' 192.168.0.21');
    assert.ok(!address.valid, 'With space - " 192.168.0.21"');
});

QUnit.test('Testing correct IPv6 addresses', function(assert) {

    var address = NET.ip_address('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    assert.ok(address.valid, 'Address - 2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    assert.deepEqual(address.parts, ['2001', '0db8', '85a3', '0000','0000','8a2e','0370','7334'], 'Checking parts');

    address = NET.ip_address('2001:db8:85a3:0:0:8a2e:370:7334');
    assert.ok(address.valid, 'Without trailing zeros - 2001:db8:85a3:0:0:8a2e:370:7334');
    assert.deepEqual(address.parts, ['2001', '0db8', '85a3', '0000','0000','8a2e','0370','7334'], 'Checking parts');

    address = NET.ip_address('2001:db8::1:0:0:1');
    assert.ok(address.valid, 'With :: - 2001:db8::1:0:0:1');
    assert.deepEqual(address.parts, ['2001', '0db8', '0000', '0000','0001','0000','0000','0001'], 'Checking parts');

    address = NET.ip_address('::1');
    assert.ok(address.valid, 'Address - ::1');
    assert.deepEqual(address.parts, ['0000', '0000', '0000', '0000','0000','0000','0000','0001'], 'Checking parts');

    address = NET.ip_address('::');
    assert.ok(address.valid, 'Address - ::');
    assert.deepEqual(address.parts, ['0000', '0000', '0000', '0000','0000','0000','0000','0000'], 'Checking parts');

    address = NET.ip_address('1::');
    assert.ok(address.valid, 'Address - 1::');
    assert.deepEqual(address.parts, ['0001', '0000', '0000', '0000','0000','0000','0000','0000'], 'Checking parts');

    address = NET.ip_address('::ffff:192.0.2.128');
    assert.ok(address.valid, 'With IPv4 part - ::ffff:192.0.2.128');
    assert.deepEqual(address.parts, ['0000', '0000', '0000', '0000','0000','ffff','c000','0280'], 'Checking parts');

});

QUnit.test('Testing incorrect IPv6 addresses', function(assert) {

    var address = NET.ip_address('02001:0db8:85a3:0000:0000:8a2e:0370:7334');
    assert.ok(!address.valid, 'Too long part- 02001:0db8:85a3:0000:0000:8a2e:0370:7334');

    address = NET.ip_address('2001:db8:85a3:0:0:8a2e:370');
    assert.ok(!address.valid, 'Missing part - 2001:db8:85a3:0:0:8a2e:370');

    address = NET.ip_address(':');
    assert.ok(!address.valid, 'Address - :');

    address = NET.ip_address('::1::');
    assert.ok(!address.valid, 'Address - ::1::');

    address = NET.ip_address(':::');
    assert.ok(!address.valid, 'Address - :::');

    address = NET.ip_address('1::1::1');
    assert.ok(!address.valid, 'Address - 1::1::1');

    address = NET.ip_address('::ffff:192.0.0x2.128');
    assert.ok(!address.valid, 'With IPv4 hex part - ::ffff:192.0.0x2.128');

    address = NET.ip_address('::ffff:192.0.02.128');
    assert.ok(!address.valid, 'With IPv4 oct part - ::ffff:192.0.02.128');

    address = NET.ip_address('aa:rt::');
    assert.ok(!address.valid, 'Invalid chars - aa:rt::');
});


QUnit.test('Testing reverse addresses', function(assert) {

    var reverse_valid = '4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa';

    var reverse = get_reverse('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    assert.deepEqual(reverse, reverse_valid, '2001:0db8:85a3:0000:0000:8a2e:0370:7334');

    reverse = get_reverse('2001:db8:85a3::8a2e:370:7334');
    assert.deepEqual(reverse, reverse_valid, '2001:db8:85a3::8a2e:370:7334');

    reverse_valid = '1.0.168.192.in-addr.arpa';
    reverse = get_reverse('192.168.0.1');
    assert.deepEqual(reverse, reverse_valid, '192.168.0.1');

    reverse_valid = '0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa';
    reverse = get_reverse('::');
    assert.deepEqual(reverse, reverse_valid, '::');

    reverse_valid = '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa';
    reverse = get_reverse('::1');
    assert.deepEqual(reverse, reverse_valid, '::1');

    reverse_valid = '0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa';
    reverse = get_reverse('1::');
    assert.deepEqual(reverse, reverse_valid, '1::');

    reverse_valid = '5.1.0.0.8.a.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa';
    reverse = get_reverse('::192.168.0.21');
    assert.deepEqual(reverse, reverse_valid, '::192.168.0.21');

    reverse_valid = '255.254.253.252.in-addr.arpa';
    reverse = get_reverse('0xFCFDFEFF');
    assert.deepEqual(reverse, reverse_valid, '0xFCFDFEFF');

    reverse = get_reverse('4244504319');
    assert.deepEqual(reverse, reverse_valid, '4244504319');

    reverse = get_reverse('037477377377');
    assert.deepEqual(reverse, reverse_valid, '037477377377');

    reverse_valid = '0.0.0.0.in-addr.arpa';
    reverse = get_reverse('0');
    assert.deepEqual(reverse, reverse_valid, '0');

    reverse = get_reverse('00');
    assert.deepEqual(reverse, reverse_valid, '00');

    reverse = get_reverse('0x0');
    assert.deepEqual(reverse, reverse_valid, '0x0');
});

QUnit.test('Usage - constructor direct input', function(assert) {

    var address = NET.ip_address('0xC0A80001');
    assert.ok(address.valid, 'Valid');
    assert.deepEqual(address.type, 'v4-int', 'Checking type');
    assert.deepEqual(address.parts, ['192', '168', '0', '1'], 'Checking parts');
    var reverse_valid = '1.0.168.192.in-addr.arpa';
    assert.deepEqual(address.get_reverse(), reverse_valid, 'Checking reverse address');
});

QUnit.test('Usage - constructor spec object', function(assert) {

    var address = NET.ip_address({ address: '0xC0A80001' });
    assert.ok(address.valid, 'Valid');
    assert.deepEqual(address.type, 'v4-int', 'Checking type');
    assert.deepEqual(address.parts, ['192', '168', '0', '1'], 'Checking parts');
    var reverse_valid = '1.0.168.192.in-addr.arpa';
    assert.deepEqual(address.get_reverse(), reverse_valid, 'Checking reverse address');
});

QUnit.test('Usage - constructor spec object - by parts', function(assert) {

    var address = NET.ip_address({
        parts: ['0xC0', '168', '00', '1'],
        type: 'v4-quads'
    });
    assert.ok(address.valid, 'Valid');
    assert.deepEqual(address.type, 'v4-quads', 'Checking type');
    assert.deepEqual(address.parts, ['192', '168', '0', '1'], 'Checking parts');
    var reverse_valid = '1.0.168.192.in-addr.arpa';
    assert.deepEqual(address.get_reverse(), reverse_valid, 'Checking reverse address');
});

QUnit.test('Usage - constructor spec object - by parts - IPv6', function(assert) {

    var address = NET.ip_address({
        parts: ['2001','db8','85a3','0','0','8a2e','370','7334'],
        type: 'v6'
    });
    assert.ok(address.valid, 'Valid');
    assert.deepEqual(address.type, 'v6', 'Checking type');
    assert.deepEqual(address.parts, ['2001','0db8','85a3','0000','0000','8a2e','0370','7334'], 'Checking parts');
    var reverse_valid = '4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa';
    assert.deepEqual(address.get_reverse(), reverse_valid, 'Checking reverse address');
});


QUnit.test('Usage - set address.input', function(assert) {

    var address = NET.ip_address();

    assert.ok(!address.valid, 'No input - invalid');
    address.input = '192.168.0.1';
    address.parse();
    assert.ok(address.valid, 'Valid');
    assert.deepEqual(address.type, 'v4-quads', 'Checking type');
    assert.deepEqual(address.parts, ['192', '168', '0', '1'], 'Checking parts');
    var reverse_valid = '1.0.168.192.in-addr.arpa';
    assert.deepEqual(address.get_reverse(), reverse_valid, 'Checking reverse address');
});

QUnit.test('Usage - set address.parts, no type', function(assert) {

    var address = NET.ip_address();

    assert.ok(!address.valid, 'No input - invalid');
    address.parts = ['192', '168', '0', '1'];
    address.parse();
    assert.ok(!address.valid, 'Still invalid');
    assert.deepEqual(address.type, null, 'Checking type');
});

};});
