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

module('ip-addresses',{
    setup: function() {
    },
    teardown: function() {
    }
});

var get_reverse = function(str) {
    var address = NET.ip_address(str);
    return address.get_reverse();
};

test('Testing correct IPv4 addresses', function() {

    var address = NET.ip_address('255.0.173.1');
    ok(address.valid, 'Dotted decimal - 255.0.173.1');
    same(address.parts, ['255', '0', '173', '1'], 'Checking parts');

    address = NET.ip_address('0377.0.0255.01');
    ok(address.valid, 'Dotted octal - 0377.0.0255.01');
    same(address.parts, ['255', '0', '173', '1'], 'Checking parts');

    address = NET.ip_address('0xFF.0x0.0xAD.0x1');
    ok(address.valid, 'Dotted hexadecimal - 0xFF.0x.0xAD.0x1');
    same(address.parts, ['255', '0', '173', '1'], 'Checking parts');

    address = NET.ip_address('4294967295');
    ok(address.valid, 'Max decimal - 4294967295');
    same(address.parts, ['255', '255', '255', '255'], 'Checking parts');

    address = NET.ip_address('037777777777');
    ok(address.valid, 'Max octal - 037777777777');
    same(address.parts, ['255', '255', '255', '255'], 'Checking parts');

    address = NET.ip_address('0xFFFFFFFF');
    ok(address.valid, 'Max hexadecimal - 0xFFFFFFFF');
    same(address.parts, ['255', '255', '255', '255'], 'Checking parts');

    address = NET.ip_address('255.0.0xAD.01');
    ok(address.valid, 'Dotted mixed - 255.0.0xAD.01');
    same(address.parts, ['255', '0', '173', '1'], 'Checking parts');

    address = NET.ip_address('0');
    ok(address.valid, 'Zero decimal - 0');
    same(address.parts, ['0', '0', '0', '0'], 'Checking parts');

    address = NET.ip_address('00');
    ok(address.valid, 'Zero octal - 00');
    same(address.parts, ['0', '0', '0', '0'], 'Checking parts');

    address = NET.ip_address('0X0');
    ok(address.valid, 'Zero hexa - 0X0');
    same(address.parts, ['0', '0', '0', '0'], 'Checking parts');
});

test('Testing incorrect IPv4 addresses', function() {

    var address = NET.ip_address('256.0.0.1');
    ok(!address.valid, 'Out of range - 256.0.0.1');

    address = NET.ip_address('0x100.0.0.1');
    ok(!address.valid, 'Out of range - 0x100.0.0.1');

    address = NET.ip_address('0400.0.0.1');
    ok(!address.valid, 'Out of range - 0400.0.0.1');


    address = NET.ip_address('0x100000000');
    ok(!address.valid, 'Out of range - 0x100000000');

    address = NET.ip_address('040000000000');
    ok(!address.valid, 'Out of range - 040000000000');

    address = NET.ip_address('4294967296');
    ok(!address.valid, 'Out of range - 4294967296');

    address = NET.ip_address('250.0.173');
    ok(!address.valid, '3 parts - 250.0.173');

    address = NET.ip_address('250.0.173.21.21');
    ok(!address.valid, '5 parts - 250.0.173.21.21');

    address = NET.ip_address('250.001.173.21');
    ok(!address.valid, 'Trailing zeros - 250.001.173.21');

    address = NET.ip_address('250.001.173.FF');
    ok(!address.valid, 'Bad hexapart - 250.01.173.FF');

    address = NET.ip_address('abcd');
    ok(!address.valid, 'Word - abcd');

    address = NET.ip_address('192.168 .0.21');
    ok(!address.valid, 'With space - 192.168 .0.21');

    address = NET.ip_address(' 192.168.0.21');
    ok(!address.valid, 'With space - " 192.168.0.21"');
});

test('Testing correct IPv6 addresses', function() {

    var address = NET.ip_address('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    ok(address.valid, 'Address - 2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    same(address.parts, ['2001', '0db8', '85a3', '0000','0000','8a2e','0370','7334'], 'Checking parts');

    address = NET.ip_address('2001:db8:85a3:0:0:8a2e:370:7334');
    ok(address.valid, 'Without trailing zeros - 2001:db8:85a3:0:0:8a2e:370:7334');
    same(address.parts, ['2001', '0db8', '85a3', '0000','0000','8a2e','0370','7334'], 'Checking parts');

    address = NET.ip_address('2001:db8::1:0:0:1');
    ok(address.valid, 'With :: - 2001:db8::1:0:0:1');
    same(address.parts, ['2001', '0db8', '0000', '0000','0001','0000','0000','0001'], 'Checking parts');

    address = NET.ip_address('::1');
    ok(address.valid, 'Address - ::1');
    same(address.parts, ['0000', '0000', '0000', '0000','0000','0000','0000','0001'], 'Checking parts');

    address = NET.ip_address('::');
    ok(address.valid, 'Address - ::');
    same(address.parts, ['0000', '0000', '0000', '0000','0000','0000','0000','0000'], 'Checking parts');

    address = NET.ip_address('1::');
    ok(address.valid, 'Address - 1::');
    same(address.parts, ['0001', '0000', '0000', '0000','0000','0000','0000','0000'], 'Checking parts');

    address = NET.ip_address('::ffff:192.0.2.128');
    ok(address.valid, 'With IPv4 part - ::ffff:192.0.2.128');
    same(address.parts, ['0000', '0000', '0000', '0000','0000','ffff','c000','0280'], 'Checking parts');

});

test('Testing incorrect IPv6 addresses', function() {

    var address = NET.ip_address('02001:0db8:85a3:0000:0000:8a2e:0370:7334');
    ok(!address.valid, 'Too long part- 02001:0db8:85a3:0000:0000:8a2e:0370:7334');

    address = NET.ip_address('2001:db8:85a3:0:0:8a2e:370');
    ok(!address.valid, 'Missing part - 2001:db8:85a3:0:0:8a2e:370');

    address = NET.ip_address(':');
    ok(!address.valid, 'Address - :');

    address = NET.ip_address('::1::');
    ok(!address.valid, 'Address - ::1::');

    address = NET.ip_address(':::');
    ok(!address.valid, 'Address - :::');

    address = NET.ip_address('1::1::1');
    ok(!address.valid, 'Address - 1::1::1');

    address = NET.ip_address('::ffff:192.0.0x2.128');
    ok(!address.valid, 'With IPv4 hex part - ::ffff:192.0.0x2.128');

    address = NET.ip_address('::ffff:192.0.02.128');
    ok(!address.valid, 'With IPv4 oct part - ::ffff:192.0.02.128');

    address = NET.ip_address('aa:rt::');
    ok(!address.valid, 'Invalid chars - aa:rt::');
});


test('Testing reverse addresses', function() {

    var reverse_valid = '4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa';

    var reverse = get_reverse('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    same(reverse, reverse_valid, '2001:0db8:85a3:0000:0000:8a2e:0370:7334');

    reverse = get_reverse('2001:db8:85a3::8a2e:370:7334');
    same(reverse, reverse_valid, '2001:db8:85a3::8a2e:370:7334');

    reverse_valid = '1.0.168.192.in-addr.arpa';
    reverse = get_reverse('192.168.0.1');
    same(reverse, reverse_valid, '192.168.0.1');

    reverse_valid = '0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa';
    reverse = get_reverse('::');
    same(reverse, reverse_valid, '::');

    reverse_valid = '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa';
    reverse = get_reverse('::1');
    same(reverse, reverse_valid, '::1');

    reverse_valid = '0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa';
    reverse = get_reverse('1::');
    same(reverse, reverse_valid, '1::');

    reverse_valid = '5.1.0.0.8.a.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa';
    reverse = get_reverse('::192.168.0.21');
    same(reverse, reverse_valid, '::192.168.0.21');

    reverse_valid = '255.254.253.252.in-addr.arpa';
    reverse = get_reverse('0xFCFDFEFF');
    same(reverse, reverse_valid, '0xFCFDFEFF');

    reverse = get_reverse('4244504319');
    same(reverse, reverse_valid, '4244504319');

    reverse = get_reverse('037477377377');
    same(reverse, reverse_valid, '037477377377');

    reverse_valid = '0.0.0.0.in-addr.arpa';
    reverse = get_reverse('0');
    same(reverse, reverse_valid, '0');

    reverse = get_reverse('00');
    same(reverse, reverse_valid, '00');

    reverse = get_reverse('0x0');
    same(reverse, reverse_valid, '0x0');
});

test('Usage - constructor direct input', function() {

    var address = NET.ip_address('0xC0A80001');
    ok(address.valid, 'Valid');
    same(address.type, 'v4-int', 'Checking type');
    same(address.parts, ['192', '168', '0', '1'], 'Checking parts');
    var reverse_valid = '1.0.168.192.in-addr.arpa';
    same(address.get_reverse(), reverse_valid, 'Checking reverse address');
});

test('Usage - constructor spec object', function() {

    var address = NET.ip_address({ address: '0xC0A80001' });
    ok(address.valid, 'Valid');
    same(address.type, 'v4-int', 'Checking type');
    same(address.parts, ['192', '168', '0', '1'], 'Checking parts');
    var reverse_valid = '1.0.168.192.in-addr.arpa';
    same(address.get_reverse(), reverse_valid, 'Checking reverse address');
});

test('Usage - constructor spec object - by parts', function() {

    var address = NET.ip_address({
        parts: ['0xC0', '168', '00', '1'],
        type: 'v4-quads'
    });
    ok(address.valid, 'Valid');
    same(address.type, 'v4-quads', 'Checking type');
    same(address.parts, ['192', '168', '0', '1'], 'Checking parts');
    var reverse_valid = '1.0.168.192.in-addr.arpa';
    same(address.get_reverse(), reverse_valid, 'Checking reverse address');
});

test('Usage - constructor spec object - by parts - IPv6', function() {

    var address = NET.ip_address({
        parts: ['2001','db8','85a3','0','0','8a2e','370','7334'],
        type: 'v6'
    });
    ok(address.valid, 'Valid');
    same(address.type, 'v6', 'Checking type');
    same(address.parts, ['2001','0db8','85a3','0000','0000','8a2e','0370','7334'], 'Checking parts');
    var reverse_valid = '4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa';
    same(address.get_reverse(), reverse_valid, 'Checking reverse address');
});


test('Usage - set address.input', function() {

    var address = NET.ip_address();

    ok(!address.valid, 'No input - invalid');
    address.input = '192.168.0.1';
    address.parse();
    ok(address.valid, 'Valid');
    same(address.type, 'v4-quads', 'Checking type');
    same(address.parts, ['192', '168', '0', '1'], 'Checking parts');
    var reverse_valid = '1.0.168.192.in-addr.arpa';
    same(address.get_reverse(), reverse_valid, 'Checking reverse address');
});

test('Usage - set address.parts, no type', function() {

    var address = NET.ip_address();

    ok(!address.valid, 'No input - invalid');
    address.parts = ['192', '168', '0', '1'];
    address.parse();
    ok(!address.valid, 'Still invalid');
    same(address.type, null, 'Checking type');
});