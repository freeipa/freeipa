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

var NET = {};

NET.ip_address = function(spec) {

    spec = spec || {};

    if (typeof spec === 'string') {
        spec = {
            address: spec
        };
    }

    var that = {};

    that.input = spec.address;

    that.type = spec.type;
    that.parts = spec.parts;
    that.reverse_address = '';
    that.only_decimal = spec.only_decimal !== undefined? spec.only_decimal :
                            false; //for parsing IPv4 address

    that.parse = function() {

        if (!that.input && !that.parts) {
            that.set_error('no input');
            return false;
        }

        if (!that.type) {
            that.type = that.detect_type();
        }

        if (that.type === 'v4-quads') {
            return that.parse_v4_quads();
        } else if (that.type === 'v4-int') {
            return that.parse_v4_int();
        } else if (that.type === 'v6') {
            return that.parse_v6();
        }

        that.set_error('not an ip address');
        return false;
    };

    that.detect_type = function() {

        var type;

        if (!that.input) return null;

        if (that.input.indexOf(':') > -1) type = 'v6';
        else if (that.input.indexOf('.') > -1) type = 'v4-quads';
        else type = 'v4-int';

        return type;
    };

    that.parse_v4_int = function() {

        var part = { value: that.input };
        if(!that.is_part_valid_v4(part, 32, that.only_decimal)) return false;

        that.parts = [];
        that.make_quads(part.decimal_value, that.parts);

        that.valid = true;
        return true;
    };

    that.parse_v4_quads = function() {

        if (!that.parts) {
            that.parts = that.input.split('.');
        }

        if (that.parts.length !== 4) {
            return that.set_error('invalid number of parts');
        }

        for (var i=0; i<4; i++) {

            var part = { value: that.parts[i] };

            if (!that.is_part_valid_v4(part, 8, that.only_decimal)) {
                return false;
            }
            that.parts[i] = part.decimal_value.toString(10);
        }

        that.valid = true;
        return true;
    };

    that.parse_v6 = function() {

        if (!that.parts) {
            that.parts = that.input.split(':');
        }

        var total_parts = that.parts.length;
        var ipv4_present = false;
        var double_colon = false;
        var double_colon_position;

        var i;

        //usecases like ':'
        if (that.parts.length <= 2) {
            return that.set_error('invalid format');
        }

        for (i=0; i<that.parts.length; i++) {
            var part = that.parts[i];

            if (i === that.parts.length -1 && part.indexOf('.') > -1) {
                ipv4_present = true;
                total_parts++; //ipv4 part consists of 4 octects (two parts)
            }

            //checking for ::
            if (part.length === 0) {

                if (!double_colon || //first occurance
                        (double_colon && i === 1) || //still at the beginning
                        (double_colon && i === that.parts.length - 1 &&
                            double_colon_position === i -1)) { //still at the end

                    part = '0000';
                    that.parts[i] = part;
                    double_colon = true;
                    double_colon_position = i;
                } else { //second occurance of ::
                    return that.set_error('invalid format: mupltiple ::');
                }
            }

            //add missing zeros for not empty parts
            if (part.length !== 0 && part.length < 4) {
                part = add_leading_zeros(part, 4 - part.length);
                that.parts[i] = part;
            }
        }

        //add missing empty parts
        if (double_colon) {
            var parts_to_add = 8 - total_parts;

            for (i=0; i<parts_to_add; i++) {
                that.parts.splice(double_colon_position, 0, '0000');
            }
        }

        //change ipv4 part
        if (ipv4_present) {
            var ipv4_address = NET.ip_address();
            ipv4_address.input = that.parts[that.parts.length -1];
            ipv4_address.only_decimal = true;
            if (ipv4_address.parse() && ipv4_address.type === 'v4-quads') {
                var v4_parts = ipv4_address.parts;
                var oct1 = dec_2_hex(v4_parts[0]);
                var oct2 = dec_2_hex(v4_parts[1]);
                var oct3 = dec_2_hex(v4_parts[2]);
                var oct4 = dec_2_hex(v4_parts[3]);

                //replace IPv4 part with two IPv6 parts (4 octets)
                that.parts[that.parts.length -1] = oct1+oct2;
                that.parts.push(oct3+oct4);
            } else {
                return that.set_error('invalid IPv4 part');
            }
        }

        //validate length after modifications
        if (that.parts.length !== 8) {
            return that.set_error('invalid number of parts');
        }

        //validate each part
        for (i=0; i<8; i++) {

            if (!that.is_part_valid_v6(that.parts[i])) {
                return false;
            }
        }

        that.valid = true;
        return true;
    };

    function dec_2_hex(val) {
        var dec = parseInt(val, 10);
        var hex = dec.toString(16);
        hex = add_leading_zeros(hex, 2 - hex.length);
        return hex;
    }

    function add_leading_zeros(val, num) {
        for (var i=0; i<num; i++) {
            val='0'+val;
        }
        return val;
    }

    that.get_reverse = function() {

        if (!that.valid) return 'invalid input address';

        if (that.type === 'v4-quads' || that.type === 'v4-int') {
            return that.get_v4_reverse();
        } else if (that.type === 'v6') {
            return that.get_v6_reverse();
        }

        return '';
    };

    that.get_v4_reverse = function() {

        that.reverse_parts = [];

        for (var i=3; i>=0; i--) {
            that.reverse_parts.push(that.parts[i]);
        }

        that.reverse_parts.push('in-addr');
        that.reverse_parts.push('arpa');

        return that.reverse_parts.join('.');
    };

    that.get_v6_reverse = function() {

        that.reverse_parts = [];

        var address = that.parts.join('');

        for (var i=31; i>=0; i--) {
            that.reverse_parts.push(address[i]);
        }

        that.reverse_parts.push('ip6');
        that.reverse_parts.push('arpa');

        return that.reverse_parts.join('.');
    };

    that.set_error = function(msg) {
        that.valid = false;
        that.error = msg;
        return false;
    };

    that.is_part_valid_v6 = function(str) {

        if (str.length === 0) {
            return that.set_error('not a number');
        }

        if (str.length > 4) {
            return that.set_error('wrong format - too long');
        }

        for (var i=0; i<str.length; i++) {

            var digit = parseInt(str[i], 16);

            //check if character is digit
            if (isNaN(digit)) {
                return that.set_error('invalid format: \''+digit+'\'');
            }
        }

        return true;
    };

    /*
     * Checks if part.value is valid IPv4 integer of given size (in bits).
     * Validation can be limited only to decimal values by only_decimal argument.
     * Sets its decimal representation to part.decimal_value.
     */
    that.is_part_valid_v4 = function(part, bits, only_decimal) {

        if (!part.value || part.value.length === 0) {
            return that.set_error('not a number');
        }

        var radix = that.get_radix(part.value);

        var number = part.value;

        if (radix === 16) number = part.value.substring(2);
        else if (radix === 8) number = part.value.substring(1);

        if (radix !== 10 && only_decimal) {
            return that.set_error('not a decimal number');
        }

        for (var i=0; i<number.length; i++) {

            var digit = parseInt(number[i], radix);

            //check if character is digit in its radix
            if (isNaN(digit)) {
                return that.set_error('invalid format: \''+digit+'\'');
            }

            //check for leading zeros
            if (i === 0 && digit === 0 && number.length > 1) {
                return that.set_error('invalid format: leading zeros');
            }
        }

        var max_value = Math.pow(2, bits) - 1;

        part.decimal_value = parseInt(part.value, radix);

        if (part.decimal_value > max_value) {
            return that.set_error('value out of range');
        }

        return true;
    };

    that.get_radix = function(str) {

        var normalized = str.toLowerCase();

        if (normalized.length > 2 &&
                normalized[0] === '0' &&
                normalized[1] === 'x') {
            return 16;

        } else if (normalized.length > 1 && normalized[0] === '0') {
            return 8;
        }

        return 10;
    };

    that.make_quads = function(integer, quads) {

        var hex_str = integer.toString(16);
        if (hex_str.length < 8) {
            hex_str = add_leading_zeros(hex_str, 8 - hex_str.length);
        }

        for (var i=0; i<hex_str.length; i+=2) {
            var quad_hex = hex_str.substring(i,i+2);
            var quad = parseInt(quad_hex, 16);
            quads.push(quad.toString(10));
        }
    };

    that.get_radix = function(str) {

        var normalized = str.toLowerCase();

        if (normalized.length > 2 &&
                normalized[0] === '0' &&
                normalized[1] === 'x') {
            return 16;

        } else if (normalized.length > 1 && normalized[0] === '0') {
            return 8;
        }

        return 10;
    };

    that.parse();

    return that;
};