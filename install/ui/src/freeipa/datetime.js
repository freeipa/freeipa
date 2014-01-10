/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2014 Red Hat
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


define([
        'dojo/string'
        ], function(string) {

    var templates = {
        human: '${YYYY}-${MM}-${DD} ${HH}:${mm}:${ss}Z',
        generalized: '${YYYY}${MM}${DD}${HH}${mm}${ss}Z'
    };

    var dates = [
        ['YYYY-MM-DD', /^(\d{4})-(\d{2})-(\d{2})$/],
        ['YYYYMMDD',/^(\d{4})(\d{2})(\d{2})$/]
    ];

    var times = [
        ['HH:mm:ss', /^(\d\d):(\d\d):(\d\d)$/],
        ['HH:mm', /^(\d\d):(\d\d)$/]
    ];

    var generalized_regex = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
    var datetime_regex = /^((?:\d{8})|(?:\d{4}-\d{2}-\d{2}))(?:(T| )(\d\d:\d\d(?::\d\d)?)(Z?))?$/;

    function parse(value) {

        var Y=0, M=0, D=0, H=0, m=0, s=0;
        var i, l, dateStr, timeStr, utc;

        var dt_match = datetime_regex.exec(value);
        var gt_match = generalized_regex.exec(value);
        if (dt_match) {
            dateStr = dt_match[1];
            timeStr = dt_match[3];
            utc = dt_match[4] || !timeStr;

            // error out if local time not supported
            if (!this.allow_local && !utc) return null;

            for (i = 0, l = dates.length; i < l; i++) {
                var dm = dates[i][1].exec(dateStr);
                if (dm) {
                    Y = dm[1];
                    M = dm[2];
                    D = dm[3];
                    break;
                }
            }

            if (timeStr) {
                for (i = 0, l = times.length; i < l; i++) {
                    var tm = times[i][1].exec(timeStr);
                    if (tm) {
                        H = tm[1];
                        m = tm[2] || 0;
                        s = tm[3] || 0;
                        break;
                    }
                }
            }
        } else if (gt_match) {
            Y = gt_match[1];
            M = gt_match[2];
            D = gt_match[3];
            H = gt_match[4];
            m = gt_match[5];
            s = gt_match[6];
            utc = true;
        } else {
            return null;
        }

        var date = new Date();

        if (utc || !timeStr) {
            date.setUTCFullYear(Y, M-1, D);
            date.setUTCHours(H, m, s, 0);
        } else {
            date.setFullYear(Y, M-1, D);
            date.setHours(H, m, s, 0);
        }
        return date;
    }

    function formatDate(date, format, local) {

        var fmt = format || templates.human;
        var str;

        function pad(value) {
            return string.pad(value, 2, '0');
        }

        if (local) {
            str = string.substitute(fmt, {
                YYYY: date.getFullYear(),
                MM: pad(date.getMonth()+1),
                DD: pad(date.getDate()),
                HH: pad(date.getHours()),
                mm: pad(date.getMinutes()),
                ss: pad(date.getSeconds())
            });
        } else {
            str = string.substitute(fmt, {
                YYYY: date.getUTCFullYear(),
                MM: pad(date.getUTCMonth()+1),
                DD: pad(date.getUTCDate()),
                HH: pad(date.getUTCHours()),
                mm: pad(date.getUTCMinutes()),
                ss: pad(date.getUTCSeconds())
            });
        }
        return str;
    }

    /**
     * Utility module to parse strings in ISO 8601-ish format into Date object
     * and vice versa
     *
     * @class datetime
     * @singleton
     */
    var datetime = {
        /**
         * Parse string, return date or null on error.
         *
         * Supported date formats:
         *
         * - `YYYY-MM-DD`
         * - `YYYYMMDD`
         *
         * Supported time formats:
         *
         * - `HH:mm:ss`
         * - `HH:mm`
         *
         * Supported formats:
         *
         * - `$dateT$timeZ`
         * - `$date $timeZ`
         * - `$date`
         * - `YYYYMMDDHHmmssZ`
         *
         * Where Z indicates UTC date. Parsing of local dates is by default
         * disabled. It can be enabled by setting `datetime.allow_local` to
         * `true`.
         *
         * @param {string} value
         * @returns {Date|null} parsed date
         */
        parse: parse,

        /**
         * Convert date to string
         *
         * - `${YYYY}` - year
         * - `${MM}` - month
         * - `${DD}` - day
         * - `${HH}` - hours
         * - `${mm}` - minutes
         * - `${ss}` - seconds
         *
         * Default format string: `${YYYY}-${MM}-${DD} ${HH}:${mm}:${ss}`
         *
         * @param {Date} date
         * @param {string} [format] format string
         * @param {boolean} [local] use local time
         */
        format: formatDate,

        /**
         * Local time input method support
         * @property {boolean}
         */
        allow_local: false,

        /**
         * Convert date value to generalized time string
         * @param {Date} date
         * @returns {string}
         */
        to_generalized_time: function(date) {
            return this.format(date, templates.generalized);
        },

        /**
         * Dictionary of common format strings
         *
         * - `human` - default format string of `format` method
         * - `generalized` - generalized time (LDAP) format
         *
         * @property {Object}
         */
        templates: templates
    };

    return datetime;
});