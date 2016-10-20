/*  Authors:
 *    Zheng Lei <zhenglei@kylinos.cn>
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

define([
        './builder',
        './ipa',
        './jquery',
        './phases',
        './reg',
        './rpc',
        './text',
        './dialogs/password',
        './details',
        './search',
        './association',
        './entity',
        './certificate'],
    function(builder, IPA, $, phases, reg, rpc, text, password_dialog) {

/**
 * Log module
 * @class log
 * @alternateClassName IPA.log
 * @singleton
 */
var exp = IPA.log = {};

var make_spec = function() {
return {
    name: 'log',
    label: '日志',
    facets: [
        {
    	    label: '日志',
            $type: 'search',
            // setting no_update value(ture) to control add and remove buttons invisible
            no_update: true,
            // setting selectable value(false) to control checkbox invisible
            selectable: false,
            columns: [
                { name: 'logtime', label: "时间" },
                { name: 'loglevel', label: "级别" },
                { name: 'loguser', label: "用户" },
                { name: 'logip', label: "远程地址" },
                { name: 'logstatus', label: "状态" },
                { name: 'logmessage', label: "信息" }
            ],
        },
    ],
}
};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'log', spec: exp.entity_spec});
};

phases.on('registration', exp.register);

return exp;
});
