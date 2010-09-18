/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

ipa_entity_set_search_definition('user', [
    ['cn', 'Name', null],
    ['uid', 'Login', null],
    ['uidnumber', 'UID', null],
    ['mail', 'EMAIL', null],
    ['telephonenumber', 'Phone', null],
    ['title', 'Job Title', null],
    ['quick_links', 'Quick Links', user_render_quick_links]
]);

ipa_entity_set_add_definition('user', [
    'dialog-add-user', 'Add New User', [
        ['uid', 'Login', null],
        ['givenname', 'First Name', null],
        ['sn', 'Last Name', null]
    ]
]);

ipa_entity_set_details_definition('user', [
    ['identity', 'Identity Details', [
        ['title', 'Title', null],
        ['givenname', 'First Name', null],
        ['sn', 'Last Name', null],
        ['cn', 'Full Name', null],
        ['displayname', 'Dispaly Name', null],
        ['initials', 'Initials', null]
    ]],
    ['account', 'Account Details', [
        ['status', 'Account Status', a_status],
        ['uid', 'Login', null],
        ['userpassword', 'Password', a_password],
        ['uidnumber', 'UID', null],
        ['gidnumber', 'GID', null],
        ['homedirectory', 'homedirectory', null]
    ]],
    ['contact', 'Contact Details', [
        ['mail', 'E-mail Address', null],
        ['numbers', 'Numbers', a_numbers]
    ]],
    ['address', 'Mailing Address', [
        ['street', 'Address', null],
        ['location', 'City', null],
        ['state', 'State', a_st],
        ['postalcode', 'ZIP', null]
    ]],
    ['employee', 'Employee Information', [
        ['ou', 'Org. Unit', null],
        ['manager', 'Manager', a_manager]
    ]],
    ['misc', 'Misc. Information', [
        ['carlicense', 'Car License', null]
    ]]
]);

/* Account status Toggle button */

function toggle_on_click(obj)
{
    var jobj = $(obj);
    var val = jobj.attr('title');
    if (val == 'Active') {
        ipa_cmd(
            'lock', [qs['pkey']], {}, on_lock_win, on_fail,
            ipa_objs['user']['name']
        );
    } else {
        ipa_cmd(
            'unlock', [qs['pkey']], {}, on_lock_win, on_fail,
            ipa_objs['user']['name']
        );
    }
    return (false);
}

function on_lock_win(data, textStatus, xhr)
{
    if (data['error']) {
        alert(data['error']['message']);
        return;
    }

    var jobj = $('a[title=Active]');
    if (jobj.length) {
        if (ipa_details_cache) {
            var memberof = ipa_details_cache['memberof'];
            if (memberof) {
                memberof.push(
                    'cn=inactivated,cn=account inactivation'
                );
            } else {
                memberof = ['cn=inactivated,cn=account inactivation'];
            }
            ipa_details_cache['memberof'] = memberof;
            a_status(jobj.parent().prev(), ipa_details_cache);
            jobj.parent().remove()
        }
        return;
    }

    var jobj = $('a[title=Inactive]');
    if (jobj.length) {
        if (ipa_details_cache) {
            var memberof = ipa_details_cache['memberof'];
            if (memberof) {
                for (var i = 0; i < memberof.length; ++i) {
                    if (memberof[i].indexOf('cn=inactivated,cn=account inactivation') != -1) {
                        memberof.splice(i, 1);
                        break;
                    }
                }
            } else {
                memberof = [];
            }
            ipa_details_cache['memberof'] = memberof;
            a_status(jobj.parent().prev(), ipa_details_cache);
            jobj.parent().remove();
        }
        return;
    }
}

/* ATTRIBUTE CALLBACKS */

var toggle_temp = 'S <a href="jslink" onclick="return (toggle_on_click(this))" title="S">Toggle</a>';
function a_status(jobj, result, mode)
{
    if (mode != IPA_DETAILS_POPULATE)
        return;

    var memberof = result['memberof'];
    if (memberof) {
        for (var i = 0; i < memberof.length; ++i) {
            if (memberof[i].indexOf('cn=inactivated,cn=account inactivation') != -1) {
                var t = toggle_temp.replace(/S/g, 'Inactive');
                ipa_insert_first_dd(jobj, t);
                return;
            }
        }
    }
    ipa_insert_first_dd(jobj, toggle_temp.replace(/S/g, 'Inactive'));
}

var pwd_temp = '<a href="jslink" onclick="return (resetpwd_on_click(this))" title="A">Reset Password</a>';
function a_password(jobj, result, mode)
{
    if (mode == IPA_DETAILS_POPULATE)
        ipa_insert_first_dd(jobj, pwd_temp.replace('A', 'userpassword'));
}

var select_temp = '<select title="st"></select>';
var option_temp = '<option value="V">V</option>';
var states = [
    'AL', 'AK', 'AS', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'DC', 'FM',
    'FL', 'GA', 'GU', 'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA',
    'ME', 'MH', 'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV',
    'NH', 'NJ', 'NM', 'NY', 'NC', 'ND', 'MP', 'OH', 'OK', 'OR', 'PW',
    'PA', 'PR', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT', 'VT', 'VI', 'VA',
    'WA', 'WV', 'WI', 'WY', '',
];
function a_st(jobj, result, mode)
{
    if (mode != IPA_DETAILS_POPULATE)
        return;

    var next = jobj.next();
    next.css('clear', 'none');
    next.css('width', '70px');

    ipa_insert_first_dd(jobj, select_temp);

    var sel = jobj.next().children().first();
    for (var i = 0; i < states.length; ++i)
        sel.append(option_temp.replace(/V/g, states[i]));

    var st = result['st'];
    if (st)
        sel.val(st);
    else
        sel.val('');
}

function a_numbers(jobj, result, mode)
{
}

function a_manager(jobj, result, mode)
{
}

function user_render_quick_links(tr, attr, value, entry_attrs) {

    var td = $("<td/>");
    tr.append(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='user_details.png' />"),
        click: function() {
            var state = {};
            state['user-facet'] = 'details';
            state['user-pkey'] = entry_attrs['uid'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='group_member.png' />"),
        click: function() {
            var state = {};
            state['user-facet'] = 'associate';
            state['user-enroll'] = 'group';
            state['user-pkey'] = entry_attrs['uid'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='netgroup_member.png' />"),
        click: function() {
            var state = {};
            state['user-facet'] = 'associate';
            state['user-enroll'] = 'netgroup';
            state['user-pkey'] = entry_attrs['uid'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='rolegroup_member.png' />"),
        click: function() {
            var state = {};
            state['user-facet'] = 'associate';
            state['user-enroll'] = 'role';
            state['user-pkey'] = entry_attrs['uid'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);
}
