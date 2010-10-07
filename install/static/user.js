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
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('user', [
    'dialog-add-user', 'Add New User', [
        ['uid', 'Login', null],
        ['givenname', 'First Name', null],
        ['sn', 'Last Name', null]
    ]
]);

ipa_entity_set_details_definition('user', [
    {name:'identity', label:'Identity Details', fields:[
        {name:'title', label:'Title'},
        {name:'givenname', label:'First Name'},
        {name:'sn', label:'Last Name'},
        {name:'cn', label:'Full Name'},
        {name:'displayname', label:'Dispaly Name'},
        {name:'initials', label:'Initials'}
    ]},
    {name:'account', label:'Account Details', fields:[
        {name:'status', label:'Account Status', load:user_status_load},
        {name:'uid', label:'Login'},
        {name:'userpassword', label:'Password', load:user_password_load},
        {name:'uidnumber', label:'UID'},
        {name:'gidnumber', label:'GID'},
        {name:'homedirectory', label:'homedirectory'}
    ]},
    {name:'contact', label:'Contact Details', fields:[
        {name:'mail', label:'E-mail Address'},
        {name:'telephonenumber', label:'Numbers', load:user_telephonenumber_load}
    ]},
    {name:'address', label:'Mailing Address', fields:[
        {name:'street', label:'Address'},
        {name:'location', label:'City'},
        {name:'state', label:'State', load:user_state_load},
        {name:'postalcode', label:'ZIP'}
    ]},
    {name:'employee', label:'Employee Information', fields:[
        {name:'ou', label:'Org. Unit'},
        {name:'manager', label:'Manager', load:user_manager_load}
    ]},
    {name:'misc', label:'Misc. Information', fields:[
        {name:'carlicense', label:'Car License'}
    ]}
]);

ipa_entity_set_association_definition('user', {
    'group': { associator: SerialAssociator },
    'netgroup': { associator: SerialAssociator },
    'rolegroup': { associator: SerialAssociator },
    'taskgroup': { associator: SerialAssociator }
});

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
function user_status_load(dt, result)
{
    var memberof = result['memberof'];
    var dd;

    if (memberof) {
        for (var i = 0; i < memberof.length; ++i) {
            if (memberof[i].indexOf('cn=inactivated,cn=account inactivation') != -1) {
                var t = toggle_temp.replace(/S/g, 'Inactive');
                dd = ipa_create_first_dd(this.name, t);
                dt.after(dd);
                return;
            }
        }
    }

    dd = ipa_create_first_dd(this.name, toggle_temp.replace(/S/g, 'Inactive'));
    dt.after(dd);
}

var pwd_temp = '<a href="jslink" onclick="return (resetpwd_on_click(this))" title="A">Reset Password</a>';
function user_password_load(dt, result)
{
    var dd = ipa_create_first_dd(this.name, pwd_temp.replace('A', 'userpassword'));
    dt.after(dd);
}

var select_temp = '<select title="st"></select>';
var option_temp = '<option value="V">V</option>';
var states = [
    'AL', 'AK', 'AS', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'DC', 'FM',
    'FL', 'GA', 'GU', 'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA',
    'ME', 'MH', 'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV',
    'NH', 'NJ', 'NM', 'NY', 'NC', 'ND', 'MP', 'OH', 'OK', 'OR', 'PW',
    'PA', 'PR', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT', 'VT', 'VI', 'VA',
    'WA', 'WV', 'WI', 'WY', ''
];
function user_state_load(dt, result)
{
    var next = dt.next();
    next.css('clear', 'none');
    next.css('width', '70px');

    var dd = ipa_create_first_dd(this.name, select_temp);
    dt.after(dd);

    var sel = dt.next().children().first();
    for (var i = 0; i < states.length; ++i)
        sel.append(option_temp.replace(/V/g, states[i]));

    var st = result['st'];
    if (st)
        sel.val(st);
    else
        sel.val('');
}

function user_telephonenumber_load(dt, result)
{
}

function user_manager_load(dt, result)
{
}
