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
    ipa_stanza({name:'identity', label:'Identity Details'}).
        input({name:'title', label: 'Title'}).
        input({name:'givenname', label:'First Name'}).
        input({name:'sn', label:'Last Name'}).
        input({name:'cn', label:'Full Name'}).
        input({name:'displayname', label:'Dispaly Name'}).
        input({name:'initials', label:'Initials'}),
    ipa_stanza({name:'account', label:'Account Details'}).
        input({name:'status', label:'Account Status', load:user_status_load}).
        input({name:'uid', label:'Login'}).
        input({name:'userpassword',
               label:'Password',
               load: user_password_load}).
        input({name:'uidnumber', label:'UID'}).
        input({name:'gidnumber', label:'GID'}).
        input({name:'homedirectory', label:'homedirectory'}),
    ipa_stanza({name:'contact', label:'Contact Details'}).
        input({name:'mail', label:'E-mail Address'}).
        input({name:'telephonenumber', label:'Phone Numbers'}).
        input({name:'pager', label:'Pager Numbers'}).
        input({name:'mobile', label:'Mobile Phone Numbers'}).
        input({name:'facsimiletelephonenumber', label:'Fax Numbers'}),
    ipa_stanza({name:'address', label:'Mailing Address'}).
        input({name:'street', label:'Address'}).
        input({name:'location', label:'City'}).
        input({name:'state', label:'State', load:user_state_load}).
        input({name:'postalcode', label:'ZIP'}),
    ipa_stanza({name:'employee', label:'Employee Information'}).
        input({name:'ou', label:'Org. Unit'}).
        input({name:'manager', label:'Manager'}),
    ipa_stanza({name:'misc', label:'Misc. Information'}).
        input({name:'carlicense', label:'Car License'})
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
            IPA.metadata['user']['name']
        );
    } else {
        ipa_cmd(
            'unlock', [qs['pkey']], {}, on_lock_win, on_fail,
            IPA.metadata['user']['name']
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
function user_status_load(container, dt, result)
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



function resetpwd_on_click(){

    function reset_password(new_password){
        var dialog =  resetpwd_dialog;

        var user_pkey = $.bbq.getState('user-pkey');
        var pw_pkey;
        if (user_pkey === ipa_whoami_pkey){
            pw_pkey = [];
        }else{
            pw_pkey = [user_pkey];
        }

        ipa_cmd('passwd',
                pw_pkey, {"password":new_password},
                function(){
                    alert("Password change complete");
                    dialog.dialog("close");
                },
                function(){});
    }


    var resetpwd_dialog =
        $('<div ><dl class="modal">'+
          '<dt>New Password</dt>'+
          '<dd class="first" ><input id="password_1" type="password"/></dd>'+
          '<dt>Repeat Password</dt>'+
          '<dd class="first"><input id="password_2" type="password"/></dd>'+
          '</dl></div>');
    resetpwd_dialog.dialog(
        { modal: true,
          minWidth:400,
          buttons: {
              'Reset Password': function(){
                  var p1 = $("#password_1").val();
                  var p2 = $("#password_2").val();
                  if (p1 != p2){
                      alert("passwords must match");
                      return;
                  }
                  reset_password(p1);
              },
              'Cancel':function(){
                  resetpwd_dialog.dialog('close');
              }
          }});
    return false;
}

function user_password_load(container, dt, result)
{
    dt.after(ipa_create_first_dd(
        this.name,
        $('<a/>',{
            href:"jslink",
            click:resetpwd_on_click,
            title:'userpassword',
            text: 'reset password'
        })));
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
function user_state_load(container, dt, result)
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


