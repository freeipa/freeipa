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
        input({name:'givenname'}).
        input({name:'sn'}).
        input({name:'cn', label:'Full Name'}).
        input({name:'displayname', label:'Display Name'}).
        input({name:'initials', label:'Initials'}),
    ipa_stanza({name:'account', label:'Account Details'}).
        input({name:'nsaccountlock', label:'Account Status',
               load:user_status_load}).
        input({name:'uid'}).
        input({name:'userpassword',
               load: user_password_load}).
        input({name:'uidnumber'}).
        input({name:'gidnumber', label:'GID'}).
        input({name:'loginshell'}).
        input({name:'homedirectory'}),
    ipa_stanza({name:'contact', label:'Contact Details'}).
        input({name:'mail'}).
        input({name:'telephonenumber'}).
        input({name:'pager'}).
        input({name:'mobile'}).
        input({name:'facsimiletelephonenumber'}),
    ipa_stanza({name:'address', label:'Mailing Address'}).
        input({name:'street'}).
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
    'group': { associator: 'serial' },
    'netgroup': { associator: 'serial' },
    'rolegroup': { associator: 'serial' },
    'taskgroup': { associator: 'serial' }
});





/* ATTRIBUTE CALLBACKS */


function user_status_load(container, result) {
    var lock_field = 'nsaccountlock';

    var dt = $('dt[title='+this.name+']', container);
    if (!dt.length) return;

    var locked  = result[lock_field] &&
        result[lock_field][0].toLowerCase() === 'true';
    var title = "Active";
    var text = "Active:  Click to Deactivate";
    if (locked) {
        title = "Inactive";
        text = "Inactive:  Click to Activate";
    }

    function on_lock_win(data, textStatus, xhr){
        alert(data.result.summary);
        $.bbq.pushState('user-facet','search');
        return false;
    }

    function on_lock_fail(data, textStatus, xhr){
        $("#userstatuslink").text = "Error changing account status";
        return false;
    }

    var status_field =
        $('<a/>',
          {
              id: 'userstatuslink',
              title: title,
              href: "jslink",
              text: text,
              click: function() {
                  var jobj = $(this);
                  var val = jobj.attr('title');
                  var pkey =  $.bbq.getState('user-pkey');
                  var command = 'user_enable';
                  if (val == 'Active') {
                      command = 'user_disable';
                  }
                  ipa_cmd(command, [pkey], {}, on_lock_win,on_lock_fail);

                  return (false);
              }
          });

    dt.after(ipa_create_first_dd(this.name, status_field));
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

function user_password_load(container, result) {
    var dt = $('dt[title='+this.name+']', container);
    if (!dt.length) return;

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
function user_state_load(container, result) {
    var dt = $('dt[title='+this.name+']', container);
    if (!dt.length) return;

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


