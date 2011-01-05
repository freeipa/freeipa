/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

function ipa_user(){

    var that = ipa_entity({
        name: 'user'
    });

    that.init = function() {

        that.create_association({
            'name': 'group',
            'associator': 'serial'
        });

        that.create_association({
            'name': 'netgroup',
            'associator': 'serial'
        });

        var search_facet = ipa_search_facet({
            'name': 'search',
            'label': 'Search',
            entity_name: that.name
        });
        that.add_facet(search_facet);

        search_facet.create_column({name:'cn'});
        search_facet.create_column({name:'uid'});
        search_facet.create_column({name:'uidnumber'});
        search_facet.create_column({name:'mail'});
        search_facet.create_column({name:'telephonenumber'});
        search_facet.create_column({name:'title'});

        that.add_facet(details_facet({name:'details',label:'Details'}));

        var dialog = ipa_add_dialog({
            'name': 'add',
            'title': 'Add User'
        });
        that.add_dialog(dialog);

        dialog.add_field(ipa_text_widget({ name: 'uid', undo: false }));
        dialog.add_field(ipa_text_widget({ name: 'givenname', undo: false }));
        dialog.add_field(ipa_text_widget({ name: 'sn', undo: false }));
        dialog.init();

        /*eventually,  we need to call
          entity.create_association_facets();
          but we are currently defining the associator using the global
          function after the registration of the entity */
      that.create_association_facets();

        that.entity_init();
    };

    function details_facet(spec) {
        spec = spec || {};
        var that = ipa_details_facet(spec);

        var sections =[
            ipa_stanza({name:'identity', label:'Identity Details'}).
                input({name:'title'}).
                input({name:'givenname'}).
                input({name:'sn'}).
                input({name:'cn'}).
                input({name:'displayname'}).
                input({name:'initials'}),
            ipa_stanza({name:'account', label:'Account Details'}).
                custom_input(user_status_widget({name:'nsaccountlock'})).
                input({name:'uid'}).
                input({name:'userpassword', load: user_password_load}).
                input({name:'uidnumber'}).
                input({name:'gidnumber'}).
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
                input({name:'location'}).
                input({name:'state', load:user_state_load}).
                input({name:'postalcode'}),
            ipa_stanza({name:'employee', label:'Employee Information'}).
                input({name:'ou', label:'Org. Unit'}).
                input({name:'manager'}),
            ipa_stanza({name:'misc', label:'Misc. Information'}).
                input({name:'carlicense'})
        ];
        for (var i = 0; i < sections.length; i += 1){
            that.add_section(sections[i]);
        }
        return that;
    }
    return that;
}
IPA.add_entity(ipa_user());

/* ATTRIBUTE CALLBACKS */


function user_status_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.update = function() {

        if (!that.record) return;

        $('dd', that.container).remove();

        var dd = ipa_create_first_dd(this.name);
        dd.appendTo(that.container);

        var lock_field = 'nsaccountlock';

        var locked  = that.record[lock_field] &&
            that.record[lock_field][0].toLowerCase() === 'true';
        var title = "Active";
        var text = "Active:  Click to Deactivate";
        if (locked) {
            title = "Inactive";
            text = "Inactive:  Click to Activate";
        }

        function on_lock_win(data, textStatus, xhr){
            var entity = IPA.get_entity(that.entity_name);
            var facet = entity.get_facet('details');
            facet.refresh();
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
        status_field.appendTo(dd);
    };

    return that;
}

function resetpwd_on_click(){

    function reset_password(new_password){
        var dialog =  resetpwd_dialog;

        var user_pkey = $.bbq.getState('user-pkey');
        var pw_pkey;
        if (user_pkey === IPA.whoami.uid[0]){
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

function user_password_load(result) {

    var that = this;

    $('dd', that.container).remove();

    var dd = ipa_create_first_dd(this.name);
    dd.appendTo(that.container);

    var link = $('<a/>',{
        href:"jslink",
        click:resetpwd_on_click,
        title:'userpassword',
        text: 'reset password'
    });
    link.appendTo(dd);

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
function user_state_load(result) {

    var that = this;

    $('dd', that.container).remove();

    //var next = dt.next();
    //next.css('clear', 'none');
    //next.css('width', '70px');

    var dd = ipa_create_first_dd(this.name);
    dd.append(select_temp);
    dd.appendTo(that.container);

    var sel = dd.children().first();
    for (var i = 0; i < states.length; ++i)
        sel.append(option_temp.replace(/V/g, states[i]));

    var st = result['st'];
    if (st)
        sel.val(st);
    else
        sel.val('');
}


