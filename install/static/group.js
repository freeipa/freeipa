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

function ipa_group() {

    var that = ipa_entity({
        'name': 'group'
    });

    that.superior_init = that.superior('init');

    that.init = function() {

        var dialog = ipa_group_add_dialog({
            'name': 'add',
            'title': 'Add New Group'
        });
        that.add_dialog(dialog);
        dialog.init();

        that.superior_init();
    };

    return that;
}

IPA.add_entity(ipa_group());

function ipa_group_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.superior_init = that.superior('init');

    that.init = function() {

        this.superior_init();

        this.add_field(ipa_text_widget({name:'cn', label:'Name', undo: false}));
        this.add_field(ipa_text_widget({name:'description', label:'Description', undo: false}));
        this.add_field(ipa_checkbox_widget({name:'posix', label:'Is this a POSIX group?', undo: false}));
        this.add_field(ipa_text_widget({name:'gidnumber', label:'GID', undo: false}));
    };

    return that;
}

ipa_entity_set_search_definition('group', [
    ['cn', 'Name', null],
    ['gidnumber', 'GID', null],
    ['description', 'Description', null]
]);

ipa_entity_set_details_definition('group',[
    ipa_stanza({name:'identity', label:'Group Details'}).
        input({name:'cn', label:'Group Name'}).
        input({name:'description', label:'Description'}).
        input({name:'gidnumber', label:'Group ID'})
]);

ipa_entity_set_association_definition('group', {
    'netgroup': { associator: 'serial' },
    'rolegroup': { associator: 'serial' },
    'taskgroup': { associator: 'serial' }
});
