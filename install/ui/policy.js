/*jsl:import ipa.js */
/*jsl:import search.js */

/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.pwpolicy = {};

IPA.pwpolicy.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            sort_enabled: false,
            columns:['cn','cospriority']
        }).
        details_facet({
            sections:[
                {
                    name : 'identity',
                    fields:[
                        {
                            type: 'link',
                            name: 'cn',
                            other_entity: 'group'
                        },
                        'krbmaxpwdlife',
                        'krbminpwdlife',
                        {
                            name: 'krbpwdhistorylength',
                            measurement_unit: 'number_of_passwords'
                        },
                        'krbpwdmindiffchars',
                        'krbpwdminlength',
                        'krbpwdmaxfailure',
                        {
                            name: 'krbpwdfailurecountinterval',
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'krbpwdlockoutduration',
                            measurement_unit: 'seconds'
                        },
                        'cospriority'
                    ]
                }]}).
        standard_association_facets().
        adder_dialog({
            fields: [
                {
                    type: 'entity_select',
                    name: 'cn',
                    other_entity: 'group',
                    other_field: 'cn',
                    required: true
                },
                'cospriority'
            ],
            height: 300
        });
    };

    return that;
};

IPA.krbtpolicy = {};

IPA.krbtpolicy.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.details_facet({
            title: IPA.metadata.objects.krbtpolicy.label,
            sections: [
                {
                    name: 'identity',
                    fields: [
                        {
                            name: 'krbmaxrenewableage',
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'krbmaxticketlife',
                            measurement_unit: 'seconds'
                        }
                    ]
                }
            ],
            needs_update: true
        });
    };

    return that;
};

IPA.register('pwpolicy', IPA.pwpolicy.entity);
IPA.register('krbtpolicy', IPA.krbtpolicy.entity);
