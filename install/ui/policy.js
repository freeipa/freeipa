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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

/**pwpolicy*/
IPA.entity_factories.pwpolicy = function() {
    return IPA.entity_builder().
        entity('pwpolicy').
        search_facet({
            columns:['cn']}).
        details_facet({
            sections:[
                {
                    name : 'identity',
                    fields:[
                        {
                            factory: IPA.entity_link_widget,
                            name: 'cn',
                            other_entity: 'group'
                        },
                        'krbmaxpwdlife','krbminpwdlife','krbpwdhistorylength',
                        'krbpwdmindiffchars','krbpwdminlength']
                }]}).
        standard_association_facets().
        adder_dialog({
            fields:[
                {
                    factory:IPA.entity_select_widget,
                    name: 'cn',
                    entity: 'group',
                    undo: false
                },
                'cospriority']
        }).
        build();
};

/**
   krbtpolicy
   Does not have search
*/
IPA.entity_factories.krbtpolicy =  function() {
    return IPA.entity_builder().
        entity('krbtpolicy').
        details_facet({
            title: IPA.metadata.objects.krbtpolicy.label,
            sections:[{
                name: 'identity',
                fields:[ 'krbmaxrenewableage','krbmaxticketlife' ]
            }]}).
        build();
};
