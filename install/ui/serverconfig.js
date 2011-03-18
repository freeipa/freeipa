/*jsl:import ipa.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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



/* Configuration */

IPA.entity_factories.config = function(){
    return IPA.entity_builder().
        entity('config').
        details_facet([{
            section: 'ipaserver',
            label: IPA.messages.objects.config.ipaserver,
            fields:
            [{
                factory: IPA.text_widget,
                name: 'cn',
                label: IPA.messages.objects.config.cn
            },
             'ipacertificatesubjectbase','ipadefaultloginshell',
             'ipadefaultprimarygroup','ipagroupsearchfields',
             'ipahomesrootdir','ipamaxusernamelength',
             'ipamigrationenabled','ipasearchrecordslimit',
             'ipasearchtimelimit','ipausersearchfields']}]).
        build();
};