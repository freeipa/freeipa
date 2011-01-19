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
IPA.entity_set_details_definition('config',[

    IPA.stanza({name:'ipaserver', label:'Configuration'}).
        input({name:'cn', label:'Name'}).
        input({name:'ipacertificatesubjectbase'}).
        input({name:'ipadefaultloginshell'}).
        input({name:'ipadefaultprimarygroup'}).
        input({name:'ipagroupsearchfields'}).
        input({name:'ipahomesrootdir'}).
        input({name:'ipamaxusernamelength'}).
        input({name:'ipamigrationenabled'}).
        input({name:'ipasearchrecordslimit'}).
        input({name:'ipasearchtimelimit'}).
        input({name:'ipausersearchfields'})
]);
