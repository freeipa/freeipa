/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

define(['./ipa'], function(IPA) {

/* tabs definition for IPA webUI */

IPA.admin_navigation = function(spec) {

    spec = spec || {};

    spec.name = 'admin';

    spec.tabs = [
        {name: 'identity', label: IPA.messages.tabs.identity, children: [
            {entity: 'user'},
            {entity: 'group'},
            {entity: 'host'},
            {entity: 'hostgroup'},
            {entity: 'netgroup'},
            {entity: 'service'},
            {name:'dns', label: IPA.messages.tabs.dns, children:[
                 {entity: 'dnszone'},
                 {entity: 'dnsconfig'},
                 {entity: 'dnsrecord', hidden:true}
             ]
            },
            {entity: 'cert', label: IPA.messages.tabs.cert },
            {entity: 'realmdomains'}
        ]},
        {name: 'policy', label: IPA.messages.tabs.policy, children: [
            {name: 'hbac', label: IPA.messages.tabs.hbac, children: [
                 {entity: 'hbacrule'},
                 {entity: 'hbacsvc'},
                 {entity: 'hbacsvcgroup'},
                 {entity: 'hbactest'}
            ]},
            {name: 'sudo', label: IPA.messages.tabs.sudo, children: [
                 {entity: 'sudorule'},
                 {entity: 'sudocmd'},
                 {entity: 'sudocmdgroup'}
            ]},
            {name:'automount',
             label: IPA.messages.tabs.automount,
             children:[
                {entity: 'automountlocation', hidden:true, depth: -1},
                {entity: 'automountmap', hidden: true, depth: -1},
                {entity: 'automountkey', hidden: true, depth: -1}]},
            {entity: 'pwpolicy'},
            {entity: 'krbtpolicy'},
            {entity: 'selinuxusermap'},
            {name: 'automember', label: IPA.messages.tabs.automember,
             children: [
                { name: 'amgroup', entity: 'automember',
                  facet: 'searchgroup', label: IPA.messages.objects.automember.usergrouprules},
                { name: 'amhostgroup', entity: 'automember',
                  facet: 'searchhostgroup', label: IPA.messages.objects.automember.hostgrouprules}
            ]}
        ]},
        {name: 'ipaserver', label: IPA.messages.tabs.ipaserver, children: [
            {name: 'rolebased', label: IPA.messages.tabs.role, children: [
                 {entity: 'role'},
                 {entity: 'privilege'},
                 {entity: 'permission'}
             ]},
            {entity: 'selfservice'},
            {entity: 'delegation'},
            {entity: 'idrange'},
            {entity: 'trust'},
            {entity: 'config'}
        ]}];

    var that = IPA.navigation(spec);

    return that;
};

IPA.self_serv_navigation = function(spec) {

    spec = spec || {};

    spec.name = 'self-service';

    spec.tabs = [
        {name: 'identity', label: IPA.messages.tabs.identity, children: [
            {entity: 'user'}
        ]}];

    var that = IPA.navigation(spec);

    that.update = function() {
        var pkey = that.get_state('user-pkey');
        var facet = that.get_state('user-facet');

        if (pkey && facet) {
            that.navigation_update();

        } else {
            var state = {
                'navigation': 'identity',
                'identity': 'user',
                'user-pkey': pkey || IPA.whoami_pkey,
                'user-facet': facet || 'details'
            };
            that.push_state(state);
        }
    };

    return that;
};

return {};
});
