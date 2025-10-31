/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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

define([
    // core
    './app_container',
    './plugins/sync_otp',
    './plugins/login',
    './plugins/login_process',
    './plugins/api_browser',
    // entities
    './aci',
    './automember',
    './automount',
    './plugins/ca',
    './plugins/caacl',
    './plugins/certprofile',
    './plugins/certmap',
    './plugins/certmapmatch',
    './dns',
    './group',
    './hbac',
    './hbactest',
    './hostgroup',
    './host',
    './idrange',
    './idviews',
    './netgroup',
    './otptoken',
    './passkeyconfig',
    './policy',
    './radiusproxy',
    './realmdomains',
    './rule',
    './selinux',
    './serverconfig',
    './service',
    './stageuser',
    './subid',
    './sudo',
    './sysaccount',
    './trust',
    './topology',
    './user',
    './vault',
    './idp',
    'dojo/domReady!'
],function(app_container) {
    return app_container;
});
