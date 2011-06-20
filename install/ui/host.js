/*jsl:import ipa.js */
/*jsl:import certificate.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

IPA.entity_factories.host = function () {

    return IPA.entity_builder().
        entity('host').
        search_facet({
            columns:['fqdn','description',{
                name: 'krblastpwdchange',
                label: IPA.messages.objects.host.enrolled,
                format: IPA.utc_date_column_format
            }]
        }).
        details_facet({sections:[
            {
                name:'details',
                fields: [
                    'fqdn',
                    'krbprincipalname',
                    {
                        factory: IPA.text_widget,
                        name: 'cn',
                        label: IPA.messages.objects.host.cn,
                        read_only: true
                    },
                    'description' ]
            },
            {
                name:'enrollment',
                fields:[
                    {
                        factory: IPA.host_provisioning_status_widget,
                        'name': 'provisioning_status',
                        label: IPA.messages.objects.host.status
                    }
                ]
            },
            {
                name:'certificate',
                fields:[
                    {
                        factory: IPA.host_certificate_status_widget,
                        'name': 'certificate_status',
                        label: IPA.messages.objects.host.status
                    }
                ]
            }]}).
        association_facet({
            factory: IPA.host_managedby_host_facet,
            name: 'managedby_host'
        }).
        association_facet({
            name: 'memberof_hostgroup',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_role',
            associator: IPA.serial_associator
        }).
        standard_association_facets().
        adder_dialog({
            width:500,
            fields:[
                {
                    factory:IPA.entity_select_widget,
                    name: 'fqdn',
                    field_name:'idnsname',
                    entity: 'dnszone',
                    label: IPA.messages.objects.service.host,
                    editable: true,
                    undo: false
                },
                {factory:IPA.force_host_add_checkbox_widget},
                {
                    factory:IPA.text_widget,
                    name:"ip_address",
                    undo:false,
                    label:  IPA.get_method_option('host_add','ip_address')['label']
                }
            ]
        }).
        build();
};


/* Take an LDAP format date in UTC and format it */
IPA.utc_date_column_format = function(value){
    if (!value) {
        return "";
    }
    if (value.length  != "20101119025910Z".length){
        return value;
    }
    /* We only handle GMT */
    if (value.charAt(value.length -1) !== 'Z'){
        return value;
    }

    var date = new Date();

    date.setUTCFullYear(
        value.substring(0, 4),    // YYYY
        value.substring(4, 6)-1,  // MM (0-11)
        value.substring(6, 8));   // DD (1-31)
    date.setUTCHours(
        value.substring(8, 10),   // HH (0-23)
        value.substring(10, 12),  // MM (0-59)
        value.substring(12, 14)); // SS (0-59)
    var formated = date.toString();
    return  formated;
};


IPA.force_host_add_checkbox_widget = function (spec){
    var param_info = IPA.get_method_option('host_add', 'force');
    spec.name = 'force';
    spec.label = param_info.label;
    spec.tooltip = param_info.doc;
    spec.undo = false;
    return  IPA.checkbox_widget(spec);
};

IPA.host_provisioning_status_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.facet = spec.facet;

    that.create = function(container) {

        that.widget_create(container);

        var div = $('<div/>', {
            name: 'kerberos-key-valid',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'check.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(div);

        var content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(div);

        content_div.append('<b>'+IPA.messages.objects.host.valid+':</b>');

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'unprovision',
            'value': IPA.messages.objects.host.delete_key_unprovision
        }).appendTo(content_div);

        div = $('<div/>', {
            name: 'kerberos-key-missing',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'caution.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(div);

        content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(div);

        content_div.append('<b>'+IPA.messages.objects.host.missing+'</b>');

        content_div.append('<br/>');

        content_div.append(IPA.messages.objects.host.enroll_otp+':');

        content_div.append('<br/>');
        content_div.append('<br/>');

        $('<input/>', {
            'type': 'text',
            'name': 'otp',
            'class': 'otp'
        }).appendTo(content_div);

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'enroll',
            'value': IPA.messages.objects.host.set_otp
        }).appendTo(content_div);
    };

    that.setup = function(container) {

        that.widget_setup(container);

        that.status_valid = $('div[name=kerberos-key-valid]', that.container);
        that.status_missing = $('div[name=kerberos-key-missing]', that.container);

        var button = $('input[name=unprovision]', that.container);
        that.unprovision_button = IPA.button({
            'label': IPA.messages.objects.host.delete_key_unprovision,
            'click': that.show_unprovision_dialog
        });
        button.replaceWith(that.unprovision_button);

        that.otp_input = $('input[name=otp]', that.container);

        that.enroll_button = $('input[name=enroll]', that.container);
        button = IPA.button({
            'label': IPA.messages.objects.host.set_otp,
            'click': that.set_otp
        });

        that.enroll_button.replaceWith(button);
        that.enroll_button = button;
    };

    that.show_unprovision_dialog = function() {

        var label = IPA.metadata.objects[that.entity_name].label;
        var title = IPA.messages.objects.host.unprovision_title;
        title = title.replace('${entity}', label);

        var dialog = IPA.dialog({
            'title': title
        });

        dialog.create = function() {
            dialog.container.append(IPA.messages.objects.host.unprovision_confirmation);
        };

        dialog.add_button(IPA.messages.objects.host.unprovision, function() {
            that.unprovision(
                function(data, text_status, xhr) {
                    set_status('missing');
                    dialog.close();
                },
                function(xhr, text_status, error_thrown) {
                    dialog.close();
                }
            );
        });

        dialog.init();

        dialog.open(that.container);

        return false;
    };

    that.unprovision = function(on_success, on_error) {

        var pkey = that.facet.get_primary_key();

        var command = IPA.command({
            name: that.entity_name+'_disable_'+pkey,
            entity: that.entity_name,
            method: 'disable',
            args: pkey,
            options: { all: true, rights: true },
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    that.set_otp = function() {

        var pkey = that.facet.get_primary_key();
        var otp = that.otp_input.val();
        that.otp_input.val('');

        var command = IPA.command({
            entity: that.entity_name,
            method: 'mod',
            args: pkey,
            options: {
                all: true,
                rights: true,
                userpassword: otp
            },
            on_success: function(data, text_status, xhr) {
                alert(IPA.messages.objects.host.otp_confirmation);
            }
        });

        command.execute();
    };

    that.load = function(result) {
        that.result = result;
        var krblastpwdchange = result['krblastpwdchange'];
        set_status(krblastpwdchange ? 'valid' : 'missing');
    };

    function set_status(status) {
        that.status_valid.css('display', status == 'valid' ? 'inline' : 'none');
        that.status_missing.css('display', status == 'missing' ? 'inline' : 'none');
    }

    return that;
};

IPA.host_certificate_status_widget = function (spec) {

    spec = spec || {};

    var that = IPA.cert.status_widget(spec);

    that.init = function() {

        that.entity_label = IPA.metadata.objects[that.entity_name].label;

        that.get_entity_pkey = function(result) {
            var values = result['fqdn'];
            return values ? values[0] : null;
        };

        that.get_entity_name = function(result) {
            return that.get_entity_pkey(result);
        };

        that.get_entity_principal = function(result) {
            var values = result['krbprincipalname'];
            return values ? values[0] : null;
        };

        that.get_entity_certificate = function(result) {
            var values = result['usercertificate'];
            return values ? values[0].__base64__ : null;
        };
    };

    return that;
};

IPA.host_managedby_host_facet = function (spec) {

    spec = spec || {};

    var that = IPA.association_facet(spec);

    that.add_method = 'add_managedby';
    that.remove_method = 'remove_managedby';

    that.init = function() {

        var column = that.create_column({
            name: 'fqdn',
            primary_key: true,
            link: true
        });

        that.create_adder_column({
            name: 'fqdn',
            primary_key: true,
            width: '200px'
        });

        that.association_facet_init();
    };

    return that;
};
