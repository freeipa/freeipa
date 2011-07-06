/*jsl:import ipa.js */
/*jsl:import certificate.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

IPA.entity_factories.service = function() {

    return  IPA.entity_builder().
        entity('service').
        search_facet({
            columns: [ 'krbprincipalname' ]
        }).
        details_facet({sections:[
            {
                name: 'details',
                fields:['krbprincipalname',
                        {
                            factory:IPA.service_name_widget,
                            name: 'service',
                            label: IPA.messages.objects.service.service,
                            read_only: true
                        },
                        {
                            factory:IPA.service_host_widget,
                            name: 'host',
                            label: IPA.messages.objects.service.host,
                            read_only: true
                        }]
            },
            {
                name: 'provisioning',
                fields:[{
                    factory:IPA.service_provisioning_status_widget,
                    name: 'provisioning_status',
                    label: IPA.messages.objects.service.status
                }]
            },
            {
                name: 'certificate',
                fields:[{
                    factory:IPA.service_certificate_status_widget,
                    name: 'certificate_status',
                    label: IPA.messages.objects.service.status
                }]
            }]}).
        association_facet({
            factory: IPA.service_managedby_host_facet,
            name: 'managedby_host',
            add_method: 'add_host',
            remove_method: 'remove_host'
        }).
        standard_association_facets().
        adder_dialog({
            factory: IPA.service_add_dialog,
            width: '450px'
        }).
        build();
};


IPA.service_select_widget = function(spec) {

    var that = IPA.text_widget(spec);
    var known_services = ["", "cifs", "DNS", "ftp", "HTTP","imap", "ldap",
                          "libvirt","nfs","qpidd","smtp"];

    that.parent_create = that.create;

    that.create = function(container) {

        var select_widget = $('<select/>');
        for (var i = 0; i < known_services.length; i += 1){
            select_widget.append($('<option/>',{
                text: known_services[i],
                click: function(){
                    that.input.val(this.value);
                }
            }));
        }
        container.append(select_widget);
        that.parent_create(container);
    };
    return that;
};

IPA.service_add_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.add_dialog(spec).
        field(IPA.widget({
            name: 'krbprincipalname',
            optional:true,
            hidden: true
        })).
        field(IPA.service_select_widget({
            name: 'service',
            label: IPA.messages.objects.service.service,
            size: 20,
            undo: false
        })).
        field(IPA.entity_select_widget({
            name: 'host',
            field_name: 'fqdn',
            entity: 'host',
            label: IPA.messages.objects.service.host,
            undo: false
        })).
        field(
        IPA.checkbox_widget({
            name: 'force',
            label: IPA.get_method_option('service_add', 'force').label,
            tooltip: IPA.get_method_option('service_add', 'force').doc,
            undo: false
        }));


    that.save = function(record) {

        var field = that.get_field('service');
        var service = field.save()[0];

        field = that.get_field('host');
        var host = field.save()[0];

        record['krbprincipalname'] = service+'/'+host;

        field = that.get_field('force');
        record['force'] = field.save()[0];
    };

    return that;
};



IPA.service_name_widget = function(spec) {

    spec = spec || {};

    var that = IPA.text_widget(spec);

    that.load = function(record) {

        that.text_load(record);

        var krbprincipalname = record['krbprincipalname'][0];
        var value = krbprincipalname.replace(/\/.*$/, '');
        that.values = [value];

        that.reset();
    };

    return that;
};

IPA.service_host_widget = function(spec) {

    spec = spec || {};

    var that = IPA.text_widget(spec);

    that.load = function(record) {

        that.text_load(record);

        var krbprincipalname = record['krbprincipalname'][0];
        var value = krbprincipalname.replace(/^.*\//, '').replace(/@.*$/, '');
        that.values = [value];

        that.reset();
    };

    return that;
};


IPA.service_provisioning_status_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

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

        content_div.append('<b>'+IPA.messages.objects.service.valid+':</b>');

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'unprovision',
            'value': IPA.messages.objects.service.delete_key_unprovision
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

        content_div.append('<b>'+IPA.messages.objects.service.missing+'</b>');
    };

    that.setup = function(container) {

        that.widget_setup(container);

        that.status_valid = $('div[name=kerberos-key-valid]', that.container);
        that.status_missing = $('div[name=kerberos-key-missing]', that.container);

        var button = $('input[name=unprovision]', that.container);
        that.unprovision_button = IPA.button({
            name: 'unprovision',
            'label': IPA.messages.objects.service.delete_key_unprovision,
            'click': that.unprovision
        });
        button.replaceWith(that.unprovision_button);
    };

    that.unprovision = function() {

        var label = IPA.metadata.objects[that.entity_name].label;
        var title = IPA.messages.objects.service.unprovision_title;
        title = title.replace('${entity}', label);

        var dialog = IPA.dialog({
            'title': title
        });

        dialog.create = function() {
            dialog.container.append(IPA.messages.objects.service.unprovision_confirmation);
        };

        dialog.add_button(IPA.messages.objects.service.unprovision, function() {
            var pkey = that.result['krbprincipalname'][0];
            IPA.command({
                entity: that.entity_name,
                method: 'disable',
                args: [pkey],
                on_success: function(data, text_status, xhr) {
                    set_status('missing');
                    dialog.close();
                },
                on_error: function(xhr, text_status, error_thrown) {
                    dialog.close();
                }
            }).execute();
        });

        dialog.init();

        dialog.open(that.container);

        return false;
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

IPA.service_certificate_status_widget = function (spec) {

    spec = spec || {};

    var that = IPA.cert.status_widget(spec);

    that.init = function() {

        that.entity_label = IPA.metadata.objects[that.entity_name].label;

        that.get_entity_pkey = function(result) {
            var values = result['krbprincipalname'];
            return values ? values[0] : null;
        };

        that.get_entity_name = function(result) {
            var value = that.get_entity_pkey(result);
            return value ? value.replace(/@.*$/, '') : null;
        };

        that.get_entity_principal = function(result) {
            return that.get_entity_pkey(result);
        };

        that.get_entity_certificate = function(result) {
            var values = result['usercertificate'];
            return values ? values[0].__base64__ : null;
        };
    };

    return that;
};

IPA.service_managedby_host_facet = function(spec) {

    spec = spec || {};

    var that = IPA.association_facet(spec);

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
