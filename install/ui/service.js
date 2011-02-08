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

IPA.entity_factories.service = function () {

    return  IPA.entity({
        'name': 'service'
    }).
        association({
            'name': 'host',
            'add_method': 'add_host',
            'remove_method': 'remove_host'
        }).
        facet(
            IPA.search_facet().
                column({name: 'krbprincipalname'}).
                dialog(
                    IPA.service_add_dialog({
                        'name': 'add',
                        'title': 'Add New Service'
                    }))).
        facet( IPA.service_details_facet()).
        facet( IPA.service_managedby_host_facet({
            'name': 'managedby_host',
            'label': IPA.messages.association.managedby +
                ' '+IPA.metadata['host'].label,
            'other_entity': 'host'
        }));
};


IPA.service_select_widget = function (spec){

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


/*TODO: the following labels etc. all need to be replaced with I18N strings */

IPA.service_add_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.add_dialog(spec).
        field(IPA.widget({
            name: 'krbprincipalname'
        })).
        field(IPA.service_select_widget({
            'name': 'service',
            'label': 'Service',
            'size': 20,
            'undo': false
        })).
        field(IPA.text_widget({
            'name': 'host',
            'label': 'Host Name',
            'size': 40,
            'undo': false
        })).
        field(IPA.checkbox_widget({
            name: 'force',
            label: 'Force',
            tooltip: 'force principal name even if not in DNS',
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


IPA.service_details_facet = function (spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec).
        section(IPA.stanza({
            name: 'details',
            label: 'Service Settings'
        }).
            input({
                name: 'krbprincipalname'
            }).
            custom_input(IPA.service_name_widget({
                name: 'service',
                label: 'Service',
                read_only: true
            })).
            custom_input(IPA.service_host_widget({
                name: 'host',
                label: 'Host Name',
                read_only: true
            }))).
        section(
            IPA.stanza({
                name: 'provisioning',
                label: 'Provisioning'
            }).
                custom_input(service_provisioning_status_widget({
                    name: 'provisioning_status',
                    label: 'Status'
                }))).
        section(
            IPA.stanza({
                name: 'certificate',
                label: 'Service Certificate'
            }).
                custom_input((service_certificate_status_widget({
                    name: 'certificate_status',
                    label: 'Status'
                }))));


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


function service_provisioning_status_widget(spec) {

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

        content_div.append('<b>Kerberos Key Present, Service Provisioned:</b>');

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'unprovision',
            'value': 'Delete Key, Unprovision'
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

        content_div.append('<b>Kerberos Key Not Present</b>');
    };

    that.setup = function(container) {

        that.widget_setup(container);

        that.status_valid = $('div[name=kerberos-key-valid]', that.container);
        that.status_missing = $('div[name=kerberos-key-missing]', that.container);

        var button = $('input[name=unprovision]', that.container);
        that.unprovision_button = IPA.button({
            'label': 'Delete Key, Unprovision',
            'click': that.unprovision
        });
        button.replaceWith(that.unprovision_button);
    };

    that.unprovision = function() {

        var label = IPA.metadata[that.entity_name].label;
        var dialog = IPA.dialog({
            'title': 'Unprovisioning '+label
        });

        dialog.create = function() {
            dialog.container.append(
                'Are you sure you want to unprovision this service?');
        };

        dialog.add_button('Unprovision', function() {
            var pkey = that.result['krbprincipalname'][0];
            IPA.cmd(that.entity_name+'_disable', [pkey], {},
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
}

function service_certificate_status_widget(spec) {

    spec = spec || {};

    var that = certificate_status_widget(spec);

    that.init = function() {

        that.entity_label = IPA.metadata[that.entity_name].label;

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
}

IPA.service_managedby_host_facet = function (spec) {

    spec = spec || {};

    var that = IPA.association_facet(spec);

    that.init = function() {

        var column = that.create_column({
            name: 'fqdn',
            primary_key: true
        });

        column.setup = function(container, record) {
            container.empty();

            var value = record[column.name];
            value = value ? value.toString() : '';

            $('<a/>', {
                'href': '#'+value,
                'html': value,
                'click': function (value) {
                    return function() {
                        var state = IPA.tab_state(that.other_entity);
                        state[that.other_entity + '-facet'] = 'details';
                        state[that.other_entity + '-pkey'] = value;
                        $.bbq.pushState(state);
                        return false;
                    };
                }(value)
            }).appendTo(container);
        };

        that.create_column({name: 'description'});

        that.create_adder_column({
            name: 'fqdn',
            primary_key: true,
            width: '100px'
        });

        that.create_adder_column({
            name: 'description',
            width: '100px'
        });

        that.association_facet_init();
    };

    return that;
};
