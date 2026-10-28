//
// Copyright (C) 2018  FreeIPA Contributors see COPYING for license
//

define([
    'dojo/_base/declare',
    'dojo/on',
    '../facets/Facet',
    '../phases',
    '../reg',
    '../text',
    '../widget',
    '../widgets/MigrateScreen'
    ],
    function(declare, on, Facet, phases, reg, text, widget, MigrateScreen) {

        /**
         * Migrate Facet plugin
         *
         * Creates and registers a facet with migrate page.
         *
         * @class plugins.migrate
         * @singleton
         */
        var migrate = {};

        migrate.facet_spec = {
            name: 'migrate',
            'class': 'login-pf-body',
            preferred_container: 'simple',
            requires_auth: false,
            widgets: [
                {
                    $type: 'activity',
                    name: 'activity',
                    text: text.get('@i18n:migration.migrating', 'Migrating'),
                    visible: false
                },
                {
                    $type: 'migrate_screen',
                    name: 'migrate_screen'
                }
            ]
        };

        migrate.MigrateFacet = declare([Facet], {
            init: function() {
                this.inherited(arguments);
                var migrate_screen = this.get_widget('migrate_screen');
                var self = this;

                on(this, 'show', function(args) {
                    migrate_screen.refresh();
                });
            }
        });

        phases.on('registration', function() {
            var fa = reg.facet;
            var w = reg.widget;

            w.register('migrate_screen', MigrateScreen);

            fa.register({
                type: 'migrate',
                factory: migrate.MigrateFacet,
                spec: migrate.facet_spec
            });
        });

        return migrate;
    });
