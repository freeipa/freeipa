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

define(['./_base/Singleton_registry'], function(Singleton_registry) {

    /**
     * entities
     * @object
     * @singleton
     *
     * A singleton registry for Entities. Registry calls a builder for building
     * an instance if it doesn't have one.
     *
     * = Usage =
     *
     * == Registration ==
     * Registry entity in application initialization phase using:
     * entities.register(name, class, spec);
     *
     * == Obtaining ==
     * Get entity by:
     * entities.get('entity_name');
     *
     */
    var entities = new Singleton_registry();
    return entities;
});