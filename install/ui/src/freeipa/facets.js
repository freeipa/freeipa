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
     * facets
     * @object
     * @singleton
     *
     * A singleton registry for Facets. Registry calls a builder for building
     * an instance if it doesn't have one.
     *
     * All facets are singleton. If one wants to use multiple instances of
     * one facet class he must registry the same class under a different name.
     * This allows to use different spec object for each instance of a facet.
     *
     * = Usage =
     *
     * == Registration ==
     * Registry facet in application initialization phase using:
     * facets.register(name, class, spec);
     *
     * == Obtaining ==
     * Get facet by:
     * facets.get('facet_name');
     *
     */
    var facets = new Singleton_registry();
    return facets;
});