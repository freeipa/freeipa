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

//
// AMD Wrapper for jQuery
//
define(function() {

    $ = jQuery;

    //
    // Following code taken from jQuery UI library, MIT license, see
    // README-LICENSES.txt
    //

    $.fn.extend({
        focus: (function( orig ) {
                return function( delay, fn ) {
                    return typeof delay === "number" ?
                            this.each(function() {
                                    var elem = this;
                                    window.setTimeout(function() {
                                            $( elem ).focus();
                                            if ( fn ) {
                                                    fn.call( elem );
                                            }
                                    }, delay );
                            }) :
                            orig.apply( this, arguments );
                };
        })( $.fn.focus )
    });

    // selectors
    function focusable( element, isTabIndexNotNaN ) {
        var map, mapName, img,
                nodeName = element.nodeName.toLowerCase();
        if ( "area" === nodeName ) {
                map = element.parentNode;
                mapName = map.name;
                if ( !element.href || !mapName || map.nodeName.toLowerCase() !== "map" ) {
                        return false;
                }
                img = $( "img[usemap=#" + mapName + "]" )[0];
                return !!img && visible( img );
        }
        return ( /input|select|textarea|button|object/.test( nodeName ) ?
                !element.disabled :
                "a" === nodeName ?
                        element.href || isTabIndexNotNaN :
                        isTabIndexNotNaN) &&
                // the element and all of its ancestors must be visible
                visible( element );
    }

    function visible( element ) {
        return $.expr.filters.visible( element ) &&
                !$( element ).parents().addBack().filter(function() {
                        return $.css( this, "visibility" ) === "hidden";
                }).length;
    }

    $.extend( $.expr[ ":" ], {

        focusable: function( element ) {
                return focusable( element, !isNaN( $.attr( element, "tabindex" ) ) );
        },

        tabbable: function( element ) {
                var tabIndex = $.attr( element, "tabindex" ),
                        isTabIndexNaN = isNaN( tabIndex );
                return ( isTabIndexNaN || tabIndex >= 0 ) && focusable( element, !isTabIndexNaN );
        }
    });


    return $;
});