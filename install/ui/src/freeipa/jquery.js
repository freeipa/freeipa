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
                img = $( "img[usemap='#" + mapName + "']" )[0];
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
        // $.expr.filters.visible was removed in jQuery 3.6.0; use :visible pseudo
        return $( element ).is( ":visible" ) &&
                !$( element ).parents().addBack().filter(function() {
                        return $( this ).css( "visibility" ) === "hidden";
                }).length;
    }

    // Register using $.expr.pseudos (canonical since jQuery 3.0).
    // Also populate $.expr[":"] for code that uses the older alias.
    $.extend( $.expr.pseudos, {

        focusable: function( element ) {
                return focusable( element, !isNaN( $.attr( element, "tabindex" ) ) );
        },

        tabbable: function( element ) {
                var tabIndex = $.attr( element, "tabindex" ),
                        isTabIndexNaN = isNaN( tabIndex );
                return ( isTabIndexNaN || tabIndex >= 0 ) && focusable( element, !isTabIndexNaN );
        }
    });

    $.expr[":"].focusable = $.expr.pseudos.focusable;
    $.expr[":"].tabbable  = $.expr.pseudos.tabbable;

    //
    // Backward-compatibility shims for external plugins written against jQuery < 3.6
    //

    // $.expr.filters was an alias of $.expr.pseudos removed in jQuery 3.6.0.
    // Restore it so plugins that reference it directly continue to work.
    if ( !$.expr.filters ) {
        $.expr.filters = $.expr.pseudos;
    }

    // $.css(element, property) was an undocumented internal jQuery function.
    // Restore as a thin wrapper so plugins that call it continue to work.
    if ( !$.css ) {
        $.css = function( element, property ) {
            return $( element ).css( property );
        };
    }

    return $;
});
