/* Copyright (C) 2007  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/**
 * dynamicselect.js
 *
 * Shared code, data, and functions for the dynamic select lists on the
 * edit user pages.
 *
 */

function enterDoSelectSearch(e, which_select) {
  var keyPressed;
  if (window.event) {
    keyPressed = window.event.keyCode;
  } else {
    keyPressed = e.which; 
  }

  if (keyPressed == 13) {
    return doSelectSearch(which_select);
  } else {
    return true;
  }
}

function startSelect(which_select) {
  new Effect.Appear($(which_select + '_searcharea'), {duration: 0.25});
  new Effect.Fade($(which_select + '_links'), {duration: 0.25});
  return false;
}

function doSelect(which_select, select_dn, select_cn) {
  select_dn_field = $('form_' + which_select);
  select_cn_field = $('form_' + which_select + '_cn');
  select_cn_span = $(which_select + '_select_cn');

  select_dn_field.value = select_dn;
  select_cn_field.value = select_cn;
  select_cn_span.update(select_cn);

  new Effect.Fade($(which_select + '_searcharea'), {duration: 0.25});
  new Effect.Appear($(which_select + '_links'), {duration: 0.25});
}

function clearSelect(which_select) {
  select_dn_field = $('form_' + which_select);
  select_cn_field = $('form_' + which_select + '_cn');
  select_cn_span = $(which_select + '_select_cn');

  select_dn_field.value = '';
  select_cn_field.value = '';
  select_cn_span.update('');

  return false;
}
