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
