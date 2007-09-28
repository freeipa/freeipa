/**
 * dynamicedit.js
 *
 * Shared code, data, and functions for the dynamic add/remove lists on the
 * edit group/user pages.
 *
 * These functions have specific expectations of the page they are used on:
 *
 * - If you want to preserve the dn_to_info_hash on round trip:
 *     - The form must have a 'form_dn_to_info_json' hidden field.
 *     - The form must have onsubmit="preSubmit()" set in its tag.
 *     - Restoring the contents of add/remove lists on round trip unfortunately
 *       can't be shared because it is a mixture of python and javascript.  See
 *       the bottom part editgroup.kid for example code on this.
 *
 * - The page must have a div: 'newmembers'
 *   that new members are dynamically added to.
 *
 * - The page must have a div: 'delmembers'
 *   that removed members are dynamically added to.
 *
 * - Hidden fields called 'dnadd' and 'dndel' will be dynamically created,
 *   holding the values of the 'dn' passed to addmember() and removemember()
 *
 * Other Notes:
 *
 * - Many of the fields refer to 'dn'.  There is no intrinsic reason this has
 *   to be a dn (it can hold any "unique id" for the objects to add/remove)
 *
 * - Similarly, the word 'member' is used because the code was originally
 *   written for editgroup.  A 'member' is just a 'thing' to add/remove.
 *   On the useredit pages, for example, a 'member' is actually a group.
 */

// Stored as the values in the dn_to_info_hash
MemberDisplayInfo = Class.create();
MemberDisplayInfo.prototype = {
  initialize: function(name, descr, type) {
    this.name = name;
    this.descr = descr;
    this.type = type;
  },
};


// this is used for round-trip recontruction of the names.
// the hidden fields only contain dns.
var dn_to_info_hash = new Hash();

// used to filter search results.
// records dns already in the group
var member_hash = new Hash();

// used to prevent double adding
// records dns to be added
var added_hash = new Hash();

// Tracks the div ids that each member belongs to.
// Since dn's will contain illegal characters for div ids, this is used
// to map them to the correct div
var dn_to_member_div_id = new Hash();



/*
 * Renders the information about the member into the passed in
 * element.  This is used by addmember and removemember to
 * consistently create the dom for the member information
 * (name, descr) and add icons/font changes correct for each type.
 */
function renderMemberInfo(newdiv, info) {
  if (info.type == "user") {
    newdiv.appendChild(document.createTextNode(
      info.name.escapeHTML() + " " + info.descr.escapeHTML() + " "));
  } else if (info.type == "group") {
    ital = document.createElement('i');
    ital.appendChild(document.createTextNode(
      info.name.escapeHTML() + " " + 
      info.descr.escapeHTML() + " "));
    newdiv.appendChild(ital);
  }
}

/*
 * Callback used for afterFinish in scriptaculous effect
 */
function removeElement(effect) {
  Element.remove(effect.element);
}

function addmember(dn, info) {
  dn_to_info_hash[dn] = info;

  if ((added_hash[dn] == 1) || (member_hash[dn] == 1)) {
    return null;
  }
  added_hash[dn] = 1;

  var newdiv = document.createElement('div');
  renderMemberInfo(newdiv, info);

  var undolink = document.createElement('a');
  undolink.setAttribute('href', '');
  undolink.setAttribute('onclick',
    'new Effect.Fade(Element.up(this), {afterFinish: removeElement});' +
    'added_hash.remove("' + jsStringEscape(dn) + '");' +
    'return false;');
  undolink.appendChild(document.createTextNode("undo"));
  newdiv.appendChild(undolink);

  var dnInfo = document.createElement('input');
  dnInfo.setAttribute('type', 'hidden');
  dnInfo.setAttribute('name', 'dnadd');
  dnInfo.setAttribute('value', dn);
  newdiv.appendChild(dnInfo);

  newdiv.style.display = 'none';
  $('newmembers').appendChild(newdiv);

  return newdiv
}

function addmemberHandler(element, dn, info) {
  var newdiv = addmember(dn, info)
  if (newdiv != null) {
    new Effect.Fade(Element.up(element));
    new Effect.Appear(newdiv);
    /* Element.up(element).remove(); */
  }
}

function removemember(dn, info) {
  dn_to_info_hash[dn] = info;

  var newdiv = document.createElement('div');
  renderMemberInfo(newdiv, info);

  orig_div_id = dn_to_member_div_id[dn];
  var undolink = document.createElement('a');
  undolink.setAttribute('href', '');
  undolink.setAttribute('onclick',
    'new Effect.Fade(Element.up(this), {afterFinish: removeElement});' +
    "new Effect.Appear($('" + orig_div_id + "'));" +
    'return false;');
  undolink.appendChild(document.createTextNode("undo"));
  newdiv.appendChild(undolink);

  var dnInfo = document.createElement('input');
  dnInfo.setAttribute('type', 'hidden');
  dnInfo.setAttribute('name', 'dndel');
  dnInfo.setAttribute('value', dn);
  newdiv.appendChild(dnInfo);

  newdiv.style.display = 'none';
  $('delmembers').appendChild(newdiv);

  return newdiv
}

function removememberHandler(element, dn, info) {
  var newdiv = removemember(dn, info);
  new Effect.Fade(Element.up(element));
  new Effect.Appear(newdiv);
  /* Element.up(element).remove(); */
}

function preSubmit() {
  var json = dn_to_info_hash.toJSON();
  $('form_dn_to_info_json').value = json;
  return true;
}
