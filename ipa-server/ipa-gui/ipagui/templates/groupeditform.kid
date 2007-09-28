<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">
  <form action="${action}" name="${name}" method="${method}" class="tableform"
      onsubmit="preSubmit()" >

<?python
from ipagui.helpers import ipahelper
?>


  <?python searchurl = tg.url('/groupedit_search') ?>

  <script type="text/javascript">

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


    function toggleProtectedFields(checkbox) {
      var gidnumberField = $('form_gidnumber');
      if (checkbox.checked) {
        gidnumberField.disabled = false;
        $('form_editprotected').value = 'true';
      } else {
        gidnumberField.disabled = true;
        $('form_editprotected').value = '';
      }
    }

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

    function enterDoSearch(e) {
      var keyPressed;
      if (window.event) {
        keyPressed = window.event.keyCode;
      } else {
        keyPressed = e.which; 
      }

      if (keyPressed == 13) {
        return doSearch();
      } else {
        return true;
      }
    }

    function doSearch() {
      $('searchresults').update("Searching...");
      new Ajax.Updater('searchresults',
          '${searchurl}',
          {  asynchronous:true,
             parameters: { criteria: $('criteria').value },
             evalScripts: true });
      return false;
    }

    function preSubmit() {
      var json = dn_to_info_hash.toJSON();
      $('form_dn_to_info_json').value = json;
      return true;
    }
  </script>

    <div py:for="field in hidden_fields"
      py:replace="field.display(value_for(field), **params_for(field))" 
      />

    <div class="formsection">Group Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${group.cn.field_id}"
            py:content="group.cn.label" />:
        </th>
        <td>
          <!-- <span py:replace="group.cn.display(value_for(group.cn))" />
          <span py:if="tg.errors.get('cn')" class="fielderror"
              py:content="tg.errors.get('cn')" /> -->
          ${value_for(group.cn)}

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${group.description.field_id}"
            py:content="group.description.label" />:
        </th>
        <td>
          <span py:replace="group.description.display(value_for(group.description))" />
          <span py:if="tg.errors.get('description')" class="fielderror"
              py:content="tg.errors.get('description')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${group.gidnumber.field_id}"
            py:content="group.gidnumber.label" />:
        </th>
        <td>
          <span py:replace="group.gidnumber.display(value_for(group.gidnumber))" />
          <span py:if="tg.errors.get('gidnumber')" class="fielderror"
              py:content="tg.errors.get('gidnumber')" />

          <script type="text/javascript">
              document.getElementById('form_gidnumber').disabled = true;
          </script>
        </td>
      </tr>
    </table>

    <div>
      <div class="formsection">Group Members</div>

      <div class="floatlist">
        <div class="floatheader">To Remove:</div>
        <div id="delmembers">
        </div>
      </div>

      <div>
        <?python div_counter = 1 ?>
        <div py:for="member in members" id="member-${div_counter}">
          <?python
          member_dn = member.get('dn')
          member_dn_esc = ipahelper.javascript_string_escape(member_dn)

          member_uid = member.get('uid')
          if member_uid:
              member_name = "%s %s" % (member.get('givenName'),
                                     member.get('sn'))
              member_descr = "(%s)" % member.get('uid')
              member_type = "user"
          else:
              member_name = member.get('cn')
              member_descr = "[group]"
              member_type = "group"
          member_name_esc = ipahelper.javascript_string_escape(member_name)
          member_descr_esc = ipahelper.javascript_string_escape(member_descr)
          member_type_esc = ipahelper.javascript_string_escape(member_type)
          ?>
          <span id="member-info-${div_counter}"></span>
          <script type="text/javascript">
            renderMemberInfo($('member-info-${div_counter}'),
                         new MemberDisplayInfo('${member_name_esc}',
                                               '${member_descr_esc}',
                                               '${member_type_esc}'));
          </script>
          <a href="#" 
            onclick="removememberHandler(this, '${member_dn_esc}',
                         new MemberDisplayInfo('${member_name_esc}',
                                               '${member_descr_esc}',
                                               '${member_type_esc}'));
                     return false;"
          >remove</a>
          <script type="text/javascript">
            dn_to_member_div_id['${member_dn_esc}'] = "member-${div_counter}";
            member_hash["${member_dn_esc}"] = 1;
          </script>
          <?python
          div_counter = div_counter + 1
          ?>
        </div>
      </div>

    </div>

    <div style="clear:both">
      <div class="formsection">Add Members</div>

      <div class="floatlist">
        <div class="floatheader">To Add:</div>
        <div id="newmembers">
        </div>
      </div>

      <div>
        <div id="search">
          <input id="criteria" type="text" name="criteria"
            onkeypress="return enterDoSearch(event);" />
          <input type="button" value="Find"
            onclick="return doSearch();"
          />
        </div>
        <div id="searchresults">
        </div>
      </div>
    </div>



    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <br />
          <input type="submit" class="submitbutton" name="submit"
              value="Update Group"/>
        </th>
        <td>
          <br />
          <input type="submit" class="submitbutton" name="submit"
              value="Cancel Edit" />
        </td>
      </tr>
    </table>

  </form>

  <script type="text/javascript">
    /*
     * This section restores the contents of the add and remove lists
     * dynamically if we have to refresh the page
     */
    if ($('form_dn_to_info_json').value != "") {
      dn_to_info_hash = new Hash($('form_dn_to_info_json').value.evalJSON());
    }

    if ($('form_editprotected').value != "") {
      $('toggleprotected_checkbox').checked = true;
      toggleProtectedFields($('toggleprotected_checkbox'));
    }
  </script>

  <?python
  dnadds = value.get('dnadd', [])
  if not(isinstance(dnadds,list) or isinstance(dnadds,tuple)):
      dnadds = [dnadds]

  dndels = value.get('dndel', [])
  if not(isinstance(dndels,list) or isinstance(dndels,tuple)):
      dndels = [dndels]
  ?>

  <script py:for="dnadd in dnadds">
    <?python
    dnadd_esc = ipahelper.javascript_string_escape(dnadd)
    ?>
    var dn = "${dnadd_esc}";
    var info = dn_to_info_hash[dn];
    var newdiv = addmember(dn, info);
    if (newdiv != null) {
      newdiv.style.display = 'block';
    }
  </script>

  <script py:for="dndel in dndels">
    <?python
    dndel_esc = ipahelper.javascript_string_escape(dndel)
    ?>
    var dn = "${dndel_esc}";
    var info = dn_to_info_hash[dn];
    var newdiv = removemember(dn, info);
    newdiv.style.display = 'block';
    orig_div_id = dn_to_member_div_id[dn]
    $(orig_div_id).style.display = 'none';
  </script>

</div>
