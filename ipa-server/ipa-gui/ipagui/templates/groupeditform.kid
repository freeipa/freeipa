<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">
  <form action="${action}" name="${name}" method="${method}" class="tableform">


  <?python searchurl = tg.url('/userlist_ajax') ?>

  <script type="text/javascript">
    function toggleProtectedFields(checkbox) {
      gidnumberField = $('form_gidnumber');
      if (checkbox.checked) {
        gidnumberField.disabled = false;
      } else {
        gidnumberField.disabled = true;
      }
    }

    /*
     * Callback used for afterFinish in scriptaculous effect
     */
    function removeElement(effect) {
      Element.remove(effect.element);
    }

    function adduser(uid, cn) {
      newdiv = document.createElement('div');
      newdiv.appendChild(document.createTextNode(
        cn.escapeHTML() + " (" + uid.escapeHTML() + ") "));

      undolink = document.createElement('a');
      undolink.setAttribute('href', '');
      undolink.setAttribute('onclick',
        'new Effect.Fade(Element.up(this), {afterFinish: removeElement});' +
        'return false;');
      undolink.appendChild(document.createTextNode("undo"));
      newdiv.appendChild(undolink);

      uidInfo = document.createElement('input');
      uidInfo.setAttribute('type', 'hidden');
      uidInfo.setAttribute('name', 'uidadd');
      uidInfo.setAttribute('value', uid);
      newdiv.appendChild(uidInfo);

      newdiv.style.display = 'none';
      $('newmembers').appendChild(newdiv);

      return newdiv
    }

    function adduserHandler(element, uid, cn) {
      newdiv = adduser(uid, cn)
      new Effect.Fade(Element.up(element));
      new Effect.Appear(newdiv);
      /* Element.up(element).remove(); */
    }

    function removeuser(uid, cn) {
      newdiv = document.createElement('div');
      newdiv.appendChild(document.createTextNode(
        cn.escapeHTML() + " (" + uid.escapeHTML() + ") "));

      undolink = document.createElement('a');
      undolink.setAttribute('href', '');
      undolink.setAttribute('onclick',
        'new Effect.Fade(Element.up(this), {afterFinish: removeElement});' +
        "new Effect.Appear($('member-" + uid + "'));" +
        'return false;');
      undolink.appendChild(document.createTextNode("undo"));
      newdiv.appendChild(undolink);

      uidInfo = document.createElement('input');
      uidInfo.setAttribute('type', 'hidden');
      uidInfo.setAttribute('name', 'uiddel');
      uidInfo.setAttribute('value', uid);
      newdiv.appendChild(uidInfo);

      newdiv.style.display = 'none';
      $('delmembers').appendChild(newdiv);

      return newdiv
    }

    function removeuserHandler(element, uid, cn) {
      newdiv = removeuser(uid, cn);
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
      new Ajax.Updater('searchresults',
          '${searchurl}',
          {  asynchronous:true,
             parameters: { uid: $('uid').value } });
      return false;
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

      <div style="float:right; width:50%">
        <div>To Remove:</div>
        <div id="delmembers">
        </div>
      </div>

      <div>
        <div py:for="member in members" id="member-${member.get('uid')}">
          <?python
          member_uid = member.get('uid')
          member_name = "%s %s" % (member.get('givenname', ''),
                                   member.get('sn', ''))
          ?>
          ${member_name}
          <a href="" 
            onclick="removeuserHandler(this, '${member_uid}', '${member_name}');
                     return false;"
          >remove</a>
        </div>
      </div>

    </div>

    <div style="clear:both">
      <div class="formsection">Add Persons</div>

      <div style="float:right; width:50%">
        <div>To Add:</div>
        <div id="newmembers">
        </div>
      </div>

      <div>
        <div id="search">
          <input id="uid" type="text" name="uid"
            onkeypress="return enterDoSearch(event);" />
          <input type="button" value="Find Users"
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
</div>
