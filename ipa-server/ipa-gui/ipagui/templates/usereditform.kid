<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">
  <form action="${action}" name="${name}" method="${method}" class="tableform"
    onsubmit="preSubmit()">

    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <input type="submit" class="submitbutton" name="submit"
              value="Update Person"/>
        </th>
        <td>
          <input type="submit" class="submitbutton" name="submit"
              value="Cancel Edit" />
        </td>
        <td></td>
      </tr>
    </table>

<?python
from ipagui.helpers import ipahelper
?>

  <script type="text/javascript" charset="utf-8"
    src="${tg.url('/static/javascript/dynamicedit.js')}"></script>

  <?python searchurl = tg.url('/user/edit_search') ?>

  <script type="text/javascript">
    function toggleProtectedFields(checkbox) {
      passwordField = document.getElementById('form_userpassword');
      passwordConfirmField = document.getElementById('form_userpassword_confirm');
      uidnumberField = document.getElementById('form_uidnumber');
      gidnumberField = document.getElementById('form_gidnumber');
      homedirectoryField = document.getElementById('form_homedirectory');
      if (checkbox.checked) {
        passwordField.disabled = false;
        passwordConfirmField.disabled = false;
        uidnumberField.disabled = false;
        gidnumberField.disabled = false;
        homedirectoryField.disabled = false;
        $('form_editprotected').value = 'true';
      } else {
        passwordField.disabled = true;
        passwordConfirmField.disabled = true;
        uidnumberField.disabled = true;
        gidnumberField.disabled = true;
        homedirectoryField.disabled = true;
        $('form_editprotected').value = '';
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

    // override dynamicedit.js version
    // we don't need to show [group] nor italize groups
    function renderMemberInfo(newdiv, info) {
      if (info.type == "group") {
        newdiv.appendChild(document.createTextNode(
          info.name + " "));
      }
    }
  </script>


  <div py:for="field in hidden_fields"
    py:replace="field.display(value_for(field), **params_for(field))" 
    />

    <div class="formsection">Identity Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.title.field_id}"
            py:content="user.title.label" />:
        </th>
        <td>
          <span py:replace="user.title.display(value_for(user.title))" />
          <span py:if="tg.errors.get('title')" class="fielderror"
              py:content="tg.errors.get('title')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.givenname.field_id}"
            py:content="user.givenname.label" />:
        </th>
        <td>
          <span py:replace="user.givenname.display(value_for(user.givenname))" />
          <span py:if="tg.errors.get('givenname')" class="fielderror"
              py:content="tg.errors.get('givenname')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.sn.field_id}"
            py:content="user.sn.label" />:
        </th>
        <td>
          <span py:replace="user.sn.display(value_for(user.sn))" />
          <span py:if="tg.errors.get('sn')" class="fielderror"
              py:content="tg.errors.get('sn')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.cn.field_id}"
            py:content="user.cn.label" />:
        </th>
        <td>
          <span py:replace="user.cn.display(value_for(user.cn))" />
          <span py:if="tg.errors.get('cn')" class="fielderror"
              py:content="tg.errors.get('cn')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.displayname.field_id}"
            py:content="user.displayname.label" />:
        </th>
        <td>
          <span py:replace="user.displayname.display(value_for(user.displayname))" />
          <span py:if="tg.errors.get('displayname')" class="fielderror"
              py:content="tg.errors.get('displayname')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.initials.field_id}"
            py:content="user.initials.label" />:
        </th>
        <td>
          <span py:replace="user.initials.display(value_for(user.initials))" />
          <span py:if="tg.errors.get('initials')" class="fielderror"
              py:content="tg.errors.get('initials')" />

        </td>
      </tr>
    </table>

    <div class="formsection">Account Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.nsAccountLock.field_id}"
            py:content="user.nsAccountLock.label" />:
        </th>
        <td>
          <span py:replace="user.nsAccountLock.display(value_for(user.nsAccountLock))" />
          <span py:if="tg.errors.get('nsAccountLock')" class="fielderror"
                    py:content="tg.errors.get('nsAccountLock')" />
        </td>
      </tr>
      <tr>
        <th>
          <label class="fieldlabel" for="${user.uid.field_id}"
            py:content="user.uid.label" />:
        </th>
        <td>
          ${value_for(user.uid)}
        </td>
      </tr>

      <tr>
        <th valign="top">
          <label class="fieldlabel" for="${user.userpassword.field_id}"
            py:content="user.userpassword.label" />:
        </th>
        <td valign="top">
          <span py:replace="user.userpassword.display(value_for(user.userpassword))" />
          <span py:if="tg.errors.get('userpassword')" class="fielderror"
              py:content="tg.errors.get('userpassword')" />

          <script type="text/javascript">
              document.getElementById('form_userpassword').disabled = true;
          </script>

          <!-- 
          <span id="password_text">********</span>
          <input id="genpassword_button" type="button" value="Generate Password"
              disabled="true"
              onclick="new Ajax.Request('${tg.url('/user/generate_password')}',
                {
                  method: 'get',
                  onSuccess: function(transport) {
                    document.getElementById('form_userpassword').value =
                        transport.responseText;
                  }
                });" />
          <br />
          <input type="checkbox"
              onclick="togglePassword(this);"><span class="xsmall">edit</span></input>
          <script type="text/javascript">
            document.getElementById('form_userpassword').style.display='none';

            function togglePassword(checkbox) {
              passwordField = document.getElementById('form_userpassword');
              passwordText = document.getElementById('password_text');
              passwordButton = document.getElementById('genpassword_button');
              if (checkbox.checked) {
                passwordField.style.display='inline';
                passwordText.style.display='none';
                passwordButton.disabled=false;
              } else {
                passwordField.style.display='none';
                passwordText.style.display='inline';
                passwordButton.disabled=true;
              }
            }
          </script>
          -->
        </td>
      </tr>

      <tr>
        <th valign="top">
          <label class="fieldlabel" for="${user.userpassword_confirm.field_id}"
            py:content="user.userpassword_confirm.label" />:
        </th>
        <td valign="top">
          <span py:replace="user.userpassword_confirm.display(
               value_for(user.userpassword_confirm))" />
          <span py:if="tg.errors.get('userpassword_confirm')" class="fielderror"
              py:content="tg.errors.get('userpassword_confirm')" />

          <script type="text/javascript">
              document.getElementById('form_userpassword_confirm').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.uidnumber.field_id}"
            py:content="user.uidnumber.label" />:
        </th>
        <td>
          <span py:replace="user.uidnumber.display(
               value_for(user.uidnumber))" />
          <span py:if="tg.errors.get('uidnumber')" class="fielderror"
              py:content="tg.errors.get('uidnumber')" />

          <script type="text/javascript">
              document.getElementById('form_uidnumber').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.gidnumber.field_id}"
            py:content="user.gidnumber.label" />:
        </th>
        <td>
          <span py:replace="user.gidnumber.display(
               value_for(user.gidnumber))" />
          <span py:if="tg.errors.get('gidnumber')" class="fielderror"
              py:content="tg.errors.get('gidnumber')" />

          <script type="text/javascript">
              document.getElementById('form_gidnumber').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.homedirectory.field_id}"
            py:content="user.homedirectory.label" />:
        </th>
        <td>
          <span py:replace="user.homedirectory.display(
               value_for(user.homedirectory))" />
          <span py:if="tg.errors.get('homedirectory')" class="fielderror"
              py:content="tg.errors.get('homedirectory')" />

          <script type="text/javascript">
              document.getElementById('form_homedirectory').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.loginshell.field_id}"
            py:content="user.loginshell.label" />:
        </th>
        <td>
          <span py:replace="user.loginshell.display(
              value_for(user.loginshell))" />
          <span py:if="tg.errors.get('loginshell')" class="fielderror"
              py:content="tg.errors.get('loginshell')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.gecos.field_id}"
            py:content="user.gecos.label" />:
        </th>
        <td>
          <span py:replace="user.gecos.display(
              value_for(user.gecos))" />
          <span py:if="tg.errors.get('gecos')" class="fielderror"
              py:content="tg.errors.get('gecos')" />
        </td>
      </tr>
    </table>

    <div class="formsection">Contact Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.mail.field_id}"
            py:content="user.mail.label" />:
        </th>
        <td>
          <span py:replace="user.mail.display(value_for(user.mail))" />
          <span py:if="tg.errors.get('mail')" class="fielderror"
              py:content="tg.errors.get('mail')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.telephonenumber.field_id}"
            py:content="user.telephonenumber.label" />:
        </th>
        <td>
          <span py:replace="user.telephonenumber.display(value_for(user.telephonenumber))" />
          <span py:if="tg.errors.get('telephonenumber')" class="fielderror"
              py:content="tg.errors.get('telephonenumber')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.facsimiletelephonenumber.field_id}"
            py:content="user.facsimiletelephonenumber.label" />:
        </th>
        <td>
          <span py:replace="user.facsimiletelephonenumber.display(value_for(user.facsimiletelephonenumber))" />
          <span py:if="tg.errors.get('facsimiletelephonenumber')" class="fielderror"
              py:content="tg.errors.get('facsimiletelephonenumber')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.mobile.field_id}"
            py:content="user.mobile.label" />:
        </th>
        <td>
          <span py:replace="user.mobile.display(value_for(user.mobile))" />
          <span py:if="tg.errors.get('mobile')" class="fielderror"
              py:content="tg.errors.get('mobile')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.pager.field_id}"
            py:content="user.pager.label" />:
        </th>
        <td>
          <span py:replace="user.pager.display(value_for(user.pager))" />
          <span py:if="tg.errors.get('pager')" class="fielderror"
              py:content="tg.errors.get('pager')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.homephone.field_id}"
            py:content="user.homephone.label" />:
        </th>
        <td>
          <span py:replace="user.homephone.display(value_for(user.homephone))" />
          <span py:if="tg.errors.get('homephone')" class="fielderror"
              py:content="tg.errors.get('homephone')" />
        </td>
      </tr>
    </table>

    <div class="formsection">Mailing Address</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.street.field_id}"
            py:content="user.street.label" />:
        </th>
        <td>
          <span py:replace="user.street.display(value_for(user.street))" />
          <span py:if="tg.errors.get('street')" class="fielderror"
              py:content="tg.errors.get('street')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.roomnumber.field_id}"
            py:content="user.roomnumber.label" />:
        </th>
        <td>
          <span py:replace="user.roomnumber.display(value_for(user.roomnumber))" />
          <span py:if="tg.errors.get('roomnumber')" class="fielderror"
              py:content="tg.errors.get('roomnumber')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.l.field_id}"
            py:content="user.l.label" />:
        </th>
        <td>
          <span py:replace="user.l.display(value_for(user.l))" />
          <span py:if="tg.errors.get('l')" class="fielderror"
              py:content="tg.errors.get('l')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.st.field_id}"
            py:content="user.st.label" />:
        </th>
        <td>
          <span py:replace="user.st.display(value_for(user.st))" />
          <span py:if="tg.errors.get('st')" class="fielderror"
              py:content="tg.errors.get('st')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.postalcode.field_id}"
            py:content="user.postalcode.label" />:
        </th>
        <td>
          <span py:replace="user.postalcode.display(value_for(user.postalcode))" />
          <span py:if="tg.errors.get('postalcode')" class="fielderror"
              py:content="tg.errors.get('postalcode')" />
        </td>
      </tr>
    </table>

    <div class="formsection">Employee Information</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.ou.field_id}"
            py:content="user.ou.label" />:
        </th>
        <td>
          <span py:replace="user.ou.display(value_for(user.ou))" />
          <span py:if="tg.errors.get('ou')" class="fielderror"
              py:content="tg.errors.get('ou')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.businesscategory.field_id}"
            py:content="user.businesscategory.label" />:
        </th>
        <td>
          <span py:replace="user.businesscategory.display(value_for(user.businesscategory))" />
          <span py:if="tg.errors.get('businesscategory')" class="fielderror"
              py:content="tg.errors.get('businesscategory')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.description.field_id}"
            py:content="user.description.label" />:
        </th>
        <td>
          <span py:replace="user.description.display(value_for(user.description))" />
          <span py:if="tg.errors.get('description')" class="fielderror"
              py:content="tg.errors.get('description')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.employeetype.field_id}"
            py:content="user.employeetype.label" />:
        </th>
        <td>
          <span py:replace="user.employeetype.display(value_for(user.employeetype))" />
          <span py:if="tg.errors.get('employeetype')" class="fielderror"
              py:content="tg.errors.get('employeetype')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.manager.field_id}"
            py:content="user.manager.label" />:
        </th>
        <td>
           TODO
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.secretary.field_id}"
            py:content="user.secretary.label" />:
        </th>
        <td>
           TODO
        </td>
      </tr>
    </table>

    <div class="formsection">Misc Information</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.carlicense.field_id}"
            py:content="user.carlicense.label" />:
        </th>
        <td>
          <span py:replace="user.carlicense.display(value_for(user.carlicense))" />
          <span py:if="tg.errors.get('carlicense')" class="fielderror"
              py:content="tg.errors.get('carlicense')" />
        </td>
      </tr>
      <tr>
        <th>
          <label class="fieldlabel" for="${user.labeleduri.field_id}"
            py:content="user.labeleduri.label" />:
        </th>
        <td>
          <span py:replace="user.labeleduri.display(value_for(user.labeleduri))" />
          <span py:if="tg.errors.get('labeleduri')" class="fielderror"
              py:content="tg.errors.get('labeleduri')" />
        </td>
      </tr>
    </table>


    <div>
      <div class="formsection">Groups</div>

      <div class="floatlist">
        <div class="floatheader">To Remove:</div>
        <div id="delmembers">
        </div>
      </div>

      <div>
        <?python div_counter = 1 ?>
        <div py:for="group in user_groups" id="member-${div_counter}">
          <?python
          group_dn = group.get('dn')
          group_dn_esc = ipahelper.javascript_string_escape(group_dn)

          group_name = group.get('cn')
          group_descr = "[group]"
          group_type = "group"

          group_name_esc = ipahelper.javascript_string_escape(group_name)
          group_descr_esc = ipahelper.javascript_string_escape(group_descr)
          group_type_esc = ipahelper.javascript_string_escape(group_type)
          ?>
          <span id="member-info-${div_counter}"></span>
          <script type="text/javascript">
            renderMemberInfo($('member-info-${div_counter}'),
                         new MemberDisplayInfo('${group_name_esc}',
                                               '${group_descr_esc}',
                                               '${group_type_esc}'));
          </script>
          <a href="#" 
            onclick="removememberHandler(this, '${group_dn_esc}',
                         new MemberDisplayInfo('${group_name_esc}',
                                               '${group_descr_esc}',
                                               '${group_type_esc}'));
                     return false;"
          >remove</a>
          <script type="text/javascript">
            dn_to_member_div_id['${group_dn_esc}'] = "member-${div_counter}";
            member_hash["${group_dn_esc}"] = 1;
          </script>
          <?python
          div_counter = div_counter + 1
          ?>
        </div>
      </div>

    </div>

    <div style="clear:both">
      <div class="formsection">Add Groups</div>

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
              value="Update Person"/>
        </th>
        <td>
          <br />
          <input type="submit" class="submitbutton" name="submit"
              value="Cancel Edit" />
        </td>
        <td></td>
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
