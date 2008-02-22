<!-- 
 Copyright (C) 2007  Red Hat
 see file 'COPYING' for use and warranty information

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 only

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
-->
<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">

  <form style="display:none" id='deleteform'
    method="post" action="${tg.url('/user/delete')}">
    <input type="hidden" name="uid" value="${value.get('uid')}" />
  </form>

  <form action="${action}" name="${name}" method="${method}" class="tableform"
    onsubmit="preSubmit()">

          <input type="submit" class="submitbutton" name="submit"
              value="Update User"/>
          <input type="submit" class="submitbutton" name="submit"
              value="Cancel Edit" />
          <input py:if="'editors' in tg.identity.groups or 'admins' in tg.identity.groups and tg.identity.display_name != value.get('uid')"
                 type="button" class="submitbutton"
                 value="Delete User"
                 onclick="return confirmDelete();"
                 />

<?python
from ipagui.helpers import ipahelper
?>

  <script type="text/javascript" charset="utf-8"
    src="${tg.url('/static/javascript/dynamicedit.js')}"></script>
  <script type="text/javascript" charset="utf-8"
    src="${tg.url('/static/javascript/dynamicselect.js')}"></script>
  <script type="text/javascript" charset="utf-8"
    src="${tg.url('/tg_widgets/tg_expanding_form_widget/javascript/expanding_form.js')}"></script>

  <?python
  searchurl = tg.url('/user/edit_search')
  selectSearchurl = tg.url('/user/user_select_search')
  ?>

  <script type="text/javascript">
    function toggleProtectedFields(checkbox) {
      passwordField = document.getElementById('form_userpassword');
      passwordConfirmField = document.getElementById('form_userpassword_confirm');
      uidField = document.getElementById('form_uid');
      uidnumberField = document.getElementById('form_uidnumber');
      gidnumberField = document.getElementById('form_gidnumber');
      homedirectoryField = document.getElementById('form_homedirectory');
      if (checkbox.checked) {
        passwordField.disabled = false;
        passwordConfirmField.disabled = false;
        uidField.disabled = false;
        uidnumberField.disabled = false;
        gidnumberField.disabled = false;
        homedirectoryField.disabled = false;
        $('form_editprotected').value = 'true';
      } else {
        passwordField.disabled = true;
        passwordConfirmField.disabled = true;
        uidField.disabled = true;
        uidnumberField.disabled = true;
        gidnumberField.disabled = true;
        homedirectoryField.disabled = true;
        $('form_editprotected').value = '';
      }
    }

    function warnRDN() {
      if (confirm("Are you sure you want to change the login name?\nThis can have unexpected results. Additionally, a password change will be required.")) {
        return true;
      }
      return false;
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

    function doSelectSearch(which_select) {
      $(which_select + '_searchresults').update("Searching...");
      new Ajax.Updater(which_select + '_searchresults',
          '${selectSearchurl}',
          {  asynchronous:true,
             parameters: { criteria: $(which_select + '_criteria').value,
                           which_select: which_select},
             evalScripts: true });
      return false;
    }

    function confirmDelete() {
      if (confirm("Are you sure you want to delete this person?")) {
        $('deleteform').submit();
      }
      return false;
    }
  </script>


  <div py:for="field in hidden_fields"
    py:replace="field.display(value_for(field), **params_for(field))" 
    />

    <h2 class="formsection">Identity Details</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.title.field_id}"
            py:content="user_fields.title.label" />:
        </th>
        <td>
          <span py:replace="user_fields.title.display(value_for(user_fields.title))" />
          <span py:if="tg.errors.get('title')" class="fielderror"
              py:content="tg.errors.get('title')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.givenname.field_id}"
            py:content="user_fields.givenname.label" />:
        </th>
        <td>
          <span py:replace="user_fields.givenname.display(value_for(user_fields.givenname))" />
          <span py:if="tg.errors.get('givenname')" class="fielderror"
              py:content="tg.errors.get('givenname')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.sn.field_id}"
            py:content="user_fields.sn.label" />:
        </th>
        <td>
          <span py:replace="user_fields.sn.display(value_for(user_fields.sn))" />
          <span py:if="tg.errors.get('sn')" class="fielderror"
              py:content="tg.errors.get('sn')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.cns.field_id}"
            py:content="user_fields.cns.label" />:
        </th>
        <td colspan="3">
          <table class="formtable" cellpadding="2" cellspacing="0" border="0" id="${user_fields.cns.field_id}">
            <tbody>
              <?python repetition = 0
                       cn_index = 0
                       cn_error = tg.errors.get('cn')         
              ?>
              <tr py:for="cn in value_for(user_fields.cn)"
                  id="${user_fields.cns.field_id}_${repetition}" 
                  class="${user_fields.cns.field_class}">

                <td py:for="field in user_fields.cns.fields">
                  <span><input class="textfield" type="text" id="${user_fields.cns.field_id}_${repetition}_cn" name="cns-${repetition}.cn" value="${cn}"/></span>
                  <span py:if="cn_error and cn_error[cn_index]" class="fielderror"
                        py:content="tg.errors.get('cn')" />
                </td>
                <?python cn_index = cn_index + 1 ?>
                <td>
                  <a
                  href="javascript:ExpandingForm.removeItem('${user_fields.cns.field_id}_${repetition}')">Remove</a>
                </td>
                <?python repetition = repetition + 1?>
              </tr>
            </tbody>
          </table>
          <a id="${user_fields.cns.field_id}_doclink" href="javascript:ExpandingForm.addItem('${user_fields.cns.field_id}');">Add Common Name</a>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.displayname.field_id}"
            py:content="user_fields.displayname.label" />:
        </th>
        <td>
          <span py:replace="user_fields.displayname.display(value_for(user_fields.displayname))" />
          <span py:if="tg.errors.get('displayname')" class="fielderror"
              py:content="tg.errors.get('displayname')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.initials.field_id}"
            py:content="user_fields.initials.label" />:
        </th>
        <td>
          <span py:replace="user_fields.initials.display(value_for(user_fields.initials))" />
          <span py:if="tg.errors.get('initials')" class="fielderror"
              py:content="tg.errors.get('initials')" />

        </td>
      </tr>
    </table>

    <h2 class="formsection">Account Details</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.nsAccountLock.field_id}"
            py:content="user_fields.nsAccountLock.label" />:
        </th>
        <td>
          <span py:replace="user_fields.nsAccountLock.display(value_for(user_fields.nsAccountLock))" />
          <span py:if="tg.errors.get('nsAccountLock')" class="fielderror"
                    py:content="tg.errors.get('nsAccountLock')" />
          <script py:if="tg.identity.display_name == value.get('uid')" type="text/javascript">
              document.getElementById('form_nsAccountLock').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.uid.field_id}"
            py:content="user_fields.uid.label" />:
        </th>
        <td>
          <span py:replace="user_fields.uid.display(
               value_for(user_fields.uid))" />
          <span py:if="tg.errors.get('uid')" class="fielderror"
              py:content="tg.errors.get('uid')" />

          <script type="text/javascript">
              document.getElementById('form_uid').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th valign="top">
          <label class="fieldlabel" for="${user_fields.userpassword.field_id}"
            py:content="user_fields.userpassword.label" />:
        </th>
        <td valign="top">
          <span py:replace="user_fields.userpassword.display(value_for(user_fields.userpassword))" />
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
          <label class="fieldlabel" for="${user_fields.userpassword_confirm.field_id}"
            py:content="user_fields.userpassword_confirm.label" />:
        </th>
        <td valign="top">
          <span py:replace="user_fields.userpassword_confirm.display(
               value_for(user_fields.userpassword_confirm))" />
          <span py:if="tg.errors.get('userpassword_confirm')" class="fielderror"
              py:content="tg.errors.get('userpassword_confirm')" />

          <script type="text/javascript">
              document.getElementById('form_userpassword_confirm').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.uidnumber.field_id}"
            py:content="user_fields.uidnumber.label" />:
        </th>
        <td>
          <span py:replace="user_fields.uidnumber.display(
               value_for(user_fields.uidnumber))" />
          <span py:if="tg.errors.get('uidnumber')" class="fielderror"
              py:content="tg.errors.get('uidnumber')" />

          <script type="text/javascript">
              document.getElementById('form_uidnumber').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.gidnumber.field_id}"
            py:content="user_fields.gidnumber.label" />:
        </th>
        <td>
          <span py:replace="user_fields.gidnumber.display(
               value_for(user_fields.gidnumber))" />
          <span py:if="tg.errors.get('gidnumber')" class="fielderror"
              py:content="tg.errors.get('gidnumber')" />

          <script type="text/javascript">
              document.getElementById('form_gidnumber').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.homedirectory.field_id}"
            py:content="user_fields.homedirectory.label" />:
        </th>
        <td>
          <span py:replace="user_fields.homedirectory.display(
               value_for(user_fields.homedirectory))" />
          <span py:if="tg.errors.get('homedirectory')" class="fielderror"
              py:content="tg.errors.get('homedirectory')" />

          <script type="text/javascript">
              document.getElementById('form_homedirectory').disabled = true;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.loginshell.field_id}"
            py:content="user_fields.loginshell.label" />:
        </th>
        <td>
          <span py:replace="user_fields.loginshell.display(
              value_for(user_fields.loginshell))" />
          <span py:if="tg.errors.get('loginshell')" class="fielderror"
              py:content="tg.errors.get('loginshell')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.gecos.field_id}"
            py:content="user_fields.gecos.label" />:
        </th>
        <td>
          <span py:replace="user_fields.gecos.display(
              value_for(user_fields.gecos))" />
          <span py:if="tg.errors.get('gecos')" class="fielderror"
              py:content="tg.errors.get('gecos')" />
        </td>
      </tr>
    </table>

    <h2 class="formsection">Contact Details</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.mail.field_id}"
            py:content="user_fields.mail.label" />:
        </th>
        <td>
          <span py:replace="user_fields.mail.display(value_for(user_fields.mail))" />
          <span py:if="tg.errors.get('mail')" class="fielderror"
              py:content="tg.errors.get('mail')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.telephonenumbers.field_id}"
            py:content="user_fields.telephonenumbers.label" />:
        </th>
        <td colspan="3">
          <table class="formtable" cellpadding="2" cellspacing="0" border="0" id="${user_fields.telephonenumbers.field_id}">
            <tbody>
              <?python repetition = 0
                       tele_index = 0
                       tele_error = tg.errors.get('telephonenumber')         
              ?>
              <tr py:for="tele in value_for(user_fields.telephonenumber)"
                  id="${user_fields.telephonenumbers.field_id}_${repetition}" 
                  class="${user_fields.telephonenumbers.field_class}">

                <td py:for="field in user_fields.telephonenumbers.fields">
                  <span><input class="textfield" type="text" id="${user_fields.telephonenumbers.field_id}_${repetition}_telephonenumber" name="telephonenumbers-${repetition}.telephonenumber" value="${tele}"/></span>
                  <span py:if="tele_error and tele_error[tele_index]" class="fielderror"
                        py:content="tg.errors.get('telephonenumber')" />
                </td>
                <?python tele_index = tele_index + 1 ?>
                <td>
                  <a
                  href="javascript:ExpandingForm.removeItem('${user_fields.telephonenumbers.field_id}_${repetition}')">Remove</a>
                </td>
                <?python repetition = repetition + 1?>
              </tr>
            </tbody>
          </table>
          <a id="${user_fields.telephonenumbers.field_id}_doclink" href="javascript:ExpandingForm.addItem('${user_fields.telephonenumbers.field_id}');">Add Work Number</a>
        </td>
      </tr>
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.facsimiletelephonenumbers.field_id}"
            py:content="user_fields.facsimiletelephonenumbers.label" />:
        </th>
        <td colspan="3">
          <table class="formtable" cellpadding="2" cellspacing="0" border="0" id="${user_fields.facsimiletelephonenumbers.field_id}">
            <tbody>
              <?python repetition = 0
                       fax_index = 0
                       fax_error = tg.errors.get('facsimiletelephonenumber')         
              ?>
              <tr py:for="fax in value_for(user_fields.facsimiletelephonenumber)"
                  id="${user_fields.facsimiletelephonenumbers.field_id}_${repetition}" 
                  class="${user_fields.facsimiletelephonenumbers.field_class}">

                <td py:for="field in user_fields.facsimiletelephonenumbers.fields">
                  <span><input class="textfield" type="text" id="${user_fields.facsimiletelephonenumbers.field_id}_${repetition}_facsimiletelephonenumber" name="facsimiletelephonenumbers-${repetition}.facsimiletelephonenumber" value="${fax}"/></span>
                  <span py:if="fax_error and fax_error[fax_index]" class="fielderror"
                        py:content="tg.errors.get('facsimiletelephonenumber')" />
                </td>
                <?python fax_index = fax_index + 1 ?>
                <td>
                  <a
                  href="javascript:ExpandingForm.removeItem('${user_fields.facsimiletelephonenumbers.field_id}_${repetition}')">Remove</a>
                </td>
                <?python repetition = repetition + 1?>
              </tr>
            </tbody>
          </table>
          <a id="${user_fields.facsimiletelephonenumbers.field_id}_doclink" href="javascript:ExpandingForm.addItem('${user_fields.facsimiletelephonenumbers.field_id}');">Add Fax Number</a>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.mobiles.field_id}"
            py:content="user_fields.mobiles.label" />:
        </th>
        <td colspan="3">
          <table class="formtable" cellpadding="2" cellspacing="0" border="0" id="${user_fields.mobiles.field_id}">
            <tbody>
              <?python repetition = 0
                       mobile_index = 0
                       mobile_error = tg.errors.get('mobile')         
              ?>
              <tr py:for="mobile in value_for(user_fields.mobile)"
                  id="${user_fields.mobiles.field_id}_${repetition}" 
                  class="${user_fields.mobiles.field_class}">

                <td py:for="field in user_fields.mobiles.fields">
                  <span><input class="textfield" type="text" id="${user_fields.mobiles.field_id}_${repetition}_mobile" name="mobiles-${repetition}.mobile" value="${mobile}"/></span>
                  <span py:if="mobile_error and mobile_error[mobile_index]" class="fielderror"
                        py:content="tg.errors.get('mobile')" />
                </td>
                <?python mobile_index = mobile_index + 1 ?>
                <td>
                  <a
                  href="javascript:ExpandingForm.removeItem('${user_fields.mobiles.field_id}_${repetition}')">Remove</a>
                </td>
                <?python repetition = repetition + 1?>
              </tr>
            </tbody>
          </table>
          <a id="${user_fields.mobiles.field_id}_doclink" href="javascript:ExpandingForm.addItem('${user_fields.mobiles.field_id}');">Add Cell Number</a>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.pagers.field_id}"
            py:content="user_fields.pagers.label" />:
        </th>
        <td colspan="3">
          <table class="formtable" cellpadding="2" cellspacing="0" border="0" id="${user_fields.pagers.field_id}">
            <tbody>
              <?python repetition = 0
                       pager_index = 0
                       pager_error = tg.errors.get('pager')         
              ?>
              <tr py:for="pager in value_for(user_fields.pager)"
                  id="${user_fields.pagers.field_id}_${repetition}" 
                  class="${user_fields.pagers.field_class}">

                <td py:for="field in user_fields.pagers.fields">
                  <span><input class="textfield" type="text" id="${user_fields.pagers.field_id}_${repetition}_pager" name="pagers-${repetition}.pager" value="${pager}"/></span>
                  <span py:if="pager_error and pager_error[pager_index]" class="fielderror"
                        py:content="tg.errors.get('pager')" />
                </td>
                <?python pager_index = pager_index + 1 ?>
                <td>
                  <a
                  href="javascript:ExpandingForm.removeItem('${user_fields.pagers.field_id}_${repetition}')">Remove</a>
                </td>
                <?python repetition = repetition + 1?>
              </tr>
            </tbody>
          </table>
          <a id="${user_fields.pagers.field_id}_doclink" href="javascript:ExpandingForm.addItem('${user_fields.pagers.field_id}');">Add Pager Number</a>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.homephones.field_id}"
            py:content="user_fields.homephones.label" />:
        </th>
        <td colspan="3">
          <table class="formtable" cellpadding="2" cellspacing="0" border="0" id="${user_fields.homephones.field_id}">
            <tbody>
              <?python repetition = 0
                       homephone_index = 0
                       homephone_error = tg.errors.get('homephone')         
              ?>
              <tr py:for="homephone in value_for(user_fields.homephone)"
                  id="${user_fields.homephones.field_id}_${repetition}" 
                  class="${user_fields.homephones.field_class}">

                <td py:for="field in user_fields.homephones.fields">
                  <span><input class="textfield" type="text" id="${user_fields.homephones.field_id}_${repetition}_homephone" name="homephones-${repetition}.homephone" value="${homephone}"/></span>
                  <span py:if="homephone_error and homephone_error[homephone_index]" class="fielderror"
                        py:content="tg.errors.get('homephone')" />
                </td>
                <?python homephone_index = homephone_index + 1 ?>
                <td>
                  <a
                  href="javascript:ExpandingForm.removeItem('${user_fields.homephones.field_id}_${repetition}')">Remove</a>
                </td>
                <?python repetition = repetition + 1?>
              </tr>
            </tbody>
          </table>
          <a id="${user_fields.homephones.field_id}_doclink" href="javascript:ExpandingForm.addItem('${user_fields.homephones.field_id}');">Add Home Phone</a>
        </td>
      </tr>
    </table>

    <h2 class="formsection">Mailing Address</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.street.field_id}"
            py:content="user_fields.street.label" />:
        </th>
        <td>
          <span py:replace="user_fields.street.display(value_for(user_fields.street))" />
          <span py:if="tg.errors.get('street')" class="fielderror"
              py:content="tg.errors.get('street')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.roomnumber.field_id}"
            py:content="user_fields.roomnumber.label" />:
        </th>
        <td>
          <span py:replace="user_fields.roomnumber.display(value_for(user_fields.roomnumber))" />
          <span py:if="tg.errors.get('roomnumber')" class="fielderror"
              py:content="tg.errors.get('roomnumber')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.l.field_id}"
            py:content="user_fields.l.label" />:
        </th>
        <td>
          <span py:replace="user_fields.l.display(value_for(user_fields.l))" />
          <span py:if="tg.errors.get('l')" class="fielderror"
              py:content="tg.errors.get('l')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.st.field_id}"
            py:content="user_fields.st.label" />:
        </th>
        <td>
          <span py:replace="user_fields.st.display(value_for(user_fields.st))" />
          <span py:if="tg.errors.get('st')" class="fielderror"
              py:content="tg.errors.get('st')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.postalcode.field_id}"
            py:content="user_fields.postalcode.label" />:
        </th>
        <td>
          <span py:replace="user_fields.postalcode.display(value_for(user_fields.postalcode))" />
          <span py:if="tg.errors.get('postalcode')" class="fielderror"
              py:content="tg.errors.get('postalcode')" />
        </td>
      </tr>
    </table>

    <h2 class="formsection">Employee Information</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.ou.field_id}"
            py:content="user_fields.ou.label" />:
        </th>
        <td>
          <span py:replace="user_fields.ou.display(value_for(user_fields.ou))" />
          <span py:if="tg.errors.get('ou')" class="fielderror"
              py:content="tg.errors.get('ou')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.businesscategory.field_id}"
            py:content="user_fields.businesscategory.label" />:
        </th>
        <td>
          <span py:replace="user_fields.businesscategory.display(value_for(user_fields.businesscategory))" />
          <span py:if="tg.errors.get('businesscategory')" class="fielderror"
              py:content="tg.errors.get('businesscategory')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.description.field_id}"
            py:content="user_fields.description.label" />:
        </th>
        <td>
          <span py:replace="user_fields.description.display(value_for(user_fields.description))" />
          <span py:if="tg.errors.get('description')" class="fielderror"
              py:content="tg.errors.get('description')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.employeetype.field_id}"
            py:content="user_fields.employeetype.label" />:
        </th>
        <td>
          <span py:replace="user_fields.employeetype.display(value_for(user_fields.employeetype))" />
          <span py:if="tg.errors.get('employeetype')" class="fielderror"
              py:content="tg.errors.get('employeetype')" />
        </td>
      </tr>

      <tr>
        <th valign="top">
          <label class="fieldlabel" for="${user_fields.manager.field_id}"
            py:content="user_fields.manager.label" />:
        </th>
        <td valign="top">
          <div>
            <span id='manager_select_cn'>${value_for(user_fields.manager_cn)}</span>
            <span py:if="'editors' in tg.identity.groups or 'admins' in tg.identity.groups or tg.identity.display_name != value.get('uid')" id='manager_links'>
              <a href="#" onclick="return clearSelect('manager');">clear</a>
              <a href="#" onclick="return startSelect('manager');">change</a>
            </span>
            <span py:if="tg.errors.get('manager')" class="fielderror"
                py:content="tg.errors.get('manager')" />
          </div>
          <div id="manager_searcharea" style="display:none">
            <div>
              <input id="manager_criteria" type="text"
                onkeypress="return enterDoSelectSearch(event, 'manager');" />
              <input type="button" value="Find"
                onclick="return doSelectSearch('manager');"
              />
            </div>
            <div id="manager_searchresults">
            </div>
          </div>
        </td>
      </tr>

      <tr>
        <th valign="top">
          <label class="fieldlabel" for="${user_fields.secretary.field_id}"
            py:content="user_fields.secretary.label" />:
        </th>
        <td valign="top">
          <div>
            <span id='secretary_select_cn'>${value_for(user_fields.secretary_cn)}</span>
            <span id='secretary_links'>
              <a href="#" onclick="return clearSelect('secretary');">clear</a>
              <a href="#" onclick="return startSelect('secretary');">change</a>
            </span>
            <span py:if="tg.errors.get('secretary')" class="fielderror"
                py:content="tg.errors.get('secretary')" />
          </div>
          <div id="secretary_searcharea" style="display:none">
            <div>
              <input id="secretary_criteria" type="text"
                onkeypress="return enterDoSelectSearch(event, 'secretary');" />
              <input type="button" value="Find"
                onclick="return doSelectSearch('secretary');"
              />
            </div>
            <div id="secretary_searchresults">
            </div>
          </div>
        </td>
      </tr>
    </table>

    <h2 class="formsection">Misc Information</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.carlicense.field_id}"
            py:content="user_fields.carlicense.label" />:
        </th>
        <td>
          <span py:replace="user_fields.carlicense.display(value_for(user_fields.carlicense))" />
          <span py:if="tg.errors.get('carlicense')" class="fielderror"
              py:content="tg.errors.get('carlicense')" />
        </td>
      </tr>
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.labeleduri.field_id}"
            py:content="user_fields.labeleduri.label" />:
        </th>
        <td>
          <span py:replace="user_fields.labeleduri.display(value_for(user_fields.labeleduri))" />
          <span py:if="tg.errors.get('labeleduri')" class="fielderror"
              py:content="tg.errors.get('labeleduri')" />
        </td>
      </tr>
    </table>

    <div py:if='len(custom_fields) &gt; 0'>
      <h2 class="formsection" >Custom Fields</h2>
      <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr py:for='custom_field in custom_fields'>
          <th>
            <label class="fieldlabel" for="${custom_field.field_id}"
              py:content="custom_field.label" />:
          </th>
          <td>
            <span py:replace="custom_field.display(value_for(custom_field))" />
            <span py:if="tg.errors.get(custom_field.name)" class="fielderror"
                py:content="tg.errors.get(custom_field.name)" />
          </td>
        </tr>
      </table>
    </div>


    <div>
      <h2 class="formsection">Groups</h2>

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
        &nbsp; <!-- a space here to prevent an empty div -->
      </div>

    </div>

    <div style="clear:both">
      <h2 class="formsection">Add Groups</h2>

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

    <hr/>

          <input type="submit" class="submitbutton" name="submit"
              value="Update User"/>
          <input type="submit" class="submitbutton" name="submit"
              value="Cancel Edit" />
          <input py:if="'editors' in tg.identity.groups or 'admins' in tg.identity.groups and tg.identity.display_name != value.get('uid')"
                 type="button" class="submitbutton"
                 value="Delete User"
                 onclick="return confirmDelete();"
                 />

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
