<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">
  <form action="${action}" name="${name}" method="${method}" class="tableform"
    onsubmit="preSubmit()">
        
<input type="submit" class="submitbutton" name="submit" value="Add Person"/>

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
          <script type="text/javascript">
            var uid_suggest = "";
            var mail_suggest = "";
            var cn_suggest = "";
            var displayname_suggest = "";
            var initials_suggest = "";

            function autofill(self) {
              var givenname = $('form_givenname');
              var sn = $('form_sn');
              if ((givenname.value == "") || (sn.value == "")) {
                return;
              }

              var uid = $('form_uid');
              var mail = $('form_mail');
              var cn = $('form_cn');
              var displayname = $('form_displayname');
              var initials = $('form_initials');

              if ((cn.value == "") || (cn.value == cn_suggest)) {
                cn.value = givenname.value + " " + sn.value;
                cn_suggest = cn.value;
                new Effect.Highlight(cn);
              }

              if ((displayname.value == "") ||
                  (displayname.value == displayname_suggest)) {
                displayname.value = givenname.value + " " + sn.value;
                displayname_suggest = displayname.value;
                new Effect.Highlight(displayname);
              }

              if ((initials.value == "") ||
                  (initials.value == initials_suggest)) {
                initials.value = givenname.value[0] + sn.value[0];
                initials_suggest = initials.value;
                new Effect.Highlight(initials);
              }

              if ((uid.value == "") || (uid.value == uid_suggest)) {
                new Ajax.Request('${tg.url('/user/suggest_uid')}', {
                    method: 'get',
                    parameters: {'givenname': givenname.value, 'sn': sn.value},
                    onSuccess: function(transport) {
                        uid.value = transport.responseText;
                        uid_suggest = uid.value;
                        new Effect.Highlight(uid);
                      }
                    });
              }

              if ((mail.value == "") || (mail.value == mail_suggest)) {
                new Ajax.Request('${tg.url('/user/suggest_email')}', {
                    method: 'get',
                    parameters: {'givenname': givenname.value, 'sn': sn.value},
                    onSuccess: function(transport) {
                        mail.value = transport.responseText;
                        mail_suggest = mail.value;
                        new Effect.Highlight(mail);
                      }
                    });
              }
            }

            document.getElementById('form_givenname').onchange = autofill;
            document.getElementById('form_sn').onchange = autofill;
          </script>
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.cn.field_id}"
            py:content="user_fields.cn.label" />:
        </th>
        <td>
          <span py:replace="user_fields.cn.display(value_for(user_fields.cn))" />
          <span py:if="tg.errors.get('cn')" class="fielderror"
              py:content="tg.errors.get('cn')" />

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
        </td>
      </tr>
      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.uid.field_id}"
            py:content="user_fields.uid.label" />:
        </th>
        <td>
          <span py:replace="user_fields.uid.display(value_for(user_fields.uid))" />
          <span py:if="tg.errors.get('uid')" class="fielderror"
              py:content="tg.errors.get('uid')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.userpassword.field_id}"
            py:content="user_fields.userpassword.label" />:
        </th>
        <td>
          <span py:replace="user_fields.userpassword.display(value_for(user_fields.userpassword))" />
          <span py:if="tg.errors.get('userpassword')" class="fielderror"
              py:content="tg.errors.get('userpassword')" />

          <!--
          <input type="button" value="Generate Password"
              onclick="new Ajax.Request('${tg.url('/user/generate_password')}',
                {
                  method: 'get',
                  onSuccess: function(transport) {
                    document.getElementById('form_userpassword').value =
                        transport.responseText;
                  }
                });" />
            -->
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.userpassword_confirm.field_id}"
            py:content="user_fields.userpassword_confirm.label" />:
        </th>
        <td>
          <span py:replace="user_fields.userpassword_confirm.display(
              value_for(user_fields.userpassword_confirm))" />
          <span py:if="tg.errors.get('userpassword_confirm')" class="fielderror"
              py:content="tg.errors.get('userpassword_confirm')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.uidnumber.field_id}"
            py:content="user_fields.uidnumber.label" />:
        </th>
        <td>
          Generated by server
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.gidnumber.field_id}"
            py:content="user_fields.gidnumber.label" />:
        </th>
        <td>
          Generated by server
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.homedirectory.field_id}"
            py:content="user_fields.homedirectory.label" />:
        </th>
        <td>
          Generated by server
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
          <label class="fieldlabel" for="${user_fields.telephonenumber.field_id}"
            py:content="user_fields.telephonenumber.label" />:
        </th>
        <td>
          <span py:replace="user_fields.telephonenumber.display(value_for(user_fields.telephonenumber))" />
          <span py:if="tg.errors.get('telephonenumber')" class="fielderror"
              py:content="tg.errors.get('telephonenumber')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.facsimiletelephonenumber.field_id}"
            py:content="user_fields.facsimiletelephonenumber.label" />:
        </th>
        <td>
          <span py:replace="user_fields.facsimiletelephonenumber.display(value_for(user_fields.facsimiletelephonenumber))" />
          <span py:if="tg.errors.get('facsimiletelephonenumber')" class="fielderror"
              py:content="tg.errors.get('facsimiletelephonenumber')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.mobile.field_id}"
            py:content="user_fields.mobile.label" />:
        </th>
        <td>
          <span py:replace="user_fields.mobile.display(value_for(user_fields.mobile))" />
          <span py:if="tg.errors.get('mobile')" class="fielderror"
              py:content="tg.errors.get('mobile')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.pager.field_id}"
            py:content="user_fields.pager.label" />:
        </th>
        <td>
          <span py:replace="user_fields.pager.display(value_for(user_fields.pager))" />
          <span py:if="tg.errors.get('pager')" class="fielderror"
              py:content="tg.errors.get('pager')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user_fields.homephone.field_id}"
            py:content="user_fields.homephone.label" />:
        </th>
        <td>
          <span py:replace="user_fields.homephone.display(value_for(user_fields.homephone))" />
          <span py:if="tg.errors.get('homephone')" class="fielderror"
              py:content="tg.errors.get('homephone')" />
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
            <span id='manager_select_cn'>${value_for(user_fields.manager)}</span>
            <span id='manager_links'>
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
        <th>
          <label class="fieldlabel" for="${user_fields.secretary.field_id}"
            py:content="user_fields.secretary.label" />:
        </th>
        <td>
          <div>
            <span id='secretary_select_cn'>${value_for(user_fields.secretary)}</span>
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
      <div class="formsection" >Custom Fields</div>
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
          <input class="searchbutton" type="button" value="Find"
            onclick="return doSearch();"
          />
        </div>
        <div id="searchresults">
        </div>
      </div>
    </div>

<hr />
<input type="submit" class="submitbutton" name="submit" value="Add Person"/>

  </form>

  <script type="text/javascript">
    /*
     * This section restores the contents of the add and remove lists
     * dynamically if we have to refresh the page
     */
    if ($('form_dn_to_info_json').value != "") {
      dn_to_info_hash = new Hash($('form_dn_to_info_json').value.evalJSON());
    }
  </script>

  <?python
  dnadds = value.get('dnadd', [])
  if not(isinstance(dnadds,list) or isinstance(dnadds,tuple)):
      dnadds = [dnadds]
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

</div>
