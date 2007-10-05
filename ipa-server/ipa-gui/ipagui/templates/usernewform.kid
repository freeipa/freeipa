<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">
  <form action="${action}" name="${name}" method="${method}" class="tableform"
    onsubmit="preSubmit()">

    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <td>
          <input type="submit" class="submitbutton" name="submit" value="Add Person"/>
        </td>
      </tr>
    </table>

<?python
from ipagui.helpers import ipahelper
?>

  <script type="text/javascript" charset="utf-8"
    src="${tg.url('/static/javascript/dynamicedit.js')}"></script>

  <?python searchurl = tg.url('/user/edit_search') ?>

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
          info.name.escapeHTML() + " "));
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
          <span py:replace="user.uid.display(value_for(user.uid))" />
          <span py:if="tg.errors.get('uid')" class="fielderror"
              py:content="tg.errors.get('uid')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.userpassword.field_id}"
            py:content="user.userpassword.label" />:
        </th>
        <td>
          <span py:replace="user.userpassword.display(value_for(user.userpassword))" />
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
          <label class="fieldlabel" for="${user.userpassword_confirm.field_id}"
            py:content="user.userpassword_confirm.label" />:
        </th>
        <td>
          <span py:replace="user.userpassword_confirm.display(
              value_for(user.userpassword_confirm))" />
          <span py:if="tg.errors.get('userpassword_confirm')" class="fielderror"
              py:content="tg.errors.get('userpassword_confirm')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.uidnumber.field_id}"
            py:content="user.uidnumber.label" />:
        </th>
        <td>
          Generated by server
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.gidnumber.field_id}"
            py:content="user.gidnumber.label" />:
        </th>
        <td>
          Generated by server
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.homedirectory.field_id}"
            py:content="user.homedirectory.label" />:
        </th>
        <td>
          Generated by server
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
        <td>
          <br />
          <input type="submit" class="submitbutton" name="submit" value="Add Person"/>
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
