<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">
  <form action="${action}" name="${name}" method="${method}" class="tableform">


  <div py:for="field in hidden_fields"
    py:replace="field.display(value_for(field), **params_for(field))" 
    />

    <div class="formsection">Account Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.uid.field_id}"
            py:content="user.uid.label" />
        </th>
        <td>
          ${value_for(user.uid)}
        </td>
      </tr>

      <tr>
        <th valign="top">
          <label class="fieldlabel" for="${user.userpassword.field_id}"
            py:content="user.userpassword.label" />
        </th>
        <td valign="top">
          <span py:replace="user.userpassword.display(value_for(user.userpassword))" />
          <span py:if="tg.errors.get('userpassword')" class="fielderror"
              py:content="tg.errors.get('userpassword')" />
          <span id="password_text">********</span>

          <input id="genpassword_button" type="button" value="Generate Password"
              disabled="true"
              onclick="new Ajax.Request('${tg.url('/generate_password')}',
                {
                  method: 'get',
                  onSuccess: function(transport) {
                    document.getElementById('form_userpassword').value =
                        transport.responseText;
                  }
                });" />
          <br />
          <input type="checkbox"
              onclick="togglePassword(this);"><span class="small">edit</span></input>
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
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.uidnumber.field_id}"
            py:content="user.uidnumber.label" />
        </th>
        <td>
          ${value_for(user.uidnumber)}
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.gidnumber.field_id}"
            py:content="user.gidnumber.label" />
        </th>
        <td>
          ${value_for(user.gidnumber)}
        </td>
      </tr>
    </table>

    <div class="formsection">Identity Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.givenname.field_id}"
            py:content="user.givenname.label" />
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
            py:content="user.sn.label" />
        </th>
        <td>
          <span py:replace="user.sn.display(value_for(user.sn))" />
          <span py:if="tg.errors.get('sn')" class="fielderror"
              py:content="tg.errors.get('sn')" />
        </td>
      </tr>
    </table>

    <div class="formsection">Contact Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.mail.field_id}"
            py:content="user.mail.label" />
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
            py:content="user.telephonenumber.label" />
        </th>
        <td>
          <span py:replace="user.telephonenumber.display(value_for(user.telephonenumber))" />
          <span py:if="tg.errors.get('telephonenumber')" class="fielderror"
              py:content="tg.errors.get('telephonenumber')" />
        </td>
      </tr>
    </table>

    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <br />
          <input type="submit" class="submitbutton" name="submit" value="Submit"/>
        </th>
        <td>
          <br />
          <input type="submit" class="submitbutton" name="submit" value="Cancel" />
        </td>
        <td></td>
      </tr>
    </table>

  </form>
</div>
