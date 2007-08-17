<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">
  <form action="${action}" name="${name}" method="${method}" class="tableform">

    <div class="formsection">Account Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
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

          <input type="button" value="Generate Password"
              onclick="new Ajax.Request('${tg.url('/generate_password')}',
                {
                  method: 'get',
                  onSuccess: function(transport) {
                    document.getElementById('form_userpassword').value =
                        transport.responseText;
                  }
                });" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.uidnumber.field_id}"
            py:content="user.uidnumber.label" />:
        </th>
        <td>
          <span py:replace="user.uidnumber.display(value_for(user.uidnumber))" />
          <span py:if="tg.errors.get('uidnumber')" class="fielderror"
              py:content="tg.errors.get('uidnumber')" />
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.gidnumber.field_id}"
            py:content="user.gidnumber.label" />:
        </th>
        <td>
          <span py:replace="user.gidnumber.display(value_for(user.gidnumber))" />
          <span py:if="tg.errors.get('gidnumber')" class="fielderror"
              py:content="tg.errors.get('gidnumber')" />
        </td>
      </tr>
    </table>

    <div class="formsection">Identity Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
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
