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

<!--      <tr>
        <th>
          <label class="fieldlabel" for="${user.userPassword.field_id}"
            py:content="user.userPassword.label" />
        </th>
        <td>
          <span py:replace="user.userPassword.display(value_for(user.userPassword))" />
          <span py:if="tg.errors.get('userPassword')" class="fielderror"
              py:content="tg.errors.get('userPassword')" />
        </td>
      </tr> -->

      <tr>
        <th>
          <label class="fieldlabel" for="${user.uidNumber.field_id}"
            py:content="user.uidNumber.label" />
        </th>
        <td>
          ${value_for(user.uidNumber)}
        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${user.gidNumber.field_id}"
            py:content="user.gidNumber.label" />
        </th>
        <td>
          ${value_for(user.gidNumber)}
        </td>
      </tr>
    </table>

    <div class="formsection">Identity Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${user.givenName.field_id}"
            py:content="user.givenName.label" />
        </th>
        <td>
          <span py:replace="user.givenName.display(value_for(user.givenName))" />
          <span py:if="tg.errors.get('givenName')" class="fielderror"
              py:content="tg.errors.get('givenName')" />

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
          <label class="fieldlabel" for="${user.telephoneNumber.field_id}"
            py:content="user.telephoneNumber.label" />
        </th>
        <td>
          <span py:replace="user.telephoneNumber.display(value_for(user.telephoneNumber))" />
          <span py:if="tg.errors.get('telephoneNumber')" class="fielderror"
              py:content="tg.errors.get('telephoneNumber')" />
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
