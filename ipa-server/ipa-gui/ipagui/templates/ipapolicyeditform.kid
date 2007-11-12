<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">

   <form action="${action}" name="${name}" method="${method}" class="tableform"
      onsubmit="preSubmit()" >

          <input type="submit" class="submitbutton" name="submit"
              value="Update Policy"/>
          <input type="submit" class="submitbutton" name="submit"
              value="Cancel Edit" />

<?python
from ipagui.helpers import ipahelper
?>

  <script type="text/javascript" charset="utf-8"
    src="${tg.url('/static/javascript/dynamicedit.js')}"></script>

    <div py:for="field in hidden_fields"
      py:replace="field.display(value_for(field), **params_for(field))"
      />

    <h2 class="formsection">Search</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.searchlimit.label" />:
          </th>
        <td>
          <span py:replace="ipapolicy_fields.searchlimit.display(value_for(ipapolicy_fields.searchlimit))" />
          <span py:if="tg.errors.get('searchlimit')" class="fielderror"
              py:content="tg.errors.get('searchlimit')" />
        </td>
        </tr>
    </table>

    <h2 class="formsection">Password Policy</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.passwordnotif.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.passwordnotif.display(value_for(ipapolicy_fields.passwordnotif))" />
          <span py:if="tg.errors.get('passwordnotif')" class="fielderror"
              py:content="tg.errors.get('passwordnotif')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.maxuidlength.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.maxuidlength.display(value_for(ipapolicy_fields.maxuidlength))" />
          <span py:if="tg.errors.get('maxuidlength')" class="fielderror"
              py:content="tg.errors.get('maxuidlength')" />
          </td>
        </tr>
    </table>
  </form>

</div>
