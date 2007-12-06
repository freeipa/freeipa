<div xmlns:py="http://purl.org/kid/ns#"
  class="simpleroster">
  <form action="${action}" name="${name}" method="${method}" class="tableform"
      onsubmit="preSubmit()" >

          <input type="submit" class="submitbutton" name="submit" value="Add Principal"/>

<?python
from ipagui.helpers import ipahelper
?>

  <script type="text/javascript" charset="utf-8"
    src="${tg.url('/static/javascript/dynamicedit.js')}"></script>

  <?python searchurl = tg.url('/principal/edit_search') ?>

  <script type="text/javascript">
    function toggleOther(field) {
      otherField = document.getElementById('form_other');
      var e=document.getElementById(field).value;
      if ( e == "other") {
        otherField.disabled = false;
      } else {
        otherField.disabled =true;
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
  </script>

    <div py:for="field in hidden_fields"
      py:replace="field.display(value_for(field), **params_for(field))" 
      />

    <h2 class="formsection">Service Principal Details</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" for="${principal_fields.hostname.field_id}"
            py:content="principal_fields.hostname.label" />:
        </th>
        <td>
          <span py:replace="principal_fields.hostname.display(value_for(principal_fields.hostname))" />
          <span py:if="tg.errors.get('hostname')" class="fielderror"
              py:content="tg.errors.get('hostname')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${principal_fields.service.field_id}"
            py:content="principal_fields.service.label" />:
        </th>
        <td>
          <span py:replace="principal_fields.service.display(value_for(principal_fields.service))" />
          <span py:if="tg.errors.get('service')" class="fielderror"
              py:content="tg.errors.get('service')" />

        </td>
      </tr>

      <tr>
        <th>
          <label class="fieldlabel" for="${principal_fields.other.field_id}"
            py:content="principal_fields.other.label" />:
        </th>
        <td>
          <span py:replace="principal_fields.other.display(value_for(principal_fields.other))" />
          <span py:if="tg.errors.get('other')" class="fielderror"
              py:content="tg.errors.get('other')" />
          <script type="text/javascript">
              var e=document.getElementById('form_service').value;
              if ( e != "other") {
                  document.getElementById('form_other').disabled = true;
              }
          </script>

        </td>
      </tr>

    </table>

<hr />

 <input type="submit" class="submitbutton" name="submit" value="Add Principal"/>

  </form>

  <script type="text/javascript">
    document.getElementById("form_hostname").focus();
  </script>

</div>
