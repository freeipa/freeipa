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
            <label class="fieldlabel" py:content="ipapolicy_fields.ipasearchtimelimit.label" />:
          </th>
        <td>
          <span py:replace="ipapolicy_fields.ipasearchtimelimit.display(value_for(ipapolicy_fields.ipasearchtimelimit))" />
          <span py:if="tg.errors.get('ipasearchtimelimit')" class="fielderror"
              py:content="tg.errors.get('ipasearchtimelimit')" />
        </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipasearchrecordslimit.label" />:
          </th>
        <td>
          <span py:replace="ipapolicy_fields.ipasearchrecordslimit.display(value_for(ipapolicy_fields.ipasearchrecordslimit))" />
          <span py:if="tg.errors.get('ipasearchrecordslimit')" class="fielderror"
              py:content="tg.errors.get('ipasearchrecordslimit')" />
        </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipausersearchfields.label" />:
          </th>
        <td>
          <span py:replace="ipapolicy_fields.ipausersearchfields.display(value_for(ipapolicy_fields.ipausersearchfields))" />
          <span py:if="tg.errors.get('ipausersearchfields')" class="fielderror"
              py:content="tg.errors.get('ipausersearchfields')" />
        </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipagroupsearchfields.label" />:
          </th>
        <td>
          <span py:replace="ipapolicy_fields.ipagroupsearchfields.display(value_for(ipapolicy_fields.ipagroupsearchfields))" />
          <span py:if="tg.errors.get('ipagroupsearchfields')" class="fielderror"
              py:content="tg.errors.get('ipagroupsearchfields')" />
        </td>
        </tr>
    </table>

    <h2 class="formsection">Password Policy</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipapwdexpadvnotify.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.ipapwdexpadvnotify.display(value_for(ipapolicy_fields.ipapwdexpadvnotify))" />
          <span py:if="tg.errors.get('ipapwdexpadvnotify')" class="fielderror"
              py:content="tg.errors.get('ipapwdexpadvnotify')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.krbminpwdlife.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.krbminpwdlife.display(value_for(ipapolicy_fields.krbminpwdlife))" />
          <span py:if="tg.errors.get('krbminpwdlife')" class="fielderror"
              py:content="tg.errors.get('krbminpwdlife')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.krbmaxpwdlife.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.krbmaxpwdlife.display(value_for(ipapolicy_fields.krbmaxpwdlife))" />
          <span py:if="tg.errors.get('krbmaxpwdlife')" class="fielderror"
              py:content="tg.errors.get('krbmaxpwdlife')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.krbpwdmindiffchars.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.krbpwdmindiffchars.display(value_for(ipapolicy_fields.krbpwdmindiffchars))" />
          <span py:if="tg.errors.get('krbpwdmindiffchars')" class="fielderror"
              py:content="tg.errors.get('krbpwdmindiffchars')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.krbpwdminlength.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.krbpwdminlength.display(value_for(ipapolicy_fields.krbpwdminlength))" />
          <span py:if="tg.errors.get('krbpwdminlength')" class="fielderror"
              py:content="tg.errors.get('krbpwdminlength')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.krbpwdhistorylength.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.krbpwdhistorylength.display(value_for(ipapolicy_fields.krbpwdhistorylength))" />
          <span py:if="tg.errors.get('krbpwdhistorylength')" class="fielderror"
              py:content="tg.errors.get('krbpwdhistorylength')" />
          </td>
        </tr>
    </table>

    <h2 class="formsection">User Settings</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipamaxusernamelength.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.ipamaxusernamelength.display(value_for(ipapolicy_fields.ipamaxusernamelength))" />
          <span py:if="tg.errors.get('ipamaxusernamelength')" class="fielderror"
              py:content="tg.errors.get('ipamaxusernamelength')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipahomesrootdir.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.ipahomesrootdir.display(value_for(ipapolicy_fields.ipahomesrootdir))" />
          <span py:if="tg.errors.get('ipahomesrootdir')" class="fielderror"
              py:content="tg.errors.get('ipahomesrootdir')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipadefaultloginshell.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.ipadefaultloginshell.display(value_for(ipapolicy_fields.ipadefaultloginshell))" />
          <span py:if="tg.errors.get('ipadefaultloginshell')" class="fielderror"
              py:content="tg.errors.get('ipadefaultloginshell')" />
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipadefaultprimarygroup.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.ipadefaultprimarygroup.display(value_for(ipapolicy_fields.ipadefaultprimarygroup))" />
          <span py:if="tg.errors.get('ipadefaultprimarygroup')" class="fielderror"
              py:content="tg.errors.get('ipadefaultprimarygroup')" />
          </td>
        </tr>
    </table>
  </form>

</div>
