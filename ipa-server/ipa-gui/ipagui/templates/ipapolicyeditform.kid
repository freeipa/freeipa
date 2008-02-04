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
  <script type="text/javascript" charset="utf-8"
    src="${tg.url('/tg_widgets/tg_expanding_form_widget/javascript/expanding_form.js')}"></script>

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
        <tr>
          <th>
            <label class="fieldlabel" py:content="ipapolicy_fields.ipadefaultemaildomain.label" />:
          </th>
          <td>
          <span py:replace="ipapolicy_fields.ipadefaultemaildomain.display(value_for(ipapolicy_fields.ipadefaultemaildomain))" />
          <span py:if="tg.errors.get('ipadefaultemaildomain')" class="fielderror"
              py:content="tg.errors.get('ipadefaultemaildomain')" />
          </td>
        </tr>
      <tr>
        <th>
          <label class="fieldlabel" for="${ipapolicy_fields.userobjectclasses.field_id}"
            py:content="ipapolicy_fields.userobjectclasses.label" />:
        </th>
        <td colspan="3">
          <table class="formtable" cellpadding="2" cellspacing="0" border="0" id="${ipapolicy_fields.userobjectclasses.field_id}">
            <tbody>
              <?python repetition = 0
                       fld_index = 0
                       fld_error = tg.errors.get('ipauserobjectclasses')
              ?>
              <tr py:for="fld in value_for(ipapolicy_fields.ipauserobjectclasses)"
                  id="${ipapolicy_fields.userobjectclasses.field_id}_${repetition}"
                  class="${ipapolicy_fields.userobjectclasses.field_class}">

                <td py:for="field in ipapolicy_fields.userobjectclasses.fields">
                  <span><input class="textfield" type="text" id="${ipapolicy_fields.userobjectclasses.field_id}_${repetition}_ipauserobjectclasses" name="userobjectclasses-${repetition}.ipauserobjectclasses" value="${fld}"/></span>
                  <span py:if="fld_error and fld_error[fld_index]" class="fielderror"
                        py:content="tg.errors.get('ipauserobjectclasses')" />
                </td>
                <?python fld_index = fld_index + 1 ?>
                <td>
                  <a
                  href="javascript:ExpandingForm.removeItem('${ipapolicy_fields.userobjectclasses.field_id}_${repetition}')">Remove</a>
                </td>
                <?python repetition = repetition + 1?>
              </tr>
            </tbody>
          </table>
          <a id="${ipapolicy_fields.userobjectclasses.field_id}_doclink" href="javascript:ExpandingForm.addItem('${ipapolicy_fields.userobjectclasses.field_id}');">Add User Object Class</a>
        </td>
      </tr>
      <tr>
        <th>
          <label class="fieldlabel" for="${ipapolicy_fields.groupobjectclasses.field_id}"
            py:content="ipapolicy_fields.groupobjectclasses.label" />:
        </th>
        <td colspan="3">
          <table class="formtable" cellpadding="2" cellspacing="0" border="0" id="${ipapolicy_fields.groupobjectclasses.field_id}">
            <tbody>
              <?python repetition = 0
                       fld_index = 0
                       fld_error = tg.errors.get('ipagroupobjectclasses')
              ?>
              <tr py:for="fld in value_for(ipapolicy_fields.ipagroupobjectclasses)"
                  id="${ipapolicy_fields.groupobjectclasses.field_id}_${repetition}"
                  class="${ipapolicy_fields.groupobjectclasses.field_class}">

                <td py:for="field in ipapolicy_fields.groupobjectclasses.fields">
                  <span><input class="textfield" type="text" id="${ipapolicy_fields.groupobjectclasses.field_id}_${repetition}_ipagroupobjectclasses" name="groupobjectclasses-${repetition}.ipagroupobjectclasses" value="${fld}"/></span>
                  <span py:if="fld_error and fld_error[fld_index]" class="fielderror"
                        py:content="tg.errors.get('ipagroupobjectclasses')" />
                </td>
                <?python fld_index = fld_index + 1 ?>
                <td>
                  <a
                  href="javascript:ExpandingForm.removeItem('${ipapolicy_fields.groupobjectclasses.field_id}_${repetition}')">Remove</a>
                </td>
                <?python repetition = repetition + 1?>
              </tr>
            </tbody>
          </table>
          <a id="${ipapolicy_fields.groupobjectclasses.field_id}_doclink" href="javascript:ExpandingForm.addItem('${ipapolicy_fields.groupobjectclasses.field_id}');">Add Group Object Class</a>
        </td>
      </tr>
    </table>

    <hr/>

          <input type="submit" class="submitbutton" name="submit"
              value="Update Policy"/>
          <input type="submit" class="submitbutton" name="submit"
              value="Cancel Edit" />
  </form>

</div>
