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
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'policylayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Manage IPA Policy</title>
</head>
<body>

<?python
from ipagui.helpers import ipahelper
edit_url = tg.url('/ipapolicy/edit')
?>

  <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>

  <h1 class="policy">Manage IPA Policy</h1>
    <input class="submitbutton" type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Policy" />

    <h2 class="formsection">Search</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipasearchtimelimit.label" />:
          </th>
          <td>${ipapolicy.get("ipasearchtimelimit")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipasearchrecordslimit.label" />:
          </th>
          <td>${ipapolicy.get("ipasearchrecordslimit")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipausersearchfields.label" />:
          </th>
          <td>${ipapolicy.get("ipausersearchfields")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipagroupsearchfields.label" />:
          </th>
          <td>${ipapolicy.get("ipagroupsearchfields")}</td>
        </tr>
    </table>

    <h2 class="formsection">Password Policy</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipapwdexpadvnotify.label" />:
          </th>
          <td>${ipapolicy.get("ipapwdexpadvnotify")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.krbminpwdlife.label" />:
          </th>
          <td>${password.get("krbminpwdlife")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.krbmaxpwdlife.label" />:
          </th>
          <td>${password.get("krbmaxpwdlife")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.krbpwdmindiffchars.label" />:
          </th>
          <td>${password.get("krbpwdmindiffchars")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.krbpwdminlength.label" />:
          </th>
          <td>${password.get("krbpwdminlength")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.krbpwdhistorylength.label" />:
          </th>
          <td>${password.get("krbpwdhistorylength")}</td>
        </tr>
    </table>
    <h2 class="formsection">User Settings</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipamaxusernamelength.label" />:
          </th>
          <td>${ipapolicy.get("ipamaxusernamelength")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipahomesrootdir.label" />:
          </th>
          <td>${ipapolicy.get("ipahomesrootdir")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipadefaultloginshell.label" />:
          </th>
          <td>${ipapolicy.get("ipadefaultloginshell")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipadefaultprimarygroup.label" />:
          </th>
          <td>${ipapolicy.get("ipadefaultprimarygroup")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipadefaultemaildomain.label" />:
          </th>
          <td>${ipapolicy.get("ipadefaultemaildomain")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipauserobjectclasses.label" />:
          </th>
          <td>
          <table cellpadding="2" cellspacing="0" border="0">
            <tbody>
              <?python
                index = 0
                values = ipapolicy.get("ipauserobjectclasses", '')
                if isinstance(values, str):
                    values = [values]
               ?>
              <tr py:for="index in range(len(values))">
              <td>${values[index]}</td>
              </tr>
            </tbody>
          </table>
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ipagroupobjectclasses.label" />:
          </th>
          <td>
          <table cellpadding="2" cellspacing="0" border="0">
            <tbody>
              <?python
                index = 0
                values = ipapolicy.get("ipagroupobjectclasses", '')
                if isinstance(values, str):
                    values = [values]
               ?>
              <tr py:for="index in range(len(values))">
              <td>${values[index]}</td>
              </tr>
            </tbody>
          </table>
          </td>
        </tr>
    </table>
<hr />
    <input class="submitbutton" type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Policy" />


</body>
</html>
