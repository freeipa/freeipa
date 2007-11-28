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

  <h1>Manage IPA Policy</h1>

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
    </table>
<hr />
    <input class="submitbutton" type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Policy" />


</body>
</html>
