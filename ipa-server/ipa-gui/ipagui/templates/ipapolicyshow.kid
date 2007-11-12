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
            <label class="fieldlabel" py:content="fields.searchlimit.label" />:
          </th>
          <td>${ipapolicy.get("searchlimit")}</td>
        </tr>
    </table>

    <h2 class="formsection">Password Policy</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.passwordnotif.label" />:
          </th>
          <td>${ipapolicy.get("passwordnotif")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.maxuidlength.label" />:
          </th>
          <td>${ipapolicy.get("maxuidlength")}</td>
        </tr>
    </table>
<hr />
    <input class="submitbutton" type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Policy" />


</body>
</html>
