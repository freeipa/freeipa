<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'userlayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>View Person</title>
</head>
<body>
    <h2>View Person</h2>

    <div class="formsection">Identity Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.givenname.label" />:
          </th>
          <td>${user.get("givenname")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.sn.label" />:
          </th>
          <td>${user.get("sn")}</td>
        </tr>
    </table>

    <div class="formsection">Account Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.uid.label" />:
          </th>
          <td>${user.get("uid")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.uidnumber.label" />:
          </th>
          <td>${user.get("uidnumber")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.gidnumber.label" />:
          </th>
          <td>${user.get("gidnumber")}</td>
        </tr>
    </table>

    <div class="formsection">Contact Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.mail.label" />:
          </th>
          <td>${user.get("mail")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.telephonenumber.label" />:
          </th>
          <td>${user.get("telephonenumber")}</td>
        </tr>
    </table>

    <div class="formsection">Account Status</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" py:content="fields.nsAccountLock.label" />:
        </th>
        <td>${user.get("nsAccountLock")}</td>
      </tr>
    </table>

    <a href="${tg.url('/useredit', uid=user.get('uid'))}">edit</a>

</body>
</html>
