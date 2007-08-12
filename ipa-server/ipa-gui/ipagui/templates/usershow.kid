<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'userlayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>View a Person</title>
</head>
<body>
    <h2>View User</h2>

    <div class="formsection">Account Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>User ID:</th>
          <td>${user.get("uid")}</td>
        </tr>
        <tr>
          <th>UID:</th>
          <td>${user.get("uidNumber")}</td>
        </tr>
        <tr>
          <th>GID:</th>
          <td>${user.get("gidNumber")}</td>
        </tr>
    </table>

    <div class="formsection">Identity Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>Full Name:</th>
          <td>${user.get("givenName")} ${user.get("sn")}</td>
        </tr>
    </table>

    <div class="formsection">Contact Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>Email:</th>
          <td>${user.get("mail")}</td>
        </tr>
        <tr>
          <th>Telephone:</th>
          <td>${user.get("telephoneNumber")}</td>
        </tr>
    </table>

    <a href="${tg.url('/useredit', uid=user.get('uid'))}">edit</a>

</body>
</html>
