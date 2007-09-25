<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'userlayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>View Person</title>
</head>
<body>
    <h2>View Person</h2>

<?python
from ipagui.helpers import userhelper
pw_expires_days = userhelper.password_expires_in(user.get("krbPasswordExpiration"))
pw_expires_soon = userhelper.password_expires_soon(pw_expires_days)
pw_is_expired = userhelper.password_is_expired(pw_expires_days)
if pw_expires_days != 1:
    days_suffix = "s"
else:
    days_suffix = ""
?>

    <div py:if='pw_expires_soon' class="warning_message">
        Password will expire in ${pw_expires_days} day${days_suffix}
    </div>
    <div py:if='pw_is_expired' class="warning_message">
        Password has expired
    </div>

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
        <tr py:if='user_manager'>
          <th>
            Manager:
          </th>
          <td>
            <a href="${tg.url('/usershow', uid=user_manager.uid)}"
              >${user_manager.givenname} ${user_manager.sn}</a>
          </td>
        </tr>
    </table>

    <div class="formsection">Account Status</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
      <tr>
        <th>
          <label class="fieldlabel" py:content="fields.nsAccountLock.label" />:
        </th>
        <td>${userhelper.account_status_display(user.get("nsAccountLock"))}</td>
      </tr>
    </table>

    <div class="formsection" py:if='len(user_reports) &gt; 0'>Direct Reports</div>
    <div py:for="report in user_reports">
      <a href="${tg.url('/usershow', uid=report.uid)}"
        >${report.givenname} ${report.sn}</a>
    </div>

    <div class="formsection">Groups</div>
    <div py:for="group in user_groups">
      <a href="${tg.url('/groupshow', cn=group.cn)}">${group.cn}</a>
    </div>

    <br/>
    <br/>

    <a href="${tg.url('/useredit', uid=user.get('uid'))}">edit</a>

</body>
</html>
