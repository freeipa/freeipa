<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'userlayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>View Person</title>
</head>
<body>
<?python
edit_url = tg.url('/user/edit', uid=user.get('uid'))
?>
    <h2>View Person</h2>

    <input type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Person" />

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
            <label class="fieldlabel" py:content="fields.title.label" />:
          </th>
          <td>${user.get("title")}</td>
        </tr>
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
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.cn.label" />:
          </th>
          <td>${user.get("cn")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.displayname.label" />:
          </th>
          <td>${user.get("displayname")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.initials.label" />:
          </th>
          <td>${user.get("initials")}</td>
        </tr>
    </table>

    <div class="formsection">Account Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.nsAccountLock.label" />:
          </th>
          <td>${userhelper.account_status_display(user.get("nsAccountLock"))}</td>
        </tr>
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
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.homedirectory.label" />:
          </th>
          <td>${user.get("homedirectory")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.loginshell.label" />:
          </th>
          <td>${user.get("loginshell")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.gecos.label" />:
          </th>
          <td>${user.get("gecos")}</td>
        </tr>
    </table>

    <div class="formsection">Contact Details</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.mail.label" />:
          </th>
          <td><a href="mailto:${user.get('mail')}">${user.get("mail")}</a></td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.telephonenumber.label" />:
          </th>
          <td>${user.get("telephonenumber")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.facsimiletelephonenumber.label" />:
          </th>
          <td>${user.get("facsimiletelephonenumber")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.mobile.label" />:
          </th>
          <td>${user.get("mobile")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.pager.label" />:
          </th>
          <td>${user.get("pager")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.homephone.label" />:
          </th>
          <td>${user.get("homephone")}</td>
        </tr>
    </table>

    <div class="formsection">Mailing Address</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.street.label" />:
          </th>
          <td>${user.get("street")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.l.label" />:
          </th>
          <td>${user.get("l")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.st.label" />:
          </th>
          <td>${user.get("st")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.postalcode.label" />:
          </th>
          <td>${user.get("postalcode")}</td>
        </tr>
    </table>

    <div class="formsection">Employee Information</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.ou.label" />:
          </th>
          <td>${user.get("ou")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.businesscategory.label" />:
          </th>
          <td>${user.get("businesscategory")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.description.label" />:
          </th>
          <td>${user.get("description")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.employeetype.label" />:
          </th>
          <td>${user.get("employeetype")}</td>
        </tr>
        <tr py:if='user_manager'>
          <th>
            Manager:
          </th>
          <td>
            <a href="${tg.url('/user/show', uid=user_manager.uid)}"
              >${user_manager.givenname} ${user_manager.sn}</a>
          </td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.roomnumber.label" />:
          </th>
          <td>${user.get("roomnumber")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.secretary.label" />:
          </th>
          <td>TODO</td>
        </tr>
    </table>

    <div class="formsection">Misc Information</div>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.carlicense.label" />:
          </th>
          <td>${user.get("carlicense")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.labeleduri.label" />:
          </th>
          <td>
            <a href="${user.get('labeleduri')}">${user.get('labeleduri')}</a>
          </td>
        </tr>
    </table>

    <div class="formsection" py:if='len(user_reports) &gt; 0'>Direct Reports</div>
    <ol>
      <li py:for="report in user_reports">
        <a href="${tg.url('/user/show', uid=report.uid)}"
          >${report.givenname} ${report.sn}</a>
      </li>
    </ol>

    <div class="formsection">Groups</div>
    <div py:for="group in user_groups">
      <a href="${tg.url('/group/show', cn=group.cn)}">${group.cn}</a>
    </div>

    <br/>

    <input type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Person" />

</body>
</html>
