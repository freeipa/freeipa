<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'grouplayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>View Group</title>
</head>
<body>
<?python
cn = group.get('cn')
if isinstance(cn, list):
    cn = cn[0]
edit_url = tg.url('/group/edit', cn=cn)
from ipagui.helpers import userhelper
?>
<div id="details">
    <h1>View Group</h1>

    <input py:if="'editors' in tg.identity.groups or 'admins' in tg.identity.groups"
      class="submitbutton" type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Group" />

    <h2 class="formsection">Group Details</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.cn.label" />:
          </th>
          <td>${group.get("cn")}</td>
        </tr>

        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.description.label" />:
          </th>
          <td>${group.get("description")}</td>
        </tr>

        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.gidnumber.label" />:
          </th>
          <td>${group.get("gidnumber")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel" py:content="fields.nsAccountLock.label" />:
          </th>
          <td>${userhelper.account_status_display(group.get("nsAccountLock"))}</td>
         </tr>
    </table>

    <h2 class="formsection">Group Members</h2>
    <div py:for="member in members">
      <?python

      member_uid = member.get('uid')
      if member_uid:
          member_cn = "%s %s" % (member.get('givenName', ''), member.get('sn', ''))
          member_desc = "(%s)" % member_uid
          member_type = "user"
          view_url = tg.url('/user/show', uid=member_uid)
      else:
          mem = member.get('cn')
          if isinstance(mem, list):
              mem = mem[0]
          member_cn = "%s" % mem
          member_desc = "[group]"
          member_type = "group"
          view_url = tg.url('/group/show', cn=member_cn)
      ?>
      <span py:if='member_type == "user"'>
        <a href="${view_url}"
          >${member_cn}</a> ${member_desc}
      </span>
      <span py:if='member_type == "group"'>
        <i>
          <a href="${view_url}"
            >${member_cn}</a> ${member_desc}
        </i>
      </span>
    </div>

    <br/>
<hr />
    <input py:if="'editors' in tg.identity.groups or 'admins' in tg.identity.groups"
      class="submitbutton" type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Group" />
</div>
</body>
</html>
