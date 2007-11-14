<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'grouplayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>View Group</title>
</head>
<body>
<?python
edit_url = tg.url('/group/edit', cn=group.get('cn')[0])
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
          <td>
          <table cellpadding="2" cellspacing="0" border="0">
            <tbody>
              <?python
                index = 0
                values = group.get("cn")      
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
          member_cn = "%s" % member.get('cn')[0]
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
