<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'grouplayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>View Group</title>
</head>
<body>
<?python
edit_url = tg.url('/groupedit', cn=group.get('cn'))
?>
    <h2>View Group</h2>

    <input type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Group" />

    <div class="formsection">Group Details</div>
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
    </table>

    <div class="formsection">Group Members</div>
    <div py:for="member in members">
      <?python

      member_uid = member.get('uid')
      if member_uid:
          member_cn = "%s %s" % (member.get('givenName'), member.get('sn'))
          member_desc = "(%s)" % member_uid
          member_type = "user"
          view_url = tg.url('usershow', uid=member_uid)
      else:
          member_cn = "%s" % member.get('cn')
          member_desc = "[group]"
          member_type = "group"
          view_url = tg.url('groupshow', cn=member_cn)
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

    <input type="button"
      onclick="document.location.href='${edit_url}'"
      value="Edit Group" />

</body>
</html>
