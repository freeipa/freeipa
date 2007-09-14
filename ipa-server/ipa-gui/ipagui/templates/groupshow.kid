<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'grouplayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>View Group</title>
</head>
<body>
    <h2>View Group</h2>

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
      member_name = "%s %s" % (member.get('givenname', ''),
                               member.get('sn', ''))
      ?>
      ${member_name} (${member.get('uid')})
    </div>

    <br/>
    <br/>

    <a href="${tg.url('/groupedit', cn=group.get('cn'))}">edit</a>

</body>
</html>
