<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'delegatelayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Delegations</title>
</head>
<body>
  <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>

  <h2>Delegations</h2>

  <table id="resultstable" class="sortable resizable">
    <thead>
    <tr>
      <th>Name</th>
      <th>People in Group</th>
      <th>Can Modify</th>
      <th>For People in Group</th>
      <th>Action</th>
    </tr>
    </thead>
    <tbody>
    <tr py:for='aci in aci_list'>
      <?python
      source_cn = group_dn_to_cn.get(aci.source_group)
      dest_cn = group_dn_to_cn.get(aci.dest_group)
      ?>
      <td>
        ${aci.name}
      </td>
      <td>
        <a href="${tg.url('/group/show', cn=source_cn)}"
          >${source_cn}</a>
      </td>
      <td>
        ${", ".join(aci.attrs)}
      </td>
      <td>
        <a href="${tg.url('/group/show', cn=dest_cn)}"
          >${dest_cn}</a>
      </td>
      <td>
        <a href="${tg.url('/delegate/edit')}">edit</a> (TODO)<br />
      </td>
    </tr>
    </tbody>
  </table>

  <table border="0">
    <tbody>
    <tr>
      <td>
        <a href="${tg.url('/delegate/new')}">add new delegation</a><br />
      </td>
    </tr>
    </tbody>
  </table>
</body>
</html>
