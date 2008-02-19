<!-- 
 Copyright (C) 2007  Red Hat
 see file 'COPYING' for use and warranty information

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 only

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
-->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'delegatelayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Delegations</title>
</head>
<body>

<?python
from ipagui.helpers import ipahelper
?>

  <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>

  <script type="text/javascript">
    function editDelegation(acistr) {
      $('edit_acistr').value = acistr;
      $('editform').submit();
      return false;
    }
  </script>

  <form style="display:none" id='editform'
    method="post" action="${tg.url('/delegate/edit')}">
    <input type="hidden" id="edit_acistr" name="acistr" value="" />
  </form>
  <h1 class="accesscontrol">Delegations</h1>

  <table id="resultstable" class="details sortable resizable">
    <thead>
    <tr>
      <th>${fields.name.label}</th>
      <th>${fields.source_group_cn.label}</th>
      <th>${fields.attrs.label}</th>
      <th>${fields.dest_group_cn.label}</th>
    </tr>
    </thead>
    <tbody>
    <tr py:for='aci in aci_list'>
      <?python
      source_cn = group_dn_to_cn.get(aci.source_group)
      dest_cn = group_dn_to_cn.get(aci.dest_group)
      acistr = aci.orig_acistr
      acistr_esc = ipahelper.javascript_string_escape(acistr)
      ?>
      <td>
        <a href="#" onclick="return editDelegation('${acistr_esc}');"
        >${aci.name}</a>
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
