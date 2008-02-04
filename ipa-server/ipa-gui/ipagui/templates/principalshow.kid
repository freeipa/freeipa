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
    py:extends="'policylayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>View Service Principal</title>
</head>
<body>

  <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>

  <script type="text/javascript" charset="utf-8">
    function confirmDelete() {
      if (confirm("Are you sure you want to delete this service principal?")) {
        $('deleteform').submit();
      }
      return false;
    }
  </script>

  <form id='deleteform'
    method="post" action="${tg.url('/principal/delete')}">

    <input type="hidden" name="principal" value="${principal.get('principal_dn')}" />

    <input type="submit" class="submitbutton"
         value="Delete Principal"
         onclick="return confirmDelete();"
    />

  <h1>View Service Principal</h1>

    <h2 class="formsection">Principal</h2>
    <table class="formtable" cellpadding="2" cellspacing="0" border="0">
        <tr>
          <th>
            <label class="fieldlabel">Host</label>:
          </th>
          <td>${principal.get("hostname")}</td>
        </tr>
        <tr>
          <th>
            <label class="fieldlabel">Service</label>:
          </th>
          <td>${principal.get("service")}</td>
        </tr>
    </table>
  </form>

<hr />

</body>
</html>
