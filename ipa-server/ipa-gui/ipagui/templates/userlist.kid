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
    py:extends="'userlayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Find Users</title>
</head>
<body>
    <h1 class="user">Find Users</h1>
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>
    <div id="search">
        <form action="${tg.url('/user/list')}" method="get">
            <input id="uid" type="text" name="uid" value="${uid}" />
            <input class="searchbutton" type="submit" value="Find Users"/>
        </form>
        <script type="text/javascript">
            document.getElementById("uid").focus();
        </script>
    </div>
    <div py:if='(users != None) and (len(users) > 0)'>
        <h2>${len(users)} results returned:</h2>
        <table id="resultstable" class="details sortable resizable" cellspacing="0">
          <thead>
            <tr>
                <th>
                    User
                </th>
                <th>
                    Phone
                </th>
                <th>
                    Unit
                </th>
                <th>
                    Job Title
                </th>
            </tr>
          </thead>
          <tbody>
            <tr py:for="user in users" py:if="user.nsAccountLock != 'true'">
                <td>
                    <a
                      href="${tg.url('/user/show',uid=user.uid)}"
                      py:content="u'%s %s (%s)' % (user.givenName, user.sn, user.uid)"
                    />
                </td>
                <td>
                    ${user.telephoneNumber}
                </td>
                <td>
                    ${user.ou}
                </td>
                <td>
                    ${user.title}
                </td>
            </tr>
          </tbody>
          <tbody>
            <tr id="inactive" py:for="user in users" py:if="user.nsAccountLock == 'true'">
                <td>
                    <a
                      href="${tg.url('/user/show',uid=user.uid)}"
                      py:content="u'%s %s (%s)' % (user.givenName, user.sn, user.uid)"
                    />
                </td>
                <td>
                    ${user.telephoneNumber}
                </td>
                <td>
                    ${user.ou}
                </td>
                <td>
                    ${user.title}
                </td>
            </tr>
          </tbody>
        </table>
    </div>
    <div id="alertbox" py:if='(users != None) and (len(users) == 0)'>
        <p>No results found for "${uid}"</p>
    </div>

    <div class="instructions" py:if='users == None'>
      <p>
        Search automatically looks across multiple fields.  If you want to find
        Joe in Finance, try typing "joe finance" into the search box.
      </p>
      <p>
        Exact matches are listed first, followed by partial matches.  If your search
        is too broad, you will get a warning that the search returned too many
        results.  Try being more specific.
      </p>
      <p>
        The results that come back are sortable.  Simply click on a column
        header to sort on that header.  A triangle will indicate the sorted
        column, along with its direction. Clicking and dragging between headers
        will allow you to resize the header.
      </p>
    </div>
</body>
</html>
