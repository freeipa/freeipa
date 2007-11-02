<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'userlayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Find People</title>
</head>
<body>
    <h1>Find People</h1>
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>
    <div id="search">
        <form action="${tg.url('/user/list')}" method="get">
            <input id="uid" type="text" name="uid" value="${uid}" />
            <input class="searchbutton" type="submit" value="Find People"/>
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
                    Person
                </th>
                <th>
                    Phone
                </th>
                <th>
                    Unit
                </th>
                <th>
                    Title
                </th>
            </tr>
          </thead>
          <tbody>
            <tr py:for="user in users" py:if="user.nsAccountLock != 'true'">
                <td>
                    <a href="${tg.url('/user/show',uid=user.uid)}"
                    >${user.givenName} ${user.sn}</a>
                    (${user.uid})
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
                    <a href="${tg.url('/user/show',uid=user.uid)}"
                    >${user.givenName} ${user.sn}</a>
                    (${user.uid})
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
        <p id="alertbox">No results found for "${uid}"</p>
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
