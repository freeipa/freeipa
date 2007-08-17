<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'userlayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>User Listing</title>
</head>
<body>
    <div id="search">
        <form action="${tg.url('/userlist')}" method="post">
            Search by uid:
            <input type="text" name="uid" />
            <input type="submit" />
        </form>
    </div>
    <div py:if='users != None'>
        <h2>Results</h2>
        <table py:if='len(users) > 0'>
            <tr>
                <th>
                    <label class="fieldlabel" py:content="fields.uid.label" />
                </th>
                <th>
                    Name
                </th>
            </tr>
            <tr py:for="user in users">
                <td>
                    <a href="${tg.url('/usershow',uid=user.uid)}">${user.uid}</a>
                </td>
                <td>
                    ${user.cn}
                </td>
            </tr>
        </table>
        <div py:if='len(users) == 0'>
            No results found.
        </div>
    </div>

    <!-- fix for visual artifact of my crappy ui -->
    <div>
        <br /><br /><br /><br />
    </div>
</body>
</html>
