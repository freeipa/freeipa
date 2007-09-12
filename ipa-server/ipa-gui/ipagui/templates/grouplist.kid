<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'grouplayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Find Groups</title>
</head>
<body>
    <div id="search">
        <form action="${tg.url('/grouplist')}" method="post">
            <input id="criteria" type="text" name="criteria" value="${criteria}" />
            <input type="submit" value="Find Groups"/>
        </form>
        <script type="text/javascript">
            document.getElementById("criteria").focus();
        </script>
    </div>
    <div py:if='(groups != None) and (len(groups) > 0)'>
        <h2>${len(groups)} results returned:</h2>
        <table id="resultstable">
            <tr>
                <th>
                    <label class="fieldlabel" py:content="fields.cn.label" />
                </th>
                <th>
                    <label class="fieldlabel" py:content="fields.description.label" />
                </th>
            </tr>
            <tr py:for="group in groups">
                <td>
                    <a href="${tg.url('/groupshow',cn=group.cn)}">${group.cn}</a>
                </td>
                <td>
                    ${group.description}
                </td>
            </tr>
        </table>
    </div>
    <div py:if='(groups != None) and (len(groups) == 0)'>
        <h2>No results found for "${criteria}"</h2>
    </div>
</body>
</html>
