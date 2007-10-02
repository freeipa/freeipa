<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'grouplayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Find Groups</title>
</head>
<body>
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>
    <div id="search">
        <form action="${tg.url('/grouplist')}" method="get">
            <input id="criteria" type="text" name="criteria" value="${criteria}" />
            <input type="submit" value="Find Groups"/>
        </form>
        <script type="text/javascript">
            document.getElementById("criteria").focus();
        </script>
    </div>
    <div py:if='(groups != None) and (len(groups) > 0)'>
        <h2>${len(groups)} results returned:</h2>
        <table id="resultstable" class="sortable resizable">
          <thead>
            <tr>
                <th>
                    ${fields.cn.label}
                </th>
                <th>
                    ${fields.description.label}
                </th>
            </tr>
          </thead>
          <tbody>
            <tr py:for="group in groups">
                <td>
                    <a href="${tg.url('/groupshow',cn=group.cn)}">${group.cn}</a>
                </td>
                <td>
                    ${group.description}
                </td>
            </tr>
          </tbody>
        </table>
    </div>
    <div py:if='(groups != None) and (len(groups) == 0)'>
        <h2>No results found for "${criteria}"</h2>
    </div>
    <div py:if='groups == None'>
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
