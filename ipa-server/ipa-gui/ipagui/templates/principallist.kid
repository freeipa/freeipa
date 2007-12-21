<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'principallayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Find Service Principals</title>
</head>
<body>
    <h1>Find Service Principals</h1>
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>
    <div id="search">
        <form action="${tg.url('/principal/list')}" method="get">
            <input id="hostname" type="text" name="hostname" value="${hostname}" />
            <input class="searchbutton" type="submit" value="Find Hosts"/>
        </form>
        <script type="text/javascript">
            document.getElementById("hostname").focus();
        </script>
    </div>
    <div py:if='(principals != None) and (len(principals) > 0)'>
        <h2>${len(principals)} results returned:</h2>
        <table id="resultstable" class="details sortable resizable" cellspacing="0">
          <thead>
            <tr>
                <th>
                    Hostname
                </th>
                <th>
                    Service
                </th>
            </tr>
          </thead>
          <tbody>
            <tr py:for="principal in principals">
                <td>
                    ${principal.hostname}
                </td>
                <td>
                    ${principal.service}
                </td>
            </tr>
          </tbody>
        </table>
    </div>
    <div id="alertbox" py:if='(principals != None) and (len(principals) == 0)'>
        <p id="alertbox">No results found for "${hostname}"</p>
    </div>

    <div class="instructions" py:if='principals == None'>
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
