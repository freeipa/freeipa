<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'userlayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>User Listing</title>
</head>
<body>
      <fieldset>
        <legend>People List</legend>
        <div>
          Page: 
          <span py:for="page in tg.paginate.pages">
              <a py:if="page != tg.paginate.current_page"
                  href="${tg.paginate.get_href(page)}">${page}</a>
              <b py:if="page == tg.paginate.current_page">${page}</b>
          </span>
          <p/>
          <span py:for="user in users">
             <a href="${tg.url('/usershow',uid=user.uid)}">${user.cn}</a>
            <br/>
          </span>
        </div>
       </fieldset>
</body>
</html>
