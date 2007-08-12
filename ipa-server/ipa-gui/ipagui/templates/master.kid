<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<?python import sitetemplate ?>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#" py:extends="sitetemplate">

<head py:match="item.tag=='{http://www.w3.org/1999/xhtml}head'" py:attrs="item.items()">
    <meta content="text/html; charset=UTF-8" http-equiv="content-type" py:replace="''"/>
    <title py:replace="''">Your title goes here</title>
    <meta py:replace="item[:]"/>
    <style type="text/css" media="screen">
    @import "${tg.url('/static/css/style.css')}";
    </style>
</head>

<body py:match="item.tag=='{http://www.w3.org/1999/xhtml}body'" py:attrs="item.items()">
    <div py:if="tg.config('identity.on') and not defined('logging_in')" id="pageLogin">
        <span py:if="tg.identity.anonymous">
            <a href="${tg.url('/login')}">Login</a>
        </span>
        <span py:if="not tg.identity.anonymous">
            Welcome ${tg.identity.user.display_name}.
            <a href="${tg.url('/logout')}">Logout</a>
        </span>
    </div>

    <div id="page">
      <div id="header">
        <h1>Free IPA</h1>
      </div>

      <div id="nav">
        <ul>
          <li><a href="${tg.url('/userindex')}">Users</a></li>
          <li><a href="${tg.url('/groupindex')}">Groups</a></li>
          <li><a href="${tg.url('/resindex')}">Resources</a></li>
        </ul>
      </div>

      <div py:replace="[item.text]+item[:]"></div>


      <div id="footer">
        This is the footer
      </div>
    </div>

</body>

</html>
