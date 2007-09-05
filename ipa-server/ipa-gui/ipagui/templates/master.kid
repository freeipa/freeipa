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
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/prototype.js')}"></script>
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/scriptaculous.js?load=effects')}"></script>
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
        <div id="login">
          Logged in as: ace
        </div>
        <div id="logo">
            <a href="${tg.url('/')}"><img 
            src="${tg.url('/static/images/logo.png')}"
            border="0"
            /></a>
        </div>
      </div>

      <div id="nav"><!-- 
      This used to have links.  Keeping around in case we move them back...
      --></div>

      <div id="sidebar">
        <h2>Tasks</h2>
        <p>
        <a href="${tg.url('/usernew')}">Add Person</a><br/>
        <a href="${tg.url('/userlist')}">Find People</a><br/>
        </p>
        <p>
        <a href="${tg.url('/groupindex')}">Add Group</a><br/>
        <a href="${tg.url('/groupindex')}">Find Groups</a><br/>
        </p>
        <p>
        <a href="${tg.url('/')}">Manage Policy</a><br/>
        <a href="${tg.url('/')}">Self Service</a><br/>
        </p>
      </div>

      <div py:replace="[item.text]+item[:]"></div>


      <div id="footer">
        <a href="http://www.freeipa.com/" target="_blank">Powered by FreeIPA</a>
      </div>
    </div>

</body>

</html>
