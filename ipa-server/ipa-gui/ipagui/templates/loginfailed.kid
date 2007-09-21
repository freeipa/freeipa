<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"
    xmlns:py="http://purl.org/kid/ns#">

<head>
    <meta content="text/html; charset=UTF-8"
        http-equiv="content-type" py:replace="''"/>
    <title>Login Failure</title>
</head>

<body>
    <div id="header">
      <div id="logo">
        <a href="${tg.url('/')}"><img 
        src="${tg.url('/static/images/logo.png')}"
        border="0" alt="homepage"
        /></a>
      </div>
      <div id="headerinfo">
        <div id="login">
    <div py:if="tg.config('identity.on') and not defined('logging_in')" id="page
Login">
        <span py:if="tg.identity.anonymous">
            Kerberos login failed.
        </span>
        <span py:if="not tg.identity.anonymous">
            Logged in as: ${tg.identity.user.display_name}
        </span>
        </div>
      </div>
    </div>
    </div>
</body>
</html>
