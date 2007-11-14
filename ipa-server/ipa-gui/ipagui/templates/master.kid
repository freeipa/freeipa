<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<?python import sitetemplate ?>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#" py:extends="sitetemplate">

<head py:match="item.tag=='{http://www.w3.org/1999/xhtml}head'" py:attrs="item.items()">
    <meta content="text/html; charset=UTF-8" http-equiv="content-type" py:replace="''"/>
    <title py:replace="''">Your title goes here</title>
    <meta py:replace="item[:]"/>
    <style type="text/css" media="all">
    @import "${tg.url('/static/css/style.css')}";
    </style>
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/prototype.js')}"></script>
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/scriptaculous.js?load=effects')}"></script>
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/ipautil.js')}"></script>
</head>

<body py:match="item.tag=='{http://www.w3.org/1999/xhtml}body'" py:attrs="item.items()">

    <div id="head">
      <h1><a href="${tg.url('/')}">Free IPA</a></h1>
      <div id="headerinfo">
        <div id="searchbar">
          <form action="${tg.url('/topsearch')}" method="post">
            <select name="searchtype">
                <option>Users</option>
                <option>Groups</option>
            </select>
            <input class="searchtext" id="topsearchbox" type="text"
              name="searchvalue"
              value="Type search terms here."
              onfocus="clearsearch()" />
            <input type="submit" value="Search"/>
          </form>
          <script type="text/javascript">
            function clearsearch() {
              topsearchbox = document.getElementById('topsearchbox');
              topsearchbox.onfocus = null;
              topsearchbox.value = "";
            }
          </script>
        </div>
      </div>
</div>
      <div id="navbar">
<!-- hiding the tabs
        <ul>
          <li><a href="#">Overview</a></li>
          <li class="active"><a href="#">Users</a></li>
          <li><a href="#">Groups</a></li>
          <li><a href="#">Resources</a></li>
          <li><a href="#">Policy</a></li>
          <li><a href="#">Search</a></li>
        </ul>
-->
  <div id="login">
    <div py:if="tg.config('identity.on') and not defined('logging_in')" id="pageLogin">
        <span py:if="tg.identity.anonymous">
            Kerberos login failed.
        </span>
        <span py:if="not tg.identity.anonymous">
            Logged in as: ${tg.identity.user.display_name}
        </span>
    </div>
        </div>


      </div>

    <div id="content">
      <div id="sidebar">
        <h2>Tasks</h2>
        <ul>
        <li py:if="'admins' in tg.identity.groups"><a href="${tg.url('/user/new')}">Add Person</a></li>
        <li><a href="${tg.url('/user/list')}">Find People</a></li>
        </ul>
        <ul>
        <li py:if="'admins' in tg.identity.groups"><a href="${tg.url('/group/new')}">Add Group</a></li>
        <li><a href="${tg.url('/group/list')}">Find Groups</a></li>
        </ul>
        <ul py:if="'admins' in tg.identity.groups">
        <li><a href="${tg.url('/policy/index')}">Manage Policy</a></li>
        </ul>
        <ul>
        <li><a href="${tg.url('/user/edit/', principal=tg.identity.user.display_name)}">Self Service</a></li>
        </ul>
        <ul py:if="'admins' in tg.identity.groups">
        <li><a href="${tg.url('/delegate/list')}">Delegations</a></li>
        </ul>
      </div>

      <div py:replace="[item.text]+item[:]"></div>


    </div>

      <div id="footer">
        <a href="http://www.freeipa.com/" target="_blank">Powered by FreeIPA</a>
      </div>
</body>

</html>
