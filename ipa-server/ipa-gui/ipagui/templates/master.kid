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
    <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/ipautil.js')}"></script>
</head>

<body py:match="item.tag=='{http://www.w3.org/1999/xhtml}body'" py:attrs="item.items()">

    <div id="header">
      <div id="logo">
        <a href="${tg.url('/')}"><img 
        src="${tg.url('/static/images/logo.png')}"
        border="0" alt="homepage"
        /></a>
      </div>
      <div id="headerinfo">
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
        <div id="topsearch">
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

    <div id="page">
      <div id="nav"><!-- 
      This used to have links.  Keeping around in case we move them back...
      --></div>

      <div id="sidebar">
        <h2>Tasks</h2>
        <p>
        <a href="${tg.url('/user/new')}">Add Person</a><br/>
        <a href="${tg.url('/user/list')}">Find People</a><br/>
        </p>
        <p>
        <a href="${tg.url('/group/new')}">Add Group</a><br/>
        <a href="${tg.url('/group/list')}">Find Groups</a><br/>
        </p>
        <p>
        <a href="${tg.url('/')}">Manage Policy</a><br/>
        <a href="${tg.url('/')}">Self Service</a><br/>
        </p>
        <p>
        <a href="${tg.url('/delegate/list')}">Delegation Mgmt</a><br/>
        </p>
      </div>

      <div py:replace="[item.text]+item[:]"></div>


      <div id="footer">
        <a href="http://www.freeipa.com/" target="_blank">Powered by FreeIPA</a>
      </div>
    </div>

</body>

</html>
