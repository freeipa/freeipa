<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'master.kid'">
<head>
</head>

<body py:match="item.tag=='{http://www.w3.org/1999/xhtml}body'" py:attrs="item.items()">
      <div id="main_content">
        <div id="status_block" class="flash" py:if="value_of('tg_flash', None)" py:content="tg_flash"></div>

        <div py:replace="[item.text]+item[:]"></div>
      </div>

      <div id="sidebar">
          <h2>Tools</h2>
          <a href="${tg.url('/usernew')}">Add Person</a><br/>
          <a href="${tg.url('/userindex')}">Find People</a><br/>
          <a href="${tg.url('/userlist')}">List People</a><br/>
      </div>
</body>

</html>
