<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'master.kid'">
<head>
</head>

<body py:match="item.tag=='{http://www.w3.org/1999/xhtml}body'" py:attrs="item.items()">
      <div id="main_content">
       <div id="details">
        <div id="alertbox" py:if="value_of('tg_flash', None)">
         <p py:content="XML(tg_flash)"></p></div>

        <div py:replace="[item.text]+item[:]"></div>
      </div>

      </div>
</body>

</html>
