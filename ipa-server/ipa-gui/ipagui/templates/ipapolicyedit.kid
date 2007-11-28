<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'policylayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>Edit IPA Policy</title>
</head>
<body>
  <div>
          <h1>Edit IPA Policy</h1>

  ${form.display(action=tg.url('/ipapolicy/update'), value=ipapolicy)}
</div>
</body>
</html>
