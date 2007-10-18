<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"
  xmlns:py="http://purl.org/kid/ns#"
  py:extends="'master.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Error</title>
</head>

<body>
  <div id="main_content">
    <h1>An unexpected error occured</h1>

    <div py:if='message'>
      <b>Message:</b>
      <pre>${message}</pre>
    </div>

    <div py:if='error_msg'>
      <b>HTTP Error Message:</b>
      <pre>${error_msg}</pre>
    </div>

    <div py:if='details'>
      <b>Stack Trace:</b>
      <pre>${details}</pre>
    </div>
  </div>

</body>
</html>
