<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'delegatelayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Edit Delegation</title>
</head>
<body>

    <h2>Edit Delegation</h2>

    ${form.display(action=tg.url("/delegate/update"), value=delegate,
                   actionname='Edit')}

</body>
</html>
