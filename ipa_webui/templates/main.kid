<?xml version='1.0' encoding='utf-8'?>
<html xmlns:py="http://purl.org/kid/ns#">

<head>
    <title>FreeIPA</title>
</head>

<body>
    <p py:for="name in api.Command">
        <a href="${name}" py:content="name"/>
    </p>
</body>

</html>
