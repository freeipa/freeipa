<?xml version='1.0' encoding='utf-8'?>
<html xmlns:py="http://purl.org/kid/ns#">

<head>
    <title>Hello</title>
</head>

<body>
    <table>
        <tr py:for="param in command.params()">
            <td py:content="param.name"/>
        </tr>
    </table>
</body>

</html>
