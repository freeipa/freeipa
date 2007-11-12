<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'policylayout.kid'">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
<title>Manage Policy</title>
</head>
<body>

<?python
from ipagui.helpers import ipahelper
?>

  <script type="text/javascript" charset="utf-8" src="${tg.url('/static/javascript/tablekit.js')}"></script>

  <h1>Manage Policy</h1>

  <table>
    <tbody>
      <tr>
          <td>
            <a href="${tg.url('/ipapolicy/show')}"
              >IPA Policy</a>
          </td>
      </tr>
    </tbody>
  </table>


</body>
</html>
