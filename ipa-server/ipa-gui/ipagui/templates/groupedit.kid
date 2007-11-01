<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'grouplayout.kid'">
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" py:replace="''"/>
    <title>Edit Group</title>
</head>
<body>
  <div id="details">
          <h1>Edit Group</h1>
<input type="checkbox" id="toggleprotected_checkbox"
          onclick="toggleProtectedFields(this);">
        <span class="small">edit protected fields</span>
      </input>

  ${form.display(action=tg.url('/group/update'), value=group, members=members)}
</div>
</body>
</html>
