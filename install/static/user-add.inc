<script type="text/javascript">
  $(document).ready(function(){     
  $("#addEdit").click(addEditUser);
  $("#addAnother").click(addAnotherUser);

  /*this is a placeholder. We will need to I18N */
  $("#content h1").text( "Add a User."); 
  });
</script>
<div id="buttons">
  <span>Add and :</span>
  <input id="addEdit" type='button' value="Edit" />
  <span>|</span>
  <input id="addAnother" type='button' value="Add Another" />
</div>

<h1></h1>
<dl class="entryattrs">
  <dt title="login">login</dt>
  <dd><input id='login' type='text' value=''/></dd>
  <dt	title ="firstname">First  Name</dt>
  <dd><input id='firstname' type='text' value=''/></dd>
  <dt title="lastname">Last Name</dt>
  <dd><input id='lastname' type='text' value=''/></dd>
</dl>
