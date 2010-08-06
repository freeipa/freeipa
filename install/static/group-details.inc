<script type="text/javascript">
  $(document).ready(function(){     
  load_object($('body'),'group');
  });
</script>
<h1>Managing group:</h1>
<div id="buttons">
  <a href="dummy"><img id="butreset" src="but-reset.png" alt="Reset" /></a>
  <a href="dummy"><img id="butupdate" src="but-update.png" alt="Update" /></a>
</div>
<ul id="viewtype">
  <li id="viewcaption">View:</li>
  <li>
    <img src="but-selected.png" alt="" />
    Personal Details
  </li>
  <li>
    <img src="but-unselected.png" alt="" />
    <a href="memberof?pkey=${pkey}">Memberships</a>
  </li>
</ul>
<hr />

<h2 onclick="h2_on_click(this)">&#8722; Group Details</h2>
<dl id="identity" class="entryattrs">
  <dt title="cn">Group Name:</dt>
  <dt title="description">Description:</dt>
  <dt title="gidnumber">GID</dt>
</dl>
<hr />


