<h1>Managing user:</h1>
<div id="buttons">
    <a href="jslink" onclick="return (reset_on_click(this));">
        <img id="butreset" src="but-reset.png" alt="Reset" />
    </a>
    <a href="jslink" onclick="return (update_on_click(this));">
        <img id="butupdate" src="but-update.png" alt="Update" />
    </a>
</div>

<ul id="viewtype">
    <li id="viewcaption">View:</li>
    <li>
        <img src="but-selected.png" alt="" />
        Identity Details
    </li>
    <li>
        <img src="but-unselected.png" alt="" />
        <a href="memberof?pkey=${pkey}">Memberships</a>
    </li>
</ul>
<hr />

<div id="backtotop">
    <a href="#viewtype">Back to Top</a>
</div>

