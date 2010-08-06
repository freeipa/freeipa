<script type="text/javascript">

$(document).ready( initializeUserGroupEnrollments);
    
</script>


<h1>Enroll in Groups</h1>

<form> 
  <div style="border-width:1px">
    <div >
      <input type="text"/>
      <input id="query" type="button" value="Find Groups"/>

      <span style="float:right"> 
	<input id="cancelEnrollGroups" type="button" value="Cancel"/>
	<input id="enrollGroups" type="button" value="Enroll"/>
      </span>

    </div>
    <div  id="results"  style="border: 2px solid rgb(0, 0, 0); position:relative;  height:200px;" >
      <div style="float:left;">
	<div>Groups</div>
	<select id="grouplist" width="150px" size="10" multiple="true" >
	</select>
      </div>
      <div style="float:left;">
	<p><input id="removeFromList" type="button" value="&lt;&lt;"/> </p>
	<p><input id="addToList" type="button" value="&gt;&gt;"/></p>
      </div>
      <div style="float:left;">
	<div>Prospective Enrollments</div>
	<select id="enrollments" width="150px"  size="10" multiple="true" >
	</select>
      </div>
    </div>
    <hr/>
    <div>Message Area</div>
    <hr/>
    <div>
      <span style="float:left">
	<p>*Enter Group Names and Press Groups</p>
	<p>*More stuff</p>
	<p>*More stuff</p>
      </span>
    </div>
  </div>
</form>
