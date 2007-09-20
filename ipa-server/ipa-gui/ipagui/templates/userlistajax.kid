<div xmlns:py="http://purl.org/kid/ns#">
    <div id="search-results-count">
    </div>
    <script type="text/javascript">
      search_string = "${uid}";
      results_counter = 0;
    </script>
    <div py:if='(users != None) and (len(users) > 0)'>
        <div py:for="user in users" id="search-${user.uid}">
          <script type="text/javascript">
            if ((added_hash["${user.uid}"] == 1) ||
                (member_hash["${user.uid}"] == 1)) {
              $("search-${user.uid}").style.display = 'none';
            } else {
              results_counter = results_counter + 1;
            }
          </script>
          ${user.givenName} ${user.sn} (${user.uid})
          <a href="" 
            onclick="adduserHandler(this, '${user.uid}', '${user.cn}'); return false;"
          >add</a>
        </div>
    </div>
    <script type="text/javascript">
      if (results_counter == 0) {
        var message = "No results found for " + search_string;
      } else {
        var message =  results_counter + " results found:";
      }
      $('search-results-count').appendChild(document.createTextNode(message));
    </script>
    <script py:if="counter &lt; 0">
      $('search-results-count').appendChild(document.createTextNode(
        " (truncated)"));
    </script>
</div>
