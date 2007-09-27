<div xmlns:py="http://purl.org/kid/ns#">

<?python
from ipagui.helpers import ipahelper
?>
    <div id="search-results-count">
    </div>
    <?python
    criteria_esc = ipahelper.javascript_string_escape(uid)
    ?>
    <script type="text/javascript">
      search_string = "${criteria_esc}";
      results_counter = 0;
    </script>
    <?python search_div_counter = 1 ?>
    <div py:if='(users != None) and (len(users) > 0)'>
        <div py:for="user in users" id="search-${search_div_counter}">
          <?python
          user_dn_esc = ipahelper.javascript_string_escape(user.dn)
          user_uid_esc = ipahelper.javascript_string_escape(user.uid)
          user_cn_esc = ipahelper.javascript_string_escape(user.cn)
          ?>
          <script type="text/javascript">
            if ((added_hash["${user_dn_esc}"] == 1) ||
                (member_hash["${user_dn_esc}"] == 1)) {
              $("search-${search_div_counter}").style.display = 'none';
            } else {
              results_counter = results_counter + 1;
            }
          </script>
          ${user.givenName} ${user.sn} (${user.uid})
          <a href=""
            onclick="adduserHandler(this, '${user_dn_esc}',
                                   '${user_cn_esc} (${user_uid_esc})');
                     return false;"
          >add</a>
          <?python
          search_div_counter = search_div_counter + 1
          ?>
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
