<div xmlns:py="http://purl.org/kid/ns#">

<?python
from ipagui.helpers import ipahelper
?>
    <div id="search-results-count">
    </div>
    <?python
    criteria_esc = ipahelper.javascript_string_escape(criteria)
    ?>
    <script type="text/javascript">
      search_string = "${criteria_esc}";
      results_counter = 0;
    </script>
    <?python search_div_counter = 1 ?>
    <div py:for="entities in (users, groups)">
      <div py:if='(entities != None) and (len(entities) > 0)'>
          <div py:for="entity in entities" id="search-${search_div_counter}">
            <?python
            ent_dn_esc = ipahelper.javascript_string_escape(entity.dn)
            ent_uid = entity.uid
            if ent_uid:
                ent_cn = "%s %s (%s)" % (entity.givenName, entity.sn, entity.uid)
            else:
                ent_cn = "%s [group]" % entity.cn
            ent_cn_esc = ipahelper.javascript_string_escape(ent_cn)
            ?>
            <script type="text/javascript">
              if ((added_hash["${ent_dn_esc}"] == 1) ||
                  (member_hash["${ent_dn_esc}"] == 1)) {
                $("search-${search_div_counter}").style.display = 'none';
              } else {
                results_counter = results_counter + 1;
              }
            </script>
            ${ent_cn}
            <a href=""
              onclick="addmemberHandler(this, '${ent_dn_esc}', '${ent_cn_esc}');
                      return false;"
            >add</a>
            <?python
            search_div_counter = search_div_counter + 1
            ?>
          </div>
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
