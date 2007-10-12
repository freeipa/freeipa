<div xmlns:py="http://purl.org/kid/ns#">

<?python
from ipagui.helpers import ipahelper
?>
  <div py:if='(groups != None) and (len(groups) > 0)'>
    <div id="search-results-count">
      ${len(groups)} results returned:
      <span py:if="counter &lt; 0">
        (truncated)
      </span>
    </div>

    <div py:for="group in groups">
      <?python
      group_dn_esc = ipahelper.javascript_string_escape(group.dn)
      group_cn_esc = ipahelper.javascript_string_escape(group.cn)
      which_group_esc = ipahelper.javascript_string_escape(which_group)
      ?>

      ${group.cn}
      <a href=""
        onclick="selectGroup('${which_group_esc}', '${group_dn_esc}', '${group_cn_esc}');
                return false;"
      >select</a>
    </div>
  </div>
  <div py:if='(groups != None) and (len(groups) == 0)'>
    No results found for "${criteria}"
  </div>
</div>
