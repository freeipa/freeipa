<div xmlns:py="http://purl.org/kid/ns#">

<?python
from ipagui.helpers import ipahelper
?>
  <div py:if='(users != None) and (len(users) > 0)'>
    <div id="search-results-count">
      ${len(users)} results returned:
      <span py:if="counter &lt; 0">
        (truncated)
      </span>
    </div>

    <div py:for="user in users">
      <?python
      user_name = "%s %s" % (user.getValue('givenName', ''),
                             user.getValue('sn', ''))
      user_descr = "(%s)" % user.uid

      user_dn_esc = ipahelper.javascript_string_escape(user.dn)
      user_name_esc = ipahelper.javascript_string_escape(user_name)
      user_descr_esc = ipahelper.javascript_string_escape(user_descr)
      which_select_esc = ipahelper.javascript_string_escape(which_select)
      ?>

      ${user_name} ${user_descr}
      <a href=""
        onclick="doSelect('${which_select_esc}', '${user_dn_esc}', '${user_name_esc}');
                return false;"
      >select</a>
    </div>
  </div>
  <div py:if='(users != None) and (len(users) == 0)'>
    No results found for "${criteria}"
  </div>
</div>
