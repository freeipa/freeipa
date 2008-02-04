<!-- 
 Copyright (C) 2007  Red Hat
 see file 'COPYING' for use and warranty information

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 only

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
-->
<div xmlns:py="http://purl.org/kid/ns#">

<?python
from ipagui.helpers import ipahelper
#
# This file is used to render the results from an AJAX search onto a page.
# It has many expectations of the page being rendered into:
#   - Source page must have included dynamicedit.js and followed all of its
#     requirements
#
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
                ent_name = "%s %s" % (entity.getValue('givenName', ''),
                                      entity.getValue('sn', ''))
                ent_descr = "(%s)" % entity.uid
                ent_type = "user"
            else:
                ent_name = entity.cn
                ent_descr = "[group]"
                ent_type = "group"
            ent_name_esc = ipahelper.javascript_string_escape(ent_name)
            ent_descr_esc = ipahelper.javascript_string_escape(ent_descr)
            ent_type_esc = ipahelper.javascript_string_escape(ent_type)
            ?>
            <span id="search-info-${search_div_counter}"></span>
            <script type="text/javascript">
              if ((added_hash["${ent_dn_esc}"] == 1) ||
                  (member_hash["${ent_dn_esc}"] == 1)) {
                $("search-${search_div_counter}").style.display = 'none';
              } else {
                results_counter = results_counter + 1;
              }

              renderMemberInfo($('search-info-${search_div_counter}'),
                           new MemberDisplayInfo('${ent_name_esc}',
                                                 '${ent_descr_esc}',
                                                 '${ent_type_esc}'));
            </script>
            <a href=""
              onclick="addmemberHandler(this, '${ent_dn_esc}',
                           new MemberDisplayInfo('${ent_name_esc}',
                                                 '${ent_descr_esc}',
                                                 '${ent_type_esc}'));
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
        var message = "No results found for '" + search_string + "'";
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
