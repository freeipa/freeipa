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
