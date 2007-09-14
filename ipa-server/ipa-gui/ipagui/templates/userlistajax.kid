<div xmlns:py="http://purl.org/kid/ns#">
    <div py:if='(users != None) and (len(users) > 0)'>
        <div>${len(users)} results returned:</div>
        <div py:for="user in users">
          ${user.givenName} ${user.sn} (${user.uid})
          <a href="" 
            onclick="adduserHandler(this, '${user.uid}', '${user.cn}'); return false;"
          >add</a>
        </div>
    </div>
    <div py:if='(users != None) and (len(users) == 0)'>
        No results found for "${uid}"
    </div>
</div>
