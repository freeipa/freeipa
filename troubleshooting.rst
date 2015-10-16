DNS / hosts file issues
=======================

Flush cache
-----------

Note: some resolvers cache NX.

Max OS X::

  dscacheutil -flushcache

Windows::

  ipconfig /flush  -- or is it /flushdns ?

