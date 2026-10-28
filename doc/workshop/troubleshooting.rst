Troubleshooting
===============

Local webserver
---------------

Drop firewall::

  sudo firewall-cmd --add-service=http


DNS / hosts file issues
-----------------------

Flush cache
^^^^^^^^^^^

Note: some resolvers cache NX.

Max OS X::

  dscacheutil -flushcache

Windows::

  ipconfig /flush  -- or is it /flushdns ?


Virtual network
---------------

If ``Vagrant::Errors::NetworkCollision`` occurs, try deleting host
network device, e.g.::

  sudo ifconfig virbr2 down


*vagrant-libvirt* might have problems if the ``default`` network is
up::

  sudo virsh net-destroy default


Vagrant
-------

If ``vagrant up`` fails to SSH into VM, delete
``~/.vagrant.d/insecure_private_key``.  See
https://stackoverflow.com/questions/28284112/.


mod_lookup_identity
-------------------

To flush cache::

  $ sudo sss_cache -E
