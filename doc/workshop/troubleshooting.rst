Troubleshooting
===============

Local webserver
---------------

Drop firewall:

.. code-block:: console

  $ sudo firewall-cmd --add-service=http


DNS / hosts file issues
-----------------------

Flush cache
^^^^^^^^^^^

Note: some resolvers cache NX.

Max OS X:

.. code-block:: console

  $ dscacheutil -flushcache

Windows:

.. code-block:: console

  $ ipconfig /flush  -- or is it /flushdns ?


Virtual network
---------------

If ``Vagrant::Errors::NetworkCollision`` occurs, try deleting host
network device, e.g.:

.. code-block:: console

  $ sudo ifconfig virbr2 down


*vagrant-libvirt* might have problems if the ``default`` network is
up:

.. code-block:: console

  $ sudo virsh net-destroy default


Vagrant
-------

If :command:`vagrant up` fails to SSH into VM, delete
:file:`~/.vagrant.d/insecure_private_key`.  See
https://stackoverflow.com/questions/28284112/.


mod_lookup_identity
-------------------

To flush cache:

.. code-block:: console

  $ sudo sss_cache -E
