Building Vagrant box images
===========================

This document describes how to build vagrant box images for the
FreeIPA workshop.

Requirements
------------

- Install packer (http://packer.io/)
- Clone the packer-templates repository
  (https://github.com/kaorimatz/packer-templates)


Packer template
---------------

Apply the following changes to the ``fedora-23-x86_64.json`` packer
template:

- Remove the ``scripts/fedora/locale.sh`` provisioner script.
  This script removes locale files from the guest for a small
  size reduction, but this breaks FreeIPA.

- Add the ``scripts/fedora/ipa.sh`` provisioner and copy (or
  symlink) ``ipa.sh`` from *this* repository to ``scripts/fedora``.
  This script installs the FreeIPA packages and creates other files
  required for the workshop.


Building the virtualbox image
-----------------------------

Build the images::

  $BIN_PACKER build fedora-23-x86_64.json

Packer stores images and other data in ``/tmp`` during processing.
If you have limited space in ``/tmp`` set ``TMPDIR`` to point
somewhere else with more space.


Building the QEMU/libvirt image
-------------------------------

Reconfigure the template for QEMU:

- Change the builder ``type`` from ``virtualbox-iso`` to ``qemu``
- Delete the ``guest_os_type`` and ``vboxmanage`` fields
- Remove the ``virtualbox.sh`` provisioner script
- Change the post-processor ``output`` to
  ``fedora-23-x86_64-libvirt.box``.

Build the image::

  $BIN_PACKER build fedora-23-x86_64.json

The output box is a gzip-compressed tarball.  Unfortunately, the VM
image it contains is not sparse and will waste a lot of space (and
time) when Vagrant unpacks and imports the image.  Therefore we
unpack, sparsify and repack the box::

  mkdir box && cd box && tar -xf ../fedora-23-x86_64-libvirt.box
  virt-sparsify --in-place box.img
  tar -czf ../fedora-23-x86-64-libvirt.box * && cd .. && rm -rf box


Uploading boxes to HashiCorp Atlas
----------------------------------

Vagrant by default looks for boxes in a directory called *Atlas*.
Therefore is is good to make images available there, so that people
can easily download them as part of workshop preparation.

1. Log into https://atlas.hashicorp.com and go to the *Vagrant* page
   where boxes can be managed.

2. Create or edit the *freeipa-workshop* box.

3. Create a new *version* of the box (left-hand menu).  Each version
   can include images for multiple *providers*.

4. *Create new provider* for ***virtualbox*** and upload the
   corresponding ``.box`` file.

5. *Create new provider* for ***libvirt*** and upload the
   corresponding ``.box`` file.  *libvirt* may not appear as an
   autocomplete option but type it in anyway.

6. *Release* the new version (this makes it available for
   Vagrant to download).  *Edit* the version, then click *Release
   version*.
