Building Vagrant box images
===========================

This document describes how to build vagrant box images for the
FreeIPA workshop.

Requirements
------------

- Install packer (http://packer.io/)
- Install Vagrant, libvirt and VirtualBox
- Clone the Fedora kickstarts repo (https://pagure.io/fedora-kickstarts)


Packer template
---------------

Packer template ``packer-template-fedora.json`` requires Fedora 34 kickstart file
used by Fedora to build vagrant images:

- Clone the repo and checkout latest Fedora release branch::

  $ git clone https://pagure.io/fedora-kickstarts.git
  $ cd fedora-kickstarts
  $ git checkout f34

- Install ``pykickstart`` package which provides ``ksflatten`` tool::

  $ sudo dnf install pykickstart

- Generate the ``anaconda-ks.cfg`` file needed by flattening vagrant kickstart files
  and putting it onto the same folder as the packer template file::

  $ ksflatten -c $FEDORA_KICKSTARTS_REPO/fedora-cloud-base-vagrant.ks > $FREEIPA_REPO/doc/workshop/anaconda-ks.cfg


Building the vagrant images
-----------------------------

Build the images::

  $ cd $FREEIPA_REPO/doc/workshop
  $ BIN_PACKER build packer-template-fedora.json


Uploading boxes to Vagrant Cloud
----------------------------------

Vagrant by default looks for boxes in a directory called *Vagrant Cloud*.
Therefore is is good to make images available there, so that people
can easily download them as part of workshop preparation.

1. Log into https://app.vagrantup.com/.

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
