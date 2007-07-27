#! /usr/bin/python -E
# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

SHARE_DIR = "/usr/share/ipa/"

import string
import tempfile
import logging
import subprocess

def realm_to_suffix(realm_name):
    s = realm_name.split(".")
    terms = ["dc=" + x.lower() for x in s]
    return ",".join(terms)


def template_str(txt, vars):
    return string.Template(txt).substitute(vars)

def template_file(infilename, vars):
    txt = open(infilename).read()
    return template_str(txt, vars)

def write_tmp_file(txt):
    fd = tempfile.NamedTemporaryFile()
    fd.write(txt)
    fd.flush()

    return fd

def run(args, stdin=None):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if stdin:
        stdout,stderr = p.communicate(stdin)
    else:
        stdout,stderr = p.communicate()
    logging.info(stdout)
    logging.info(stderr)

    if p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, args[0])
