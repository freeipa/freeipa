#!/usr/bin/python

# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Python-level packaging using distutils.
"""

from distutils.core import setup

setup(
    name='freeipa',
    version='1.99.0',
    license='GPLv2+',
    url='http://freeipa.org/',
    packages=[
        'ipalib',
        'ipalib.plugins',
        'ipaserver',
        'ipaserver.plugins',
        'ipawebui',
        'ipawebui.templates',
    ],
    package_data={
        'ipawebui.templates': ['*.kid'],
        'ipawebui': ['static/*'],
    },
    scripts=['ipa'],
)
