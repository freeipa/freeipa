# Authors: Petr Vobornik <pvoborni@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Plugin index generation script
"""
from __future__ import absolute_import

import logging
import os
from ipaplatform.paths import paths

logger = logging.getLogger(os.path.basename(__file__))


def get_plugin_index():

    if not os.path.isdir(paths.IPA_JS_PLUGINS_DIR):
        raise Exception("Supplied plugin directory path is not a directory")

    dirs = os.listdir(paths.IPA_JS_PLUGINS_DIR)
    index = 'define([],function(){return['
    index += ','.join("'"+x+"'" for x in dirs)
    index += '];});'
    return index.encode('utf-8')

def get_failed():
    return (
        b'define([],function(){return[];});/*error occured: serving default */'
    )

def application(environ, start_response):
    try:
        index = get_plugin_index()
        status = '200 OK'
    except Exception as e:
        logger.error('plugin index generation failed: %s', e)
        status = '200 OK'
        index = get_failed()
    headers = [('Content-type', 'application/javascript'),
               ('Content-Length', str(len(index)))]
    start_response(status, headers)
    return [index]
