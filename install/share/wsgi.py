# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
WSGI appliction for IPA server.
"""
import sys

# Some dependencies like Dogtag's pki.client library and custodia use
# python-requsts to make HTTPS connection. python-requests prefers
# PyOpenSSL over Python's stdlib ssl module. PyOpenSSL is build on top
# of python-cryptography which trigger a execmem SELinux violation
# in the context of Apache HTTPD (httpd_execmem).
# When requests is imported, it always tries to import pyopenssl glue
# code from urllib3's contrib directory. The import of PyOpenSSL is
# enough to trigger the SELinux denial.
# Block any import of PyOpenSSL's SSL module by raising an ImportError
sys.modules['OpenSSL.SSL'] = None

from ipaplatform.paths import paths
from ipalib import api
from ipalib.config import Env
from ipalib.constants import DEFAULT_CONFIG

# Determine what debug level is configured. We can only do this
# by reading in the configuration file(s). The server always reads
# default.conf and will also read in `context'.conf.
env = Env()
env._bootstrap(context='server', log=None, confdir=paths.ETC_IPA)
env._finalize_core(**dict(DEFAULT_CONFIG))

# Initialize the API with the proper debug level
api.bootstrap(context='server', confdir=paths.ETC_IPA,
              debug=env.debug, log=None)
try:
    api.finalize()
except Exception as e:
    api.log.error('Failed to start IPA: %s' % e)
else:
    api.log.info('*** PROCESS START ***')

    # This is the WSGI callable:
    def application(environ, start_response):
        if not environ['wsgi.multithread']:
            return api.Backend.wsgi_dispatch(environ, start_response)
        else:
            api.log.error("IPA does not work with the threaded MPM, use the pre-fork MPM")
