# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

from ipalib import api, errors
import httplib
import xml.dom.minidom

def get_ca_certchain(ca_host=None):
    """
    Retrieve the CA Certificate chain from the configured Dogtag server.
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    chain = None
    conn = httplib.HTTPConnection(ca_host, 9180)
    conn.request("GET", "/ca/ee/ca/getCertChain")
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()
        conn.close()
        try:
            doc = xml.dom.minidom.parseString(data)
            try:
                item_node = doc.getElementsByTagName("ChainBase64")
                chain = item_node[0].childNodes[0].data
            except IndexError:
                try:
                    item_node = doc.getElementsByTagName("Error")
                    reason = item_node[0].childNodes[0].data
                    raise errors.RemoteRetrieveError(reason=reason)
                except Exception, e:
                    raise errors.RemoteRetrieveError(reason="Retrieving CA cert chain failed: %s" % str(e))
        finally:
            doc.unlink()

    return chain
