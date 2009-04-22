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

from ipalib import api
import httplib
import xml.dom.minidom

def get_ca_certchain():
    """
    Retrieve the CA Certificate chain from the configured Dogtag server.
    """
    chain = None
    conn = httplib.HTTPConnection(api.env.ca_host, 9180)
    conn.request("GET", "/ca/ee/ca/getCertChain")
    res = conn.getresponse()
    if res.status == 200:
        data = res.read()

        doc = xml.dom.minidom.parseString(data)
        item_node = doc.getElementsByTagName("ChainBase64")
        chain = item_node[0].childNodes[0].data
        doc.unlink()
        conn.close()

    return chain
