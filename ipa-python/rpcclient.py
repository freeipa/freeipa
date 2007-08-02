#! /usr/bin/python -E
# Authors: Rob Crittenden <rcritten@redhat.com>
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

#!/usr/bin/python

try:
    import krbV
except ImportError:
    pass
import xmlrpclib
import socket
import config

# Some errors to catch
# http://cvs.fedora.redhat.com/viewcvs/ldapserver/ldap/servers/plugins/pam_passthru/README?root=dirsec&rev=1.6&view=auto

def server_url():
    return "http://" + config.config.get_server() + "/ipa"

def setup_server():
    return xmlrpclib.ServerProxy(server_url())
    
def get_user(username):
    """Get a specific user"""
    server = setup_server()
    try:
      result = server.get_user(username)
      myuser = result
    except xmlrpclib.Fault, fault:
        raise xmlrpclib.Fault(fault.faultCode, fault.faultString)
        return None
    except socket.error, (value, msg):
        raise xmlrpclib.Fault(value, msg)
        return None
    
    return myuser
    
def add_user(user):
    """Add a new user"""
    server = setup_server()

    # FIXME: Get the realm from somewhere
    realm = config.config.get_realm()

    # FIXME: This should be dynamic and can include just about anything
    # Let us add in some missing attributes
    if user.get('homeDirectory') is None:
        user['homeDirectory'] ='/home/%s' % user['uid']
    if user.get('gecos') is None:
        user['gecos'] = user['uid']

    # FIXME: This can be removed once the DS plugin is installed
    user['uidNumber'] ='501'

    # FIXME: What is the default group for users?
    user['gidNumber'] ='501'
    user['krbPrincipalName'] = "%s@%s" % (user['uid'], realm)
    user['cn'] = "%s %s" % (user['givenName'], user['sn'])

    try:
        result = server.add_user(user)
        return result
    except xmlrpclib.Fault, fault:
        raise xmlrpclib.Fault(fault.faultCode, fault.faultString)
        return None
    except socket.error, (value, msg):
        raise xmlrpclib.Fault(value, msg)
        return None
    
def get_add_schema():
    """Get the list of attributes we need to ask when adding a new
       user.
    """
    server = setup_server()
    
    # FIXME: Hardcoded and designed for the TurboGears GUI. Do we want
    # this for the CLI as well?
    try:
        result = server.get_add_schema()
    except xmlrpclib.Fault, fault:
        raise xmlrpclib.Fault(fault, fault.faultString)
        return None
    except socket.error, (value, msg):
        raise xmlrpclib.Fault(value, msg)
        return None
  
    return result
