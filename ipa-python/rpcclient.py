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

import xmlrpclib
import socket
import config
from krbtransport import KerbTransport
from kerberos import GSSError
import os
import base64
import user
import ipa

# Some errors to catch
# http://cvs.fedora.redhat.com/viewcvs/ldapserver/ldap/servers/plugins/pam_passthru/README?root=dirsec&rev=1.6&view=auto

class RPCClient:

    def __init__(self):
        ipa.config.init_config()
    
    def server_url(self):
        return "http://" + config.config.get_server() + "/ipa"
    
    def setup_server(self):
        return xmlrpclib.ServerProxy(self.server_url(), KerbTransport())
    
    def convert_entry(self,ent):
        # Convert into a dict. We need to handle multi-valued attributes as well
        # so we'll convert those into lists.
        user={}
        for (k) in ent:
            k = k.lower()
            if user.get(k) is not None:
                if isinstance(user[k],list):
                    user[k].append(ent[k].strip())
                else:
                    first = user[k]
                    user[k] = ()
                    user[k].append(first)
                    user[k].append(ent[k].strip())
            else:
                 user[k] = ent[k]
    
        return user
        
    def get_user(self,username):
        """Get a specific user"""
        server = self.setup_server()
        try:
            result = server.get_user(username)
        except xmlrpclib.Fault, fault:
            raise xmlrpclib.Fault(fault.faultCode, fault.faultString)
        except socket.error, (value, msg):
            raise xmlrpclib.Fault(value, msg)

        return result
        
        
    def add_user(self,user):
        """Add a new user"""
        server = self.setup_server()
    
        try:
            result = server.add_user(user)
        except xmlrpclib.Fault, fault:
            raise xmlrpclib.Fault(fault.faultCode, fault.faultString)
        except socket.error, (value, msg):
            raise xmlrpclib.Fault(value, msg)

        return result
        
    def get_add_schema(self):
        """Get the list of attributes we need to ask when adding a new
           user.
        """
        server = self.setup_server()
        
        # FIXME: Hardcoded and designed for the TurboGears GUI. Do we want
        # this for the CLI as well?
        try:
            result = server.get_add_schema()
        except xmlrpclib.Fault, fault:
            raise xmlrpclib.Fault(fault.faultCode, fault.faultString)
        except socket.error, (value, msg):
            raise xmlrpclib.Fault(value, msg)
      
        return result
    
    def get_all_users (self):
        """Return a list containing a User object for each existing user."""
    
        server = self.setup_server()
        try:
            result = server.get_all_users()
        except xmlrpclib.Fault, fault:
            raise xmlrpclib.Fault(fault.faultCode, fault.faultString)
        except socket.error, (value, msg):
            raise xmlrpclib.Fault(value, msg)
    
        return result
