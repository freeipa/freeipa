#! /usr/bin/python -E
# Authors: Rich Megginson <richm@redhat.com>
#          Rob Crittenden <rcritten2redhat.com
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

import sys
import os
import os.path
import popen2
import base64
import urllib
import urllib2
import socket
import ldif
import re
import ldap
import cStringIO
import time
import operator

from ldap.ldapobject import SimpleLDAPObject

class Error(Exception): pass
class InvalidArgumentError(Error):
    def __init__(self,message): self.message = message
    def __repr__(self): return message
class NoSuchEntryError(Error):
    def __init__(self,message): self.message = message
    def __repr__(self): return message

class Entry:
    """This class represents an LDAP Entry object.  An LDAP entry consists of a DN
    and a list of attributes.  Each attribute consists of a name and a list of
    values.  In python-ldap, entries are returned as a list of 2-tuples.
    Instance variables:
    dn - string - the string DN of the entry
    data - cidict - case insensitive dict of the attributes and values"""

    def __init__(self,entrydata):
        """data is the raw data returned from the python-ldap result method, which is
        a search result entry or a reference or None.
        If creating a new empty entry, data is the string DN."""
        if entrydata:
            if isinstance(entrydata,tuple):
                self.dn = entrydata[0]
                self.data = ldap.cidict.cidict(entrydata[1])
            elif isinstance(entrydata,str):
                self.dn = entrydata
                self.data = ldap.cidict.cidict()
        else:
            self.dn = ''
            self.data = ldap.cidict.cidict()

    def __nonzero__(self):
        """This allows us to do tests like if entry: returns false if there is no data,
        true otherwise"""
        return self.data != None and len(self.data) > 0

    def hasAttr(self,name):
        """Return True if this entry has an attribute named name, False otherwise"""
        return self.data and self.data.has_key(name)

    def __getattr__(self,name):
        """If name is the name of an LDAP attribute, return the first value for that
        attribute - equivalent to getValue - this allows the use of
        entry.cn
        instead of
        entry.getValue('cn')
        This also allows us to return None if an attribute is not found rather than
        throwing an exception"""
        return self.getValue(name)

    def getValues(self,name):
        """Get the list (array) of values for the attribute named name"""
        return self.data.get(name)

    def getValue(self,name):
        """Get the first value for the attribute named name"""
        return self.data.get(name,[None])[0]

    def setValue(self,name,*value):
        """Value passed in may be a single value, several values, or a single sequence.
        For example:
           ent.setValue('name', 'value')
           ent.setValue('name', 'value1', 'value2', ..., 'valueN')
           ent.setValue('name', ['value1', 'value2', ..., 'valueN'])
           ent.setValue('name', ('value1', 'value2', ..., 'valueN'))
        Since *value is a tuple, we may have to extract a list or tuple from that
        tuple as in the last two examples above"""
        if isinstance(value[0],list) or isinstance(value[0],tuple):
            self.data[name] = value[0]
        else:
            self.data[name] = value

    setValues = setValue

    def toTupleList(self):
        """Convert the attrs and values to a list of 2-tuples.  The first element
        of the tuple is the attribute name.  The second element is either a
        single value or a list of values."""
        return self.data.items()

    def __str__(self):
        """Convert the Entry to its LDIF representation"""
        return self.__repr__()

    # the ldif class base64 encodes some attrs which I would rather see in raw form - to
    # encode specific attrs as base64, add them to the list below
    ldif.safe_string_re = re.compile('^$')
    base64_attrs = ['nsstate', 'krbprincipalkey', 'krbExtraData']

    def __repr__(self):
        """Convert the Entry to its LDIF representation"""
        sio = cStringIO.StringIO()
        # what's all this then?  the unparse method will currently only accept
        # a list or a dict, not a class derived from them.  self.data is a
        # cidict, so unparse barfs on it.  I've filed a bug against python-ldap,
        # but in the meantime, we have to convert to a plain old dict for printing
        # I also don't want to see wrapping, so set the line width really high (1000)
        newdata = {}
        newdata.update(self.data)
        ldif.LDIFWriter(sio,Entry.base64_attrs,1000).unparse(self.dn,newdata)
        return sio.getvalue()

def wrapper(f,name):
    """This is the method that wraps all of the methods of the superclass.  This seems
    to need to be an unbound method, that's why it's outside of IPAdmin.  Perhaps there
    is some way to do this with the new classmethod or staticmethod of 2.4.
    Basically, we replace every call to a method in SimpleLDAPObject (the superclass
    of IPAdmin) with a call to inner.  The f argument to wrapper is the bound method
    of IPAdmin (which is inherited from the superclass).  Bound means that it will implicitly
    be called with the self argument, it is not in the args list.  name is the name of
    the method to call.  If name is a method that returns entry objects (e.g. result),
    we wrap the data returned by an Entry class.  If name is a method that takes an entry
    argument, we extract the raw data from the entry object to pass in."""
    def inner(*args, **kargs):
        if name == 'result':
            type, data = f(*args, **kargs)
            # data is either a 2-tuple or a list of 2-tuples
            # print data
            if data:
                if isinstance(data,tuple):
                    return type, Entry(data)
                elif isinstance(data,list):
                    return type, [Entry(x) for x in data]
                else:
                    raise TypeError, "unknown data type %s returned by result" % type(data)
            else:
                return type, data
        elif name.startswith('add'):
            # the first arg is self
            # the second and third arg are the dn and the data to send
            # We need to convert the Entry into the format used by
            # python-ldap
            ent = args[0]
            if isinstance(ent,Entry):
                return f(ent.dn, ent.toTupleList(), *args[2:])
            else:
                return f(*args, **kargs)
        else:
            return f(*args, **kargs)
    return inner

class IPAdmin(SimpleLDAPObject):
    CFGSUFFIX = "o=NetscapeRoot"
    DEFAULT_USER_ID = "nobody"
    
    def __initPart2(self):
        if self.binddn and len(self.binddn) and not hasattr(self,'sroot'):
            try:
                ent = self.getEntry('cn=config', ldap.SCOPE_BASE, '(objectclass=*)',
                                    [ 'nsslapd-instancedir', 'nsslapd-errorlog' ])
                instdir = ent.getValue('nsslapd-instancedir')
                self.sroot, self.inst = re.match(r'(.*)[\/]slapd-(\w)$', instdir).groups()
                self.errlog = ent.getValue('nsslapd-errorlog')
            except (ldap.INSUFFICIENT_ACCESS, ldap.CONNECT_ERROR, NoSuchEntryError):
                pass # usually means 
#                print "ignored exception"
            except ldap.LDAPError, e:
                print "caught exception ", e
                raise

    def __localinit__(self):
        SimpleLDAPObject.__init__(self,'ldap://%s:%d' % (self.host,self.port))
        # see if binddn is a dn or a uid that we need to lookup
        if self.binddn and not IPAdmin.is_a_dn(self.binddn):
            self.simple_bind("","") # anon
            ent = self.getEntry(IPAdmin.CFGSUFFIX, ldap.SCOPE_SUBTREE,
                                "(uid=%s)" % self.binddn,
                                ['uid'])
            if ent:
                self.binddn = ent.dn
            else:
                print "Error: could not find %s under %s" % (self.binddn, IPAdmin.CFGSUFFIX)
        self.simple_bind(self.binddn,self.bindpw)
#        self.__initPart2()
                
    def __init__(self,host,port,binddn,bindpw):
        """We just set our instance variables and wrap the methods - the real work is
        done in __localinit__ and __initPart2 - these are separated out this way so
        that we can call them from places other than instance creation e.g. when
        using the start command, we just need to reconnect, not create a new instance"""
        self.__wrapmethods()
        self.port = port or 389
        self.sslport = 0
        self.host = host
        self.binddn = binddn
        self.bindpw = bindpw
        # see if is local or not
        host1 = IPAdmin.getfqdn(host)
        host2 = IPAdmin.getfqdn()
        self.isLocal = (host1 == host2)
        self.suffixes = {}
        self.__localinit__()

    def __str__(self):
        return self.host  ":"  str(self.port)

    def toLDAPURL(self):
        return "ldap://%s:%d/" % (self.host,self.port)

    def getEntry(self,*args):
        """This wraps the search function.  It is common to just get one entry"""
        res = self.search(*args)
        type, obj = self.result(res)
        if not obj:
            raise NoSuchEntryError("no such entry for "  str(args))
        elif isinstance(obj,Entry):
            return obj
        else: # assume list/tuple
            return obj[0]

    def addEntry(self,*args):
        """This wraps the add function. It assumes that the entry is already
           populated with all of the desired objectclasses and attributes"""
        try:
            self.add_s(*args)
        except ldap.ALREADY_EXISTS:
            raise ldap.ALREADY_EXISTS
        except ldap.LDAPError, e:
            raise e
        return "Success"

    def __wrapmethods(self):
        """This wraps all methods of SimpleLDAPObject, so that we can intercept
        the methods that deal with entries.  Instead of using a raw list of tuples
        of lists of hashes of arrays as the entry object, we want to wrap entries
        in an Entry class that provides some useful methods"""
        for name in dir(self.__class__.__bases__[0]):
            attr = getattr(self, name)
            if callable(attr):
                setattr(self, name, wrapper(attr, name))

    def exportLDIF(self, file, suffix, forrepl=False, verbose=False):
        cn = "export"  str(int(time.time()))
        dn = "cn=%s, cn=export, cn=tasks, cn=config" % cn
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('nsFilename', file)
        entry.setValues('nsIncludeSuffix', suffix)
        if forrepl:
            entry.setValues('nsExportReplica', 'true')

        rc = self.startTaskAndWait(entry, verbose)

        if rc:
            if verbose:
                print "Error: export task %s for file %s exited with %d" % (cn,file,rc)
        else:
            if verbose:
                print "Export task %s for file %s completed successfully" % (cn,file)
        return rc

    def waitForEntry(self, dn, timeout=7200, attr='', quiet=False):
        scope = ldap.SCOPE_BASE
        filter = "(objectclass=*)"
        attrlist = []
        if attr:
            filter = "(%s=*)" % attr
            attrlist.append(attr)
        timeout = int(time.time())

        if isinstance(dn,Entry):
            dn = dn.dn

        # wait for entry and/or attr to show up
        if not quiet:
            sys.stdout.write("Waiting for %s %s:%s " % (self,dn,attr))
            sys.stdout.flush()
        entry = None
        while not entry and int(time.time()) < timeout:
            try:
                entry = self.getEntry(dn, scope, filter, attrlist)
            except NoSuchEntryError: pass # found entry, but no attr
            except ldap.NO_SUCH_OBJECT: pass # no entry yet
            except ldap.LDAPError, e: # badness
                print "\nError reading entry", dn, e
                break
            if not entry:
                if not quiet:
                    sys.stdout.write(".")
                    sys.stdout.flush()
                time.sleep(1)

        if not entry and int(time.time()) > timeout:
            print "\nwaitForEntry timeout for %s for %s" % (self,dn)
        elif entry and not quiet:
            print "\nThe waited for entry is:", entry
        else:
            print "\nError: could not read entry %s from %s" % (dn,self)

        return entry

    def addSchema(self, attr, val):
        dn = "cn=schema"
        self.modify_s(dn, [(ldap.MOD_ADD, attr, val)])

    def addAttr(self, *args):
        return self.addSchema('attributeTypes', args)

    def addObjClass(self, *args):
        return self.addSchema('objectClasses', args)

    ###########################
    # Static methods start here
    ###########################
    def normalizeDN(dn):
        # not great, but will do until we use a newer version of python-ldap
        # that has DN utilities
        ary = ldap.explode_dn(dn.lower())
        return ",".join(ary)
    normalizeDN = staticmethod(normalizeDN)

    def getfqdn(name=''):
        return socket.getfqdn(name)
    getfqdn = staticmethod(getfqdn)

    def getdomainname(name=''):
        fqdn = IPAdmin.getfqdn(name)
        index = fqdn.find('.')
        if index >= 0:
            return fqdn[index1:]
        else:
            return fqdn
    getdomainname = staticmethod(getdomainname)

    def getdefaultsuffix(name=''):
        dm = IPAdmin.getdomainname(name)
        if dm:
            return "dc="  dm.replace('.', ', dc=')
        else:
            return 'dc=localdomain'
    getdefaultsuffix = staticmethod(getdefaultsuffix)

    def getnewhost(args):
        """One of the arguments to createInstance is newhost.  If this is specified, we need
        to convert it to the fqdn.  If not given, we need to figure out what the fqdn of the
        local host is.  This method sets newhost in args to the appropriate value and
        returns True if newhost is the localhost, False otherwise"""
        isLocal = False
        if args.has_key('newhost'):
            args['newhost'] = IPAdmin.getfqdn(args['newhost'])
            myhost = IPAdmin.getfqdn()
            if myhost == args['newhost']:
                isLocal = True
            elif args['newhost'] == 'localhost' or \
                     args['newhost'] == 'localhost.localdomain':
                isLocal = True
        else:
            isLocal = True
            args['newhost'] = IPAdmin.getfqdn()
        return isLocal
    getnewhost = staticmethod(getnewhost)

    def is_a_dn(dn):
        """Returns True if the given string is a DN, False otherwise."""
        return (dn.find("=") > 0)
    is_a_dn = staticmethod(is_a_dn)
