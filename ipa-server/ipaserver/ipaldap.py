# Authors: Rich Megginson <richm@redhat.com>
#          Rob Crittenden <rcritten@redhat.com
#
# Copyright (C) 2007  Red Hat
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
import string
import ldap
import cStringIO
import time
import operator
import struct
import ldap.sasl
from ldap.controls import LDAPControl,DecodeControlTuples,EncodeControlTuples
from ldap.ldapobject import SimpleLDAPObject
from ipa import ipaerror, ipautil

# Global variable to define SASL auth
sasl_auth = ldap.sasl.sasl({},'GSSAPI')

class Entry:
    """This class represents an LDAP Entry object.  An LDAP entry consists of a DN
    and a list of attributes.  Each attribute consists of a name and a list of
    values.  In python-ldap, entries are returned as a list of 2-tuples.
    Instance variables:
    dn - string - the string DN of the entry
    data - CIDict - case insensitive dict of the attributes and values"""

    def __init__(self,entrydata):
        """data is the raw data returned from the python-ldap result method, which is
        a search result entry or a reference or None.
        If creating a new empty entry, data is the string DN."""
        if entrydata:
            if isinstance(entrydata,tuple):
                self.dn = entrydata[0]
                self.data = ipautil.CIDict(entrydata[1])
            elif isinstance(entrydata,str) or isinstance(entrydata,unicode):
                self.dn = entrydata
                self.data = ipautil.CIDict()
        else:
            self.dn = ''
            self.data = ipautil.CIDict()

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

class LDIFConn(ldif.LDIFParser):
    def __init__(
        self,
        input_file,
        ignored_attr_types=None,max_entries=0,process_url_schemes=None
    ):
        """
        See LDIFParser.__init__()
        
        Additional Parameters:
        all_records
        List instance for storing parsed records
        """
        self.dndict = {} # maps dn to Entry
        self.dnlist = [] # contains entries in order read
        myfile = input_file
        if isinstance(input_file,str) or isinstance(input_file,unicode):
            myfile = open(input_file, "r")
        ldif.LDIFParser.__init__(self,myfile,ignored_attr_types,max_entries,process_url_schemes)
        self.parse()
        if isinstance(input_file,str) or isinstance(input_file,unicode):
            myfile.close()

    def handle(self,dn,entry):
        """
        Append single record to dictionary of all records.
        """
        if not dn:
            dn = ''
        newentry = Entry((dn, entry))
        self.dndict[IPAdmin.normalizeDN(dn)] = newentry
        self.dnlist.append(newentry)

    def get(self,dn):
        ndn = IPAdmin.normalizeDN(dn)
        return self.dndict.get(ndn, Entry(None))

class IPAdmin(SimpleLDAPObject):
    CFGSUFFIX = "o=NetscapeRoot"
    DEFAULT_USER_ID = "nobody"

    def getDseAttr(self,attrname):
        conffile = self.confdir + '/dse.ldif'
        dseldif = LDIFConn(conffile)
        cnconfig = dseldif.get("cn=config")
        if cnconfig:
            return cnconfig.getValue(attrname)
        return None
    
    def __initPart2(self):
        if self.binddn and len(self.binddn) and not hasattr(self,'sroot'):
            try:
                ent = self.getEntry('cn=config', ldap.SCOPE_BASE, '(objectclass=*)',
                                    [ 'nsslapd-instancedir', 'nsslapd-errorlog',
                                      'nsslapd-certdir', 'nsslapd-schemadir' ])
                self.errlog = ent.getValue('nsslapd-errorlog')
                self.confdir = None
                if self.isLocal:
                    self.confdir = ent.getValue('nsslapd-certdir')
                    if not self.confdir or not os.access(self.confdir + '/dse.ldif', os.R_OK):
                        self.confdir = ent.getValue('nsslapd-schemadir')
                        if self.confdir:
                            self.confdir = os.path.dirname(self.confdir)
                instdir = ent.getValue('nsslapd-instancedir')
                if not instdir:
                    # get instance name from errorlog
                    self.inst = re.match(r'(.*)[\/]slapd-([\w-]+)/errors', self.errlog).group(2)
                    if self.confdir:
                        instdir = self.getDseAttr('nsslapd-instancedir')
                    else:
                        if self.isLocal:
                            print instdir
                            self.sroot, self.inst = re.match(r'(.*)[\/]slapd-([\w-]+)$', instdir).groups()
                            instdir = re.match(r'(.*/slapd-.*)/errors', self.errlog).group(1)
                            #self.sroot, self.inst = re.match(r'(.*)[\/]slapd-([\w-]+)$', instdir).groups()
                ent = self.getEntry('cn=config,cn=ldbm database,cn=plugins,cn=config',
                                    ldap.SCOPE_BASE, '(objectclass=*)',
                                    [ 'nsslapd-directory' ])
                self.dbdir = os.path.dirname(ent.getValue('nsslapd-directory'))
            except (ldap.INSUFFICIENT_ACCESS, ldap.CONNECT_ERROR):
                pass # usually means 
            except ldap.LDAPError, e:
                print "caught exception ", e
                raise

    def __localinit__(self):
        """If a CA certificate is provided then it is assumed that we are
           doing SSL client authentication with proxy auth.

           If a CA certificate is not present then it is assumed that we are
           using a forwarded kerberos ticket for SASL auth. SASL provides
           its own encryption.
        """
        if self.cacert is not None:
            SimpleLDAPObject.__init__(self,'ldaps://%s:%d' % (self.host,self.port))
        else:
            SimpleLDAPObject.__init__(self,'ldap://%s:%d' % (self.host,self.port))

    def __init__(self,host,port=389,cacert=None,bindcert=None,bindkey=None,proxydn=None,debug=None):
        """We just set our instance variables and wrap the methods - the real
           work is done in __localinit__ and __initPart2 - these are separated
           out this way so that we can call them from places other than
           instance creation e.g. when we just need to reconnect, not create a
           new instance"""
        if debug and debug.lower() == "on":
            ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
        if cacert is not None:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,cacert)
            ldap.set_option(ldap.OPT_X_TLS_CERTFILE,bindcert)
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE,bindkey)

        self.__wrapmethods()
        self.port = port
        self.host = host
        self.cacert = cacert
        self.bindcert = bindcert
        self.bindkey = bindkey
        self.proxydn = proxydn
        # see if is local or not
        host1 = IPAdmin.getfqdn(host)
        host2 = IPAdmin.getfqdn()
        self.isLocal = (host1 == host2)
        self.suffixes = {}
        self.__localinit__()

    def __str__(self):
        return self.host + ":" + str(self.port)

    def __get_server_controls__(self):
        """Create the proxy user server control. The control has the form
        0x04 = Octet String
        4|0x80 sets the length of the string length field at 4 bytes
        the struct() gets us the length in bytes of string self.proxydn
        self.proxydn is the proxy dn to send"""

        import sys

        if self.proxydn is not None:
            proxydn = chr(0x04) + chr(4|0x80) + struct.pack('l', socket.htonl(len(self.proxydn))) + self.proxydn;

            # Create the proxy control
            sctrl=[]
            sctrl.append(LDAPControl('2.16.840.1.113730.3.4.18',True,proxydn))
        else:
            sctrl=None

        return sctrl

    def toLDAPURL(self):
        return "ldap://%s:%d/" % (self.host,self.port)

    def set_proxydn(self, proxydn):
        self.proxydn = proxydn

    def set_krbccache(self, krbccache, principal):
        if krbccache is not None:
            os.environ["KRB5CCNAME"] = krbccache
            self.sasl_interactive_bind_s("", sasl_auth)
            self.principal = principal
        self.proxydn = None

    def do_simple_bind(self, binddn="cn=directory manager", bindpw=""):
        self.binddn = binddn
        self.bindpwd = bindpw
        self.simple_bind_s(binddn, bindpw)
        self.__initPart2()

    def getEntry(self,*args):
        """This wraps the search function.  It is common to just get one entry"""

        sctrl = self.__get_server_controls__()

        if sctrl is not None:
            self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)

        try:
            res = self.search(*args)
            type, obj = self.result(res)
        except ldap.NO_SUCH_OBJECT:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND,
                    notfound(args))
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)

        if not obj:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND,
                    notfound(args))
        elif isinstance(obj,Entry):
            return obj
        else: # assume list/tuple
            return obj[0]

    def getList(self,*args):
        """This wraps the search function to find all users."""

        sctrl = self.__get_server_controls__()
        if sctrl is not None:
            self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)

        try:
            res = self.search(*args)
            type, obj = self.result(res)
        except (ldap.ADMINLIMIT_EXCEEDED, ldap.SIZELIMIT_EXCEEDED), e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR,
                    "Too many results returned by search", e)
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)

        if not obj:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND,
                    notfound(args))

        all_users = []
        for s in obj:
            all_users.append(s)

        return all_users

    def getListAsync(self,*args):
        """This version performs an asynchronous search, to allow
           results even if we hit a limit.

           It returns a list: counter followed by the results.
           If the results are truncated, counter will be set to -1.
           """

        sctrl = self.__get_server_controls__()
        if sctrl is not None:
            self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)

        entries = []
        partial = 0

        try:
            msgid = self.search_ext(*args)
            type, result_list = self.result(msgid, 0)
            while result_list:
                for result in result_list:
                    entries.append(result)
                type, result_list = self.result(msgid, 0)
        except (ldap.ADMINLIMIT_EXCEEDED, ldap.SIZELIMIT_EXCEEDED,
                ldap.TIMELIMIT_EXCEEDED), e:
            partial = 1
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)

        if not entries:
            raise ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND,
                    notfound(args))

        if partial == 1:
            counter = -1
        else:
            counter = len(entries)

        return [counter] + entries

    def addEntry(self,*args):
        """This wraps the add function. It assumes that the entry is already
           populated with all of the desired objectclasses and attributes"""

        sctrl = self.__get_server_controls__()

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.add_s(*args)
        except ldap.ALREADY_EXISTS:
            raise ipaerror.gen_exception(ipaerror.LDAP_DUPLICATE)
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)
        return "Success"

    def updateRDN(self, dn, newrdn):
        """Wrap the modrdn function."""

        sctrl = self.__get_server_controls__()

        if dn == newrdn:
            # no need to report an error
            return "Success"

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.modrdn_s(dn, newrdn, delold=1)
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)
        return "Success"

    def updateEntry(self,dn,olduser,newuser):
        """This wraps the mod function. It assumes that the entry is already
           populated with all of the desired objectclasses and attributes"""

        sctrl = self.__get_server_controls__()

        modlist = self.generateModList(olduser, newuser)

        if len(modlist) == 0:
            raise ipaerror.gen_exception(ipaerror.LDAP_EMPTY_MODLIST)

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.modify_s(dn, modlist)
        # this is raised when a 'delete' attribute isn't found.
        # it indicates the previous attribute was removed by another
        # update, making the olduser stale.
        except ldap.NO_SUCH_ATTRIBUTE:
            raise ipaerror.gen_exception(ipaerror.LDAP_MIDAIR_COLLISION)
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)
        return "Success"

    def generateModList(self, old_entry, new_entry):
        """A mod list generator that computes more precise modification lists
           than the python-ldap version.  This version purposely generates no
           REPLACE operations, to deal with multi-user updates more properly."""
        modlist = []

        old_entry = ipautil.CIDict(old_entry)
        new_entry = ipautil.CIDict(new_entry)

        keys = set(map(string.lower, old_entry.keys()))
        keys.update(map(string.lower, new_entry.keys()))

        for key in keys:
            new_values = new_entry.get(key, [])
            if not(isinstance(new_values,list) or isinstance(new_values,tuple)):
                new_values = [new_values]
            new_values = filter(lambda value:value!=None, new_values)
            new_values = set(new_values)

            old_values = old_entry.get(key, [])
            if not(isinstance(old_values,list) or isinstance(old_values,tuple)):
                old_values = [old_values]
            old_values = filter(lambda value:value!=None, old_values)
            old_values = set(old_values)

            adds = list(new_values.difference(old_values))
            removes = list(old_values.difference(new_values))

            if len(removes) > 0:
                modlist.append((ldap.MOD_DELETE, key, removes))
            if len(adds) > 0:
                modlist.append((ldap.MOD_ADD, key, adds))

        return modlist

    def inactivateEntry(self,dn,has_key):
        """Rather than deleting entries we mark them as inactive.
           has_key defines whether the entry already has nsAccountlock
           set so we can determine which type of mod operation to run."""

        sctrl = self.__get_server_controls__()
        modlist=[]

        if has_key == True:
            operation = ldap.MOD_REPLACE
        else:
            operation = ldap.MOD_ADD

        modlist.append((operation, "nsAccountlock", "true"))

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.modify_s(dn, modlist)
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)
        return "Success"

    def deleteEntry(self,*args):
        """This wraps the delete function. Use with caution."""

        sctrl = self.__get_server_controls__()

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.delete_s(*args)
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)
        return "Success"

    def modifyPassword(self,dn,oldpass,newpass):
        """Set the user password using RFC 3062, LDAP Password Modify Extended
           Operation. This ends up calling the IPA password slapi plugin 
           handler so the Kerberos password gets set properly.

           oldpass is not mandatory
        """

        sctrl = self.__get_server_controls__()

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.passwd_s(dn, oldpass, newpass)
        except ldap.LDAPError, e:
            raise ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)
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
        cn = "export" + str(int(time.time()))
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

    def waitForEntry(self, dn, timeout=7200, attr='', quiet=True):
        scope = ldap.SCOPE_BASE
        filter = "(objectclass=*)"
        attrlist = []
        if attr:
            filter = "(%s=*)" % attr
            attrlist.append(attr)
        timeout += int(time.time())

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
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                pass # found entry, but no attr
            except ldap.NO_SUCH_OBJECT:
                pass # no entry yet
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
        elif not entry:
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
            return fqdn[index+1:]
        else:
            return fqdn
    getdomainname = staticmethod(getdomainname)

    def getdefaultsuffix(name=''):
        dm = IPAdmin.getdomainname(name)
        if dm:
            return "dc=" + dm.replace('.', ', dc=')
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


def notfound(args):
    """Return a string suitable for displaying as an error when a
       search returns no results.

       This just returns whatever is after the equals sign"""
    if len(args) > 2:
        filter = args[2]
        try:
            target = re.match(r'\(.*=(.*)\)', filter).group(1)
        except:
            target = filter
        return "%s not found" % str(target)
    else:
        return args[0]
