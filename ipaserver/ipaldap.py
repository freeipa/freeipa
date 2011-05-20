# Authors: Rich Megginson <richm@redhat.com>
#          Rob Crittenden <rcritten@redhat.com
#
# Copyright (C) 2007  Red Hat
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

import sys
import os
import os.path
import socket
import ldif
import re
import string
import ldap
import cStringIO
import time
import struct
import ldap.sasl
from ldap.controls import LDAPControl,DecodeControlTuples,EncodeControlTuples
from ldap.ldapobject import SimpleLDAPObject
from ipaserver import ipautil
from ipalib import errors

# Global variable to define SASL auth
SASL_AUTH = ldap.sasl.sasl({},'GSSAPI')

class Entry:
    """
    This class represents an LDAP Entry object.  An LDAP entry consists of
    a DN and a list of attributes.  Each attribute consists of a name and
    a list of values.  In python-ldap, entries are returned as a list of
    2-tuples.  Instance variables:

        * dn - string - the string DN of the entry
        * data - CIDict - case insensitive dict of the attributes and values
    """
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

    def setValue(self, name, *value):
        """
        Set a value on this entry.

        The value passed in may be a single value, several values, or a
        single sequence.  For example:

           * ent.setValue('name', 'value')
           * ent.setValue('name', 'value1', 'value2', ..., 'valueN')
           * ent.setValue('name', ['value1', 'value2', ..., 'valueN'])
           * ent.setValue('name', ('value1', 'value2', ..., 'valueN'))

        Since value is a tuple, we may have to extract a list or tuple from
        that tuple as in the last two examples above.
        """
        if isinstance(value[0],list) or isinstance(value[0],tuple):
            self.data[name] = value[0]
        else:
            self.data[name] = value

    setValues = setValue

    def delAttr(self, name):
        """
        Entirely remove an attribute of this entry.
        """
        if self.hasAttr(name):
            del self.data[name]

    def toTupleList(self):
        """Convert the attrs and values to a list of 2-tuples.  The first element
        of the tuple is the attribute name.  The second element is either a
        single value or a list of values."""
        r = []
        for i in self.data.iteritems():
            n = ipautil.utf8_encode_values(i[1])
            r.append((i[0], n))
        return r

    def toDict(self):
        """Convert the attrs and values to a dict. The dict is keyed on the
        attribute name.  The value is either single value or a list of values."""
        result = ipautil.CIDict(self.data)
        for i in result.keys():
            result[i] = ipautil.utf8_encode_values(result[i])
        result['dn'] = self.dn
        return result

    def __str__(self):
        """Convert the Entry to its LDIF representation"""
        return self.__repr__()

    # the ldif class base64 encodes some attrs which I would rather see in
    # raw form - to encode specific attrs as base64, add them to the list below
    ldif.safe_string_re = re.compile('^$')
    base64_attrs = ['nsstate', 'krbprincipalkey', 'krbExtraData']

    def __repr__(self):
        """Convert the Entry to its LDIF representation"""
        sio = cStringIO.StringIO()
        # what's all this then?  the unparse method will currently only accept
        # a list or a dict, not a class derived from them.  self.data is a
        # cidict, so unparse barfs on it.  I've filed a bug against python-ldap,
        # but in the meantime, we have to convert to a plain old dict for
        # printing
        # I also don't want to see wrapping, so set the line width really high
        # (1000)
        newdata = {}
        newdata.update(self.data)
        ldif.LDIFWriter(sio,Entry.base64_attrs,1000).unparse(self.dn,newdata)
        return sio.getvalue()

def wrapper(f,name):
    """This is the method that wraps all of the methods of the superclass.
       This seems to need to be an unbound method, that's why it's outside
       of IPAdmin.  Perhaps there is some way to do this with the new
       classmethod or staticmethod of 2.4. Basically, we replace every call
       to a method in SimpleLDAPObject (the superclass of IPAdmin) with a
       call to inner.  The f argument to wrapper is the bound method of
       IPAdmin (which is inherited from the superclass).  Bound means that it
       will implicitly be called with the self argument, it is not in the
       args list.  name is the name of the method to call.  If name is a
       method that returns entry objects (e.g. result), we wrap the data
       returned by an Entry class.  If name is a method that takes an entry
       argument, we extract the raw data from the entry object to pass in.
    """
    def inner(*args, **kargs):
        if name == 'result':
            objtype, data = f(*args, **kargs)
            # data is either a 2-tuple or a list of 2-tuples
            # print data
            if data:
                if isinstance(data,tuple):
                    return objtype, Entry(data)
                elif isinstance(data,list):
                    return objtype, [Entry(x) for x in data]
                else:
                    raise TypeError, "unknown data type %s returned by result" % type(data)
            else:
                return objtype, data
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

    def __localinit(self):
        """If a CA certificate is provided then it is assumed that we are
           doing SSL client authentication with proxy auth.

           If a CA certificate is not present then it is assumed that we are
           using a forwarded kerberos ticket for SASL auth. SASL provides
           its own encryption.
        """
        if self.cacert is not None:
            SimpleLDAPObject.__init__(self,'ldaps://%s:%d' % (self.host,self.port))
        else:
            if self.ldapi:
                SimpleLDAPObject.__init__(self,'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % "-".join(self.realm.split(".")))
            else:
                SimpleLDAPObject.__init__(self,'ldap://%s:%d' % (self.host,self.port))

    def __init__(self,host='',port=389,cacert=None,bindcert=None,bindkey=None,proxydn=None,debug=None,ldapi=False,realm=None):
        """We just set our instance variables and wrap the methods - the real
           work is done in __localinit. This is separated out this way so
           that we can call it from places other than instance creation
           e.g. when we just need to reconnect
           """
        if debug and debug.lower() == "on":
            ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
        if cacert is not None:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,cacert)
        if bindcert is not None:
            ldap.set_option(ldap.OPT_X_TLS_CERTFILE,bindcert)
        if bindkey is not None:
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE,bindkey)

        self.__wrapmethods()
        self.port = port
        self.host = host
        self.cacert = cacert
        self.bindcert = bindcert
        self.bindkey = bindkey
        self.proxydn = proxydn
        self.ldapi = ldapi
        self.realm = realm
        self.suffixes = {}
        self.schema = None
        self.__localinit()

    def __lateinit(self):
        """
        This is executed after the connection is bound to fill in some useful
        values.
        """
        try:
            ent = self.getEntry('cn=config,cn=ldbm database,cn=plugins,cn=config',
                                ldap.SCOPE_BASE, '(objectclass=*)',
                                [ 'nsslapd-directory' ])

            self.dbdir = os.path.dirname(ent.getValue('nsslapd-directory'))
        except ldap.LDAPError, e:
            self.__handle_errors(e, **{})

    def __str__(self):
        return self.host + ":" + str(self.port)

    def __get_server_controls(self):
        """Create the proxy user server control. The control has the form
        0x04 = Octet String
        4|0x80 sets the length of the string length field at 4 bytes
        the struct() gets us the length in bytes of string self.proxydn
        self.proxydn is the proxy dn to send"""

        if self.proxydn is not None:
            proxydn = chr(0x04) + chr(4|0x80) + struct.pack('l', socket.htonl(len(self.proxydn))) + self.proxydn;

            # Create the proxy control
            sctrl=[]
            sctrl.append(LDAPControl('2.16.840.1.113730.3.4.18',True,proxydn))
        else:
            sctrl=None

        return sctrl

    def __handle_errors(self, e, **kw):
        """
        Centralize error handling in one place.

        e is the error to be raised
        **kw is an exception-specific list of options
        """
        if not isinstance(e,ldap.TIMEOUT):
            desc = e.args[0]['desc'].strip()
            info = e.args[0].get('info','').strip()
        else:
            desc = ''
            info = ''

        try:
            # re-raise the error so we can handle it
            raise e
        except ldap.NO_SUCH_OBJECT, e:
            args = kw.get('args', ["entry not found"])
            raise errors.NotFound(reason=notfound(args))
        except ldap.ALREADY_EXISTS, e:
            raise errors.DuplicateEntry()
        except ldap.CONSTRAINT_VIOLATION, e:
            # This error gets thrown by the uniqueness plugin
            if info == 'Another entry with the same attribute value already exists':
                raise errors.DuplicateEntry()
            else:
                raise errors.DatabaseError(desc=desc,info=info)
        except ldap.INSUFFICIENT_ACCESS, e:
            raise errors.ACIError(info=info)
        except ldap.NO_SUCH_ATTRIBUTE:
            # this is raised when a 'delete' attribute isn't found.
            # it indicates the previous attribute was removed by another
            # update, making the oldentry stale.
            raise errors.MidairCollision()
        except ldap.ADMINLIMIT_EXCEEDED, e:
            raise errors.LimitsExceeded()
        except ldap.SIZELIMIT_EXCEEDED, e:
            raise errors.LimitsExceeded()
        except ldap.TIMELIMIT_EXCEEDED, e:
            raise errors.LimitsExceeded()
        except ldap.LDAPError, e:
            raise errors.DatabaseError(desc=desc,info=info)

    def toLDAPURL(self):
        return "ldap://%s:%d/" % (self.host,self.port)

    def set_proxydn(self, proxydn):
        self.proxydn = proxydn

    def set_krbccache(self, krbccache, principal):
        try:
            if krbccache is not None:
                os.environ["KRB5CCNAME"] = krbccache
                self.sasl_interactive_bind_s("", SASL_AUTH)
                self.principal = principal
            self.proxydn = None
        except ldap.LDAPError, e:
            self.__handle_errors(e, **{})

    def do_simple_bind(self, binddn="cn=directory manager", bindpw=""):
        self.binddn = binddn
        self.bindpwd = bindpw
        self.simple_bind_s(binddn, bindpw)
        self.__lateinit()

    def do_sasl_gssapi_bind(self):
        self.sasl_interactive_bind_s('', SASL_AUTH)
        self.__lateinit()

    def do_external_bind(self, user_name=None):
        auth_tokens = ldap.sasl.external(user_name)
        self.sasl_interactive_bind_s("", auth_tokens)
        self.__lateinit()

    def getEntry(self,*args):
        """This wraps the search function.  It is common to just get one entry"""

        sctrl = self.__get_server_controls()

        if sctrl is not None:
            self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)

        try:
            res = self.search(*args)
            objtype, obj = self.result(res)
        except ldap.LDAPError, e:
            kw = {'args': args}
            self.__handle_errors(e, **kw)

        if not obj:
            raise errors.NotFound(reason=notfound(args))

        elif isinstance(obj,Entry):
            return obj
        else: # assume list/tuple
            return obj[0]

    def getList(self,*args):
        """This wraps the search function to find multiple entries."""

        sctrl = self.__get_server_controls()
        if sctrl is not None:
            self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)

        try:
            res = self.search(*args)
            objtype, obj = self.result(res)
        except ldap.LDAPError, e:
            kw = {'args': args}
            self.__handle_errors(e, **kw)

        if not obj:
            raise errors.NotFound(reason=notfound(args))

        entries = []
        for s in obj:
            entries.append(s)

        return entries

    def getListAsync(self,*args):
        """This version performs an asynchronous search, to allow
           results even if we hit a limit.

           It returns a list: counter followed by the results.
           If the results are truncated, counter will be set to -1.
           """

        sctrl = self.__get_server_controls()
        if sctrl is not None:
            self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)

        entries = []
        partial = 0

        try:
            msgid = self.search_ext(*args)
            objtype, result_list = self.result(msgid, 0)
            while result_list:
                for result in result_list:
                    entries.append(result)
                objtype, result_list = self.result(msgid, 0)
        except (ldap.ADMINLIMIT_EXCEEDED, ldap.SIZELIMIT_EXCEEDED,
                ldap.TIMELIMIT_EXCEEDED), e:
            partial = 1
        except ldap.LDAPError, e:
            kw = {'args': args}
            self.__handle_errors(e, **kw)

        if not entries:
            raise errors.NotFound(reason=notfound(args))

        if partial == 1:
            counter = -1
        else:
            counter = len(entries)

        return [counter] + entries

    def addEntry(self,*args):
        """This wraps the add function. It assumes that the entry is already
           populated with all of the desired objectclasses and attributes"""

        sctrl = self.__get_server_controls()

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.add_s(*args)
        except ldap.LDAPError, e:
            kw = {'args': args}
            self.__handle_errors(e, **kw)
        return True

    def updateRDN(self, dn, newrdn):
        """Wrap the modrdn function."""

        sctrl = self.__get_server_controls()

        if dn == newrdn:
            # no need to report an error
            return True

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.modrdn_s(dn, newrdn, delold=1)
        except ldap.LDAPError, e:
            self.__handle_errors(e, **{})
        return True

    def updateEntry(self,dn,oldentry,newentry):
        """This wraps the mod function. It assumes that the entry is already
           populated with all of the desired objectclasses and attributes"""

        sctrl = self.__get_server_controls()

        modlist = self.generateModList(oldentry, newentry)

        if len(modlist) == 0:
            raise errors.EmptyModlist

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.modify_s(dn, modlist)
        except ldap.LDAPError, e:
            self.__handle_errors(e, **{})
        return True

    def generateModList(self, old_entry, new_entry):
        """A mod list generator that computes more precise modification lists
           than the python-ldap version.  For single-value attributes always
           use a REPLACE operation, otherwise use ADD/DEL.
        """

        # Some attributes, like those in cn=config, need to be replaced
        # not deleted/added.
        FORCE_REPLACE_ON_UPDATE_ATTRS = ('nsslapd-ssl-check-hostname',)
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

            if len(adds) == 0 and len(removes) == 0:
                continue

            is_single_value = self.get_single_value(key)
            force_replace = False
            if key in FORCE_REPLACE_ON_UPDATE_ATTRS or is_single_value:
                force_replace = True

            # You can't remove schema online. An add will automatically
            # replace any existing schema.
            if old_entry.get('dn') == 'cn=schema':
                if len(adds) > 0:
                    modlist.append((ldap.MOD_ADD, key, adds))
            else:
                if adds:
                    if force_replace:
                        modlist.append((ldap.MOD_REPLACE, key, adds))
                    else:
                        modlist.append((ldap.MOD_ADD, key, adds))
                if removes:
                    if not force_replace:
                        modlist.append((ldap.MOD_DELETE, key, removes))

        return modlist

    def inactivateEntry(self,dn,has_key):
        """Rather than deleting entries we mark them as inactive.
           has_key defines whether the entry already has nsAccountlock
           set so we can determine which type of mod operation to run."""

        sctrl = self.__get_server_controls()
        modlist=[]

        if has_key:
            operation = ldap.MOD_REPLACE
        else:
            operation = ldap.MOD_ADD

        modlist.append((operation, "nsAccountlock", "true"))

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.modify_s(dn, modlist)
        except ldap.LDAPError, e:
            self.__handle_errors(e, **{})
        return True

    def deleteEntry(self,*args):
        """This wraps the delete function. Use with caution."""

        sctrl = self.__get_server_controls()

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.delete_s(*args)
        except ldap.LDAPError, e:
            kw = {'args': args}
            self.__handle_errors(e, **kw)
        return True

    def modifyPassword(self,dn,oldpass,newpass):
        """Set the user password using RFC 3062, LDAP Password Modify Extended
           Operation. This ends up calling the IPA password slapi plugin
           handler so the Kerberos password gets set properly.

           oldpass is not mandatory
        """

        sctrl = self.__get_server_controls()

        try:
            if sctrl is not None:
                self.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
            self.passwd_s(dn, oldpass, newpass)
        except ldap.LDAPError, e:
            self.__handle_errors(e, **{})
        return True

    def __wrapmethods(self):
        """This wraps all methods of SimpleLDAPObject, so that we can intercept
        the methods that deal with entries.  Instead of using a raw list of tuples
        of lists of hashes of arrays as the entry object, we want to wrap entries
        in an Entry class that provides some useful methods"""
        for name in dir(self.__class__.__bases__[0]):
            attr = getattr(self, name)
            if callable(attr):
                setattr(self, name, wrapper(attr, name))

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

    def checkTask(self, dn, dowait=False, verbose=False):
        """check task status - task is complete when the nsTaskExitCode attr
           is set return a 2 tuple (true/false,code) first is false if task is
           running, true if done - if true, second is the exit code - if dowait
           is True, this function will block until the task is complete
        """
        attrlist = ['nsTaskLog', 'nsTaskStatus', 'nsTaskExitCode', 'nsTaskCurrentItem', 'nsTaskTotalItems']
        done = False
        exitCode = 0
        while not done:
            try:
                entry = self.getEntry(dn, ldap.SCOPE_BASE, "(objectclass=*)", attrlist)
            except errors.NotFound:
                break
            if verbose:
                print entry
            if entry.nsTaskExitCode:
                exitCode = int(entry.nsTaskExitCode)
                done = True
            if dowait: time.sleep(1)
            else: break
        return (done, exitCode)

    def get_schema(self):
        """
        Retrieve cn=schema and convert it into a python-ldap schema
        object.
        """
        if self.schema:
            return self.schema
        schema = self.getEntry('cn=schema', ldap.SCOPE_BASE,
            '(objectclass=*)', ['attributetypes', 'objectclasses'])
        schema = schema.toDict()
        self.schema = ldap.schema.SubSchema(schema)
        return self.schema

    def get_single_value(self, attr):
        """
        Check the schema to see if the attribute is single-valued.

        If the attribute is in the schema then returns True/False

        If there is a problem loading the schema or the attribute is
        not in the schema return None
        """
        if not self.schema:
            self.get_schema()
        obj = self.schema.get_obj(ldap.schema.AttributeType, attr)
        return obj and obj.single_value

    def normalizeDN(dn):
        # not great, but will do until we use a newer version of python-ldap
        # that has DN utilities
        ary = ldap.explode_dn(dn.lower())
        return ",".join(ary)
    normalizeDN = staticmethod(normalizeDN)

    def get_dns_sorted_by_length(self, entries, reverse=False):
        """
        Sorts a list of entries [(dn, entry_attrs)] based on their DN.
        Entries within the same node are not sorted in any meaningful way.
        If Reverse is set to True, leaf entries are returned first. This is
        useful to perform recursive deletes where you need to delete entries
        starting from the leafs and go up to delete nodes only when all its
        leafs are removed.

        Returns a "sorted" dict keyed by dn lengths and corresponding list
        of DNs.
        {'1': [dn1, dn2, dn3], '2': [dn4, dn5], ..}
        """

        res = dict()

        for e in entries:
            sdn = ldap.dn.str2dn(e.dn)
            l = len(sdn)
            if not l in res:
                res[l] = []
            res[l].append(e.dn)

        keys = res.keys()
        keys.sort(reverse=reverse)

        return map(res.get, keys)


def notfound(args):
    """Return a string suitable for displaying as an error when a
       search returns no results.

       This just returns whatever is after the equals sign"""
    if len(args) > 2:
        searchfilter = args[2]
        try:
            # Python re doesn't do paren counting so the string could
            # have a trailing paren "foo)"
            target = re.match(r'\(.*=(.*)\)', searchfilter).group(1)
            target = target.replace(")","")
        except:
            target = searchfilter
        return "%s not found" % str(target)
    else:
        return args[0]
