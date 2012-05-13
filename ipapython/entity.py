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

import copy

from ipapython import ipautil
from ipapython.dn import DN

def copy_CIDict(x):
    """Do a deep copy of a CIDict"""
    y = {}
    for key, value in x.iteritems():
        y[copy.deepcopy(key)] = copy.deepcopy(value)
    return y

class Entity:
    """This class represents an IPA user.  An LDAP entry consists of a DN
    and a list of attributes.  Each attribute consists of a name and a list of
    values. For the time being I will maintain this.

    In python-ldap, entries are returned as a list of 2-tuples.
    Instance variables:
    dn - string - the string DN of the entry
    data - CIDict - case insensitive dict of the attributes and values
    orig_data - CIDict - case insentiive dict of the original attributes and values"""

    def __init__(self,entrydata=None):
        """data is the raw data returned from the python-ldap result method,
        which is a search result entry or a reference or None.
        If creating a new empty entry, data is the string DN."""
        if entrydata:
            if isinstance(entrydata,tuple):
                self.dn = entrydata[0]
                self.data = ipautil.CIDict(entrydata[1])
            elif isinstance(entrydata, DN):
                self.dn = entrydata
                self.data = ipautil.CIDict()
            elif isinstance(entrydata, basestring):
                self.dn = DN(entrydata)
                self.data = ipautil.CIDict()
            elif isinstance(entrydata,dict):
                self.dn = entrydata['dn']
                del entrydata['dn']
                self.data = ipautil.CIDict(entrydata)
        else:
            self.dn = DN()
            self.data = ipautil.CIDict()

        assert isinstance(self.dn, DN)
        self.orig_data = ipautil.CIDict(copy_CIDict(self.data))

    dn = ipautil.dn_attribute_property('_dn')

    def __nonzero__(self):
        """This allows us to do tests like if entry: returns false if there is no data,
        true otherwise"""
        return self.data != None and len(self.data) > 0

    def hasAttr(self,name):
        """Return True if this entry has an attribute named name, False otherwise"""
        return self.data and self.data.has_key(name)

    def __str__(self):
        return "dn: %s data: %s" % (self.dn, self.data)

    def getValues(self,name):
        """Get the list (array) of values for the attribute named name"""
        return self.data.get(name)

    def getValue(self,name,default=None):
        """Get the first value for the attribute named name"""
        value =  self.data.get(name,default)
        if isinstance(value,list) or isinstance(value,tuple):
            return value[0]
        else:
            return value

    def setValue(self,name,*value):
        """Value passed in may be a single value, several values, or a single sequence.
        For example:
           ent.setValue('name', 'value')
           ent.setValue('name', 'value1', 'value2', ..., 'valueN')
           ent.setValue('name', ['value1', 'value2', ..., 'valueN'])
           ent.setValue('name', ('value1', 'value2', ..., 'valueN'))
        Since *value is a tuple, we may have to extract a list or tuple from that
        tuple as in the last two examples above"""
        if (len(value) < 1):
            return
        if (len(value) == 1):
            self.data[name] = ipautil.utf8_encode_values(value[0])
        else:
            self.data[name] = ipautil.utf8_encode_values(value)

    setValues = setValue

    def setValueNotEmpty(self,name,*value):
        """Similar to setValue() but will not set an empty field. This
           is an attempt to avoid adding empty attributes."""
        if (len(value) >= 1) and value[0] and len(value[0]) > 0:
            if isinstance(value[0], list):
                if len(value[0][0]) > 0:
                    self.setValue(name, *value)
                    return
            else:
                self.setValue(name, *value)
                return

        # At this point we have an empty incoming value. See if they are
        # trying to erase the current value. If so we'll delete it so
        # it gets marked as removed in the modlist.
        v = self.getValues(name)
        if v:
            self.delValue(name)

        return

    def delValue(self,name):
        """Remove the attribute named name."""
        if self.data.get(name,None):
            del self.data[name]

    def toTupleList(self):
        """Convert the attrs and values to a list of 2-tuples.  The first element
        of the tuple is the attribute name.  The second element is either a
        single value or a list of values."""
        return self.data.items()

    def toDict(self):
        """Convert the attrs and values to a dict. The dict is keyed on the
        attribute name.  The value is either single value or a list of values."""
        assert isinstance(self.dn, DN)
        result = ipautil.CIDict(self.data)
        result['dn'] = self.dn
        return result

    def attrList(self):
        """Return a list of all attributes in the entry"""
        return self.data.keys()

    def origDataDict(self):
        """Returns a dict of the original values of the user.  Used for updates."""
        assert isinstance(self.dn, DN)
        result = ipautil.CIDict(self.orig_data)
        result['dn'] = self.dn
        return result

#    def __str__(self):
#        """Convert the Entry to its LDIF representation"""
#        return self.__repr__()
#
#    # the ldif class base64 encodes some attrs which I would rather see in raw form - to
#    # encode specific attrs as base64, add them to the list below
#    ldif.safe_string_re = re.compile('^$')
#    base64_attrs = ['nsstate', 'krbprincipalkey', 'krbExtraData']
#
#    def __repr__(self):
#        """Convert the Entry to its LDIF representation"""
#        sio = cStringIO.StringIO()
#        # what's all this then?  the unparse method will currently only accept
#        # a list or a dict, not a class derived from them.  self.data is a
#        # cidict, so unparse barfs on it.  I've filed a bug against python-ldap,
#        # but in the meantime, we have to convert to a plain old dict for printing
#        # I also don't want to see wrapping, so set the line width really high (1000)
#        newdata = {}
#        newdata.update(self.data)
#        ldif.LDIFWriter(sio,User.base64_attrs,1000).unparse(self.dn,newdata)
#        return sio.getvalue()
