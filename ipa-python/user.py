import ldap
import ldif
import re
import cStringIO

class User:
    """This class represents an IPA user.  An LDAP entry consists of a DN
    and a list of attributes.  Each attribute consists of a name and a list of
    values. For the time being I will maintain this.

    In python-ldap, entries are returned as a list of 2-tuples.
    Instance variables:
    dn - string - the string DN of the entry
    data - cidict - case insensitive dict of the attributes and values"""

    def __init__(self,entrydata):
        """data is the raw data returned from the python-ldap result method,
        which is a search result entry or a reference or None.
        If creating a new empty entry, data is the string DN."""
        if entrydata:
            if isinstance(entrydata,tuple):
                self.dn = entrydata[0]
                self.data = ldap.cidict.cidict(entrydata[1])
            elif isinstance(entrydata,str):
                self.dn = entrydata
                self.data = ldap.cidict.cidict()
            elif isinstance(entrydata,dict):
                self.dn = entrydata['dn']
                del entrydata['dn']
                self.data = ldap.cidict.cidict(entrydata)
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
        value =  self.data.get(name,[None])
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
        if (len(value[0]) < 1):
            return
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

    def toDict(self):
        """Convert the attrs and values to a dict. The dict is keyed on the
        attribute name.  The value is either single value or a list of values."""
        result = {}
        for k in self.data.keys():
            result[k] = self.data[k]
        result['dn'] = self.dn
        return result

    def attrList(self):
        """Return a list of all attributes in the entry"""
        return self.data.keys()

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
