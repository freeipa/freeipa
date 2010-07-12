# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
"""
Backend plugin for LDAP.
"""

# Entries are represented as (dn, entry_attrs), where entry_attrs is a dict
# mapping attribute names to values. Values can be a single value or list/tuple
# of virtually any type. Each method passing these values to the python-ldap
# binding encodes them into the appropriate representation. This applies to
# everything except the CrudBackend methods, where dn is part of the entry dict.

import copy
import os
import socket
import string
import shutil
import tempfile

import krbV
import ldap as _ldap
import ldap.filter as _ldap_filter
import ldap.sasl as _ldap_sasl
from ldap.controls import LDAPControl
# for backward compatibility
from ldap.functions import explode_dn

import krbV

from ipalib import api, errors
from ipalib.crud import CrudBackend
from ipalib.encoder import Encoder, encode_args, decode_retval
from ipalib.request import context


# SASL authentication mechanism
SASL_AUTH = _ldap_sasl.sasl({}, 'GSSAPI')

# universal LDAPError handler
def _handle_errors(e, **kw):
    """
    Centralize error handling in one place.

    e is the error to be raised
    **kw is an exception-specific list of options
    """
    if not isinstance(e, _ldap.TIMEOUT):
        desc = e.args[0]['desc'].strip()
        info = e.args[0].get('info', '').strip()
    else:
        desc = ''
        info = ''

    try:
        # re-raise the error so we can handle it
        raise e
    except _ldap.NO_SUCH_OBJECT, e:
        # args = kw.get('args', '')
        # raise errors.NotFound(msg=notfound(args))
        raise errors.NotFound(reason='no such entry')
    except _ldap.ALREADY_EXISTS, e:
        raise errors.DuplicateEntry()
    except _ldap.CONSTRAINT_VIOLATION, e:
        # This error gets thrown by the uniqueness plugin
        if info == 'Another entry with the same attribute value already exists':
            raise errors.DuplicateEntry()
        else:
            raise errors.DatabaseError(desc=desc, info=info)
    except _ldap.INSUFFICIENT_ACCESS, e:
        raise errors.ACIError(info=info)
    except _ldap.INVALID_CREDENTIALS, e:
        raise errors.ACIError(info="%s %s" % (info, desc))
    except _ldap.NO_SUCH_ATTRIBUTE:
        # this is raised when a 'delete' attribute isn't found.
        # it indicates the previous attribute was removed by another
        # update, making the oldentry stale.
        raise errors.MidairCollision()
    except _ldap.OBJECT_CLASS_VIOLATION:
        raise errors.ObjectclassViolation(info=info)
    except _ldap.ADMINLIMIT_EXCEEDED, e:
        raise errors.LimitsExceeded()
    except _ldap.SIZELIMIT_EXCEEDED, e:
        raise errors.LimitsExceeded()
    except _ldap.TIMELIMIT_EXCEEDED, e:
        raise errors.LimitsExceeded()
    except _ldap.LDAPError, e:
        raise errors.DatabaseError(desc=desc, info=info)


def global_init(url):
    """
    Perform global initialization when the module is loaded.

    Retrieve the LDAP schema from the provided url and determine if
    User-Private Groups (upg) are configured.

    Bind using kerberos credentials. If in the context of the
    in-tree "lite" server then use the current ccache. If in the context of
    Apache then create a new ccache and bind using the Apache HTTP service
    principal.
    """
    tmpdir = None
    upg = False

    if not api.env.in_server or api.env.context not in ['lite', 'server']:
        # The schema is only needed on the server side
        return (None, None)

    try:
        if api.env.context == 'server':
            try:
                # Create a new credentials cache for this Apache process
                tmpdir = tempfile.mkdtemp(prefix = "tmp-")
                ccache_file = 'FILE:%s/ccache' % tmpdir
                krbcontext = krbV.default_context()
                principal = str('HTTP/%s@%s' % (api.env.host, api.env.realm))
                keytab = krbV.Keytab(name='/etc/httpd/conf/ipa.keytab', context=krbcontext)
                principal = krbV.Principal(name=principal, context=krbcontext)
                os.environ['KRB5CCNAME'] = ccache_file
                ccache = krbV.CCache(name=ccache_file, context=krbcontext, primary_principal=principal)
                ccache.init(principal)
                ccache.init_creds_keytab(keytab=keytab, principal=principal)
            except krbV.Krb5Error, e:
                raise StandardError('Unable to retrieve LDAP schema. Error initializing principal %s in %s: %s' % (principal.name, '/etc/httpd/conf/ipa.keytab', str(e)))

        conn = _ldap.initialize(url)
        conn.sasl_interactive_bind_s('', SASL_AUTH)

        schema_entry = conn.search_s(
            'cn=schema', _ldap.SCOPE_BASE,
            attrlist=['attributetypes', 'objectclasses']
        )[0]
        try:
            upg_entry = conn.search_s(
                'cn=UPG Template, %s' % api.env.basedn, _ldap.SCOPE_BASE,
                attrlist=['*']
            )[0]
            upg = True
        except _ldap.NO_SUCH_OBJECT, e:
            upg = False
        conn.unbind_s()
    except _ldap.SERVER_DOWN:
        return (None, upg)
    except _ldap.LDAPError, e:
        desc = e.args[0]['desc'].strip()
        info = e.args[0].get('info', '').strip()
        raise StandardError('Unable to retrieve LDAP schema: %s: %s' % (desc, info))
    except IndexError:
        # no 'cn=schema' entry in LDAP? some servers use 'cn=subschema'
        # TODO: DS uses 'cn=schema', support for other server?
        #       raise a more appropriate exception
        raise
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir)

    return (_ldap.schema.SubSchema(schema_entry[1]), upg)

# cache schema and User-Private Groups when importing module
try:
    (_schema, _upg) = global_init(api.env.ldap_uri)
except AttributeError:
    _schema = None
    _upg = None


def get_syntax(attr, value):
    global _schema

    if not _schema:
        return None
    obj = _schema.get_obj(_ldap.schema.AttributeType, attr)
    if obj is not None:
        return obj.syntax
    else:
        return None


class ldap2(CrudBackend, Encoder):
    """
    LDAP Backend Take 2.
    """
    # attribute syntax to python type mapping, 'SYNTAX OID': type
    # everything not in this dict is considered human readable unicode
    _SYNTAX_MAPPING = {
        '1.3.6.1.4.1.1466.115.121.1.1': str,  # ACI item
        '1.3.6.1.4.1.1466.115.121.1.4': str,  # Audio
        '1.3.6.1.4.1.1466.115.121.1.5': str,  # Binary
        '1.3.6.1.4.1.1466.115.121.1.8': str,  # Certificate
        '1.3.6.1.4.1.1466.115.121.1.9': str,  # Certificate List
        '1.3.6.1.4.1.1466.115.121.1.10': str, # Certificate Pair
        '1.3.6.1.4.1.1466.115.121.1.23': str, # Fax
        '1.3.6.1.4.1.1466.115.121.1.28': str, # JPEG
        '1.3.6.1.4.1.1466.115.121.1.40': str, # OctetString (same as Binary)
        '1.3.6.1.4.1.1466.115.121.1.49': str, # Supported Algorithm
        '1.3.6.1.4.1.1466.115.121.1.51': str, # Teletext Terminal Identifier
    }

    # attributes in this list cannot be deleted by update_entry
    # only MOD_REPLACE operations are generated for them
    _FORCE_REPLACE_ON_UPDATE_ATTRS = []

    # rules for generating filters from entries
    MATCH_ANY = '|'   # (|(filter1)(filter2))
    MATCH_ALL = '&'   # (&(filter1)(filter2))
    MATCH_NONE = '!'  # (!(filter1)(filter2))

    # search scope for find_entries()
    SCOPE_BASE = _ldap.SCOPE_BASE
    SCOPE_ONELEVEL = _ldap.SCOPE_ONELEVEL
    SCOPE_SUBTREE = _ldap.SCOPE_SUBTREE

    def __init__(self, shared_instance=True, ldap_uri=None, base_dn=None,
                 schema=None):
        CrudBackend.__init__(self, shared_instance=shared_instance)
        Encoder.__init__(self)
        self.encoder_settings.encode_dict_keys = True
        self.encoder_settings.decode_dict_keys = True
        self.encoder_settings.decode_dict_vals_postprocess = False
        self.encoder_settings.decode_dict_vals_table = self._SYNTAX_MAPPING
        self.encoder_settings.decode_dict_vals_table_keygen = get_syntax
        self.encoder_settings.decode_postprocessor = lambda x: string.lower(x)
        try:
            self.ldap_uri = ldap_uri or api.env.ldap_uri
        except AttributeError:
            self.ldap_uri = 'ldap://example.com'
        try:
            self.base_dn = base_dn or api.env.basedn
        except AttributeError:
            self.base_dn = ''
        self.schema = schema or _schema

    def __del__(self):
        if self.isconnected():
            self.disconnect()

    def __str__(self):
        return self.ldap_uri

    @encode_args(2, 3, 'bind_dn', 'bind_pw')
    def create_connection(self, ccache=None, bind_dn='', bind_pw='',
            tls_cacertfile=None, tls_certfile=None, tls_keyfile=None,
            debug_level=255):
        """
        Connect to LDAP server.

        Keyword arguments:
        ldapuri -- the LDAP server to connect to
        ccache -- Kerberos V5 ccache name
        bind_dn -- dn used to bind to the server
        bind_pw -- password used to bind to the server
        debug_level -- LDAP debug level option
        tls_cacertfile -- TLS CA certificate filename
        tls_certfile -- TLS certificate filename
        tls_keyfile - TLS bind key filename

        Extends backend.Connectible.create_connection.
        """
        if tls_cacertfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_CACERTFILE, tls_cacertfile)
        if tls_certfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_CERTFILE, tls_certfile)
        if tls_keyfile is not None:
            _ldap.set_option(_ldap.OPT_X_TLS_KEYFILE, tls_keyfile)

        try:
            conn = _ldap.initialize(self.ldap_uri)
            if ccache is not None:
                os.environ['KRB5CCNAME'] = ccache
                conn.sasl_interactive_bind_s('', SASL_AUTH)
                principal = krbV.CCache(name=ccache,
                            context=krbV.default_context()).principal().name
                setattr(context, 'principal', principal)
            else:
                # no kerberos ccache, use simple bind
                conn.simple_bind_s(bind_dn, bind_pw)
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})
        return conn

    def destroy_connection(self):
        """Disconnect from LDAP server."""
        try:
            self.conn.unbind_s()
        except _ldap.LDAPError:
            # ignore when trying to unbind multiple times
            pass

    def normalize_dn(self, dn):
        """
        Normalize distinguished name.

        Note: You don't have to normalize DN's before passing them to
              ldap2 methods. It's done internally for you.
        """
        rdns = explode_dn(dn)
        if rdns:
            dn = ','.join(rdns)
            if not dn.endswith(self.base_dn):
                dn = '%s,%s' % (dn, self.base_dn)
            return dn
        return self.base_dn

    def get_container_rdn(self, name):
        """Get relative distinguished name of cotainer."""
        env_container = 'container_%s' % name
        if env_container in self.api.env:
            return self.api.env[env_container]
        return ''

    def make_rdn_from_attr(self, attr, value):
        """Make relative distinguished name from attribute."""
        if isinstance(value, (list, tuple)):
            value = value[0]
        attr = _ldap.dn.escape_dn_chars(attr)
        value = _ldap.dn.escape_dn_chars(value)
        return '%s=%s' % (attr, value)

    def make_dn_from_rdn(self, rdn, parent_dn=''):
        """
        Make distinguished name from relative distinguished name.

        Keyword arguments:
        parent_dn -- DN of the parent entry (default '')
        """
        parent_dn = self.normalize_dn(parent_dn)
        return '%s,%s' % (rdn, parent_dn)

    def make_dn_from_attr(self, attr, value, parent_dn=''):
        """
        Make distinguished name from attribute.

        Keyword arguments:
        parent_dn -- DN of the parent entry (default '')
        """
        rdn = self.make_rdn_from_attr(attr, value)
        return self.make_dn_from_rdn(rdn, parent_dn)

    def make_dn(self, entry_attrs, primary_key='cn', parent_dn=''):
        """
        Make distinguished name from entry attributes.

        Keyword arguments:
        primary_key -- attribute from which to make RDN (default 'cn')
        parent_dn -- DN of the parent entry (default '')
        """
        assert primary_key in entry_attrs
        rdn = self.make_rdn_from_attr(primary_key, entry_attrs[primary_key])
        return self.make_dn_from_rdn(rdn, parent_dn)

    @encode_args(1, 2)
    def add_entry(self, dn, entry_attrs, normalize=True):
        """Create a new entry."""
        if normalize:
            dn = self.normalize_dn(dn)
        # remove all None values, python-ldap hates'em
        entry_attrs = dict(
            (k, v) for (k, v) in entry_attrs.iteritems() if v
        )
        try:
            self.conn.add_s(dn, list(entry_attrs.iteritems()))
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    # generating filters for find_entry
    # some examples:
    # f1 = ldap2.make_filter_from_attr(u'firstName', u'Pavel')
    # f2 = ldap2.make_filter_from_attr(u'lastName', u'Zuna')
    # f = ldap2.combine_filters([f1, f2], ldap2.MATCH_ALL)
    # # f should be (&(firstName=Pavel)(lastName=Zuna))
    # # it should be equivalent to:
    # entry_attrs = {u'firstName': u'Pavel', u'lastName': u'Zuna'}
    # f = ldap2.make_filter(entry_attrs, rules=ldap2.MATCH_ALL)

    def combine_filters(self, filters, rules='|'):
        """
        Combine filters into one for ldap2.find_entries.

        Keyword arguments:
        rules -- see ldap2.make_filter
        """
        assert isinstance(filters, (list, tuple))
        filters = [f for f in filters if f]
        if len(filters) > 1:
            flt = '(%s' % rules
        else:
            flt = ''
        for f in filters:
            if not f.startswith('('):
                f = '(%s)' % f
            flt = '%s%s' % (flt, f)
        if len(filters) > 1:
            flt = '%s)' % flt
        return flt

    @encode_args(1, 2)
    def make_filter_from_attr(self, attr, value, rules='|', exact=True):
        """
        Make filter for ldap2.find_entries from attribute.

        Keyword arguments:
        rules -- see ldap2.make_filter
        exact -- boolean, True - make filter as (attr=value)
                          False - make filter as (attr=*value*)
        """
        if isinstance(value, (list, tuple)):
            flts = []
            for v in value:
                flts.append(self.make_filter_from_attr(attr, v, rules, exact))
            return self.combine_filters(flts, rules)
        elif value is not None:
            value = _ldap_filter.escape_filter_chars(value)
            if not exact:
                value = '*%s*' % value
            if rules == self.MATCH_NONE:
                return '(!(%s=%s))' % (attr, value)
            return '(%s=%s)' % (attr, value)
        return ''

    def make_filter(self, entry_attrs, attrs_list=None, rules='|', exact=True):
        """
        Make filter for ldap2.find_entries from entry attributes.

        Keyword arguments:
        attrs_list -- list of attributes to use, all if None (default None)
        rules -- specifies how to determine a match (default ldap2.MATCH_ANY)
        exact -- boolean, True - make filter as (attr=value)
                          False - make filter as (attr=*value*)

        rules can be one of the following:
        ldap2.MATCH_NONE - match entries that do not match any attribute
        ldap2.MATCH_ALL - match entries that match all attributes
        ldap2.MATCH_ANY - match entries that match any of attribute
        """
        flts = []
        if attrs_list is None:
            for (k, v) in entry_attrs.iteritems():
                flts.append(
                    self.make_filter_from_attr(k, v, rules, exact)
                )
        else:
            for a in attrs_list:
                value = entry_attrs.get(a, None)
                if value is not None:
                    flts.append(
                        self.make_filter_from_attr(a, value, rules, exact)
                    )
        return self.combine_filters(flts, rules)

    @encode_args(1, 2, 3)
    @decode_retval()
    def find_entries(self, filter, attrs_list=None, base_dn='',
            scope=_ldap.SCOPE_SUBTREE, time_limit=1, size_limit=3000,
            normalize=True):
        """
        Return a list of entries [(dn, entry_attrs)] matching specified
        search parameters followed by truncated flag. If the truncated flag is
        True, search hit a server limit and its results are incomplete.

        Keyword arguments:
        attrs_list -- list of attributes to return, all if None (default None)
        base_dn -- dn of the entry at which to start the search (default '')
        scope -- search scope, see LDAP docs (default ldap2.SCOPE_SUBTREE)
        time_limit -- time limit in seconds (default 1)
        size_limit -- size (number of entries returned) limit (default 3000)
        normalize -- normalize the DN (default True)
        """
        if normalize:
            base_dn = self.normalize_dn(base_dn)
        if not filter:
            filter = '(objectClass=*)'
        res = []
        truncated = False

        # pass arguments to python-ldap
        try:
            id = self.conn.search_ext(
                base_dn, scope, filter, attrs_list, timeout=time_limit,
                sizelimit=size_limit
            )
            while True:
                (objtype, res_list) = self.conn.result(id, 0)
                if not res_list:
                    break
                res.append(res_list[0])
        except (_ldap.ADMINLIMIT_EXCEEDED, _ldap.TIMELIMIT_EXCEEDED,
                _ldap.SIZELIMIT_EXCEEDED), e:
            truncated = True
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

        if not res:
            raise errors.NotFound(reason='no such entry')

        return (res, truncated)

    def find_entry_by_attr(self, attr, value, object_class, attrs_list=None,
            base_dn=''):
        """
        Find entry (dn, entry_attrs) by attribute and object class.

        Keyword arguments:
        attrs_list - list of attributes to return, all if None (default None)
        base_dn - dn of the entry at which to start the search (default '')
        """
        search_kw = {attr: value, 'objectClass': object_class}
        filter = self.make_filter(search_kw, rules=self.MATCH_ALL)
        return self.find_entries(filter, attrs_list, base_dn)[0][0]

    def get_entry(self, dn, attrs_list=None, normalize=True):
        """
        Get entry (dn, entry_attrs) by dn.

        Keyword arguments:
        attrs_list - list of attributes to return, all if None (default None)
        """
        return self.find_entries(None, attrs_list, dn, self.SCOPE_BASE, normalize=normalize)[0][0]

    def get_ipa_config(self):
        """Returns the IPA configuration entry (dn, entry_attrs)."""
        filter = '(cn=ipaConfig)'
        return self.find_entries(filter, None, 'cn=etc', self.SCOPE_ONELEVEL)[0][0]

    def get_schema(self):
        """Returns a copy of the current LDAP schema."""
        return copy.deepcopy(self.schema)

    def has_upg(self):
        """Returns True/False whether User-Private Groups are enabled.
           This is determined based on whether the UPG Template exists.
           We determine this at module load so we don't have to test for
           it every time.
        """
        global _upg

        return _upg

    @encode_args(1, 2)
    def get_effective_rights(self, dn, entry_attrs):
        """Returns the rights the currently bound user has for the given DN.

           Returns 2 attributes, the attributeLevelRights for the given list of
           attributes and the entryLevelRights for the entry itself.
        """
        principal = getattr(context, 'principal')
        (binddn, attrs) = self.find_entry_by_attr("krbprincipalname", principal, "krbPrincipalAux")
        sctrl = [LDAPControl("1.3.6.1.4.1.42.2.27.9.5.2", True, "dn: " + binddn.encode('UTF-8'))]
        self.conn.set_option(_ldap.OPT_SERVER_CONTROLS, sctrl)
        (dn, attrs) = self.get_entry(dn, entry_attrs)
        # remove the control so subsequent operations don't include GER
        self.conn.set_option(_ldap.OPT_SERVER_CONTROLS, [])
        return (dn, attrs)

    @encode_args(1, 2)
    def can_write(self, dn, attr):
        """Returns True/False if the currently bound user has write permissions
           on the attribute. This only operates on a single attribute at a time.
        """
        (dn, attrs) = self.get_effective_rights(dn, [attr])
        if 'attributelevelrights' in attrs:
            attr_rights = attrs.get('attributelevelrights')[0].decode('UTF-8')
            (attr, rights) = attr_rights.split(':')
            if 'w' in rights:
                return True

        return False

    #
    # Entry-level effective rights
    #
    # a - Add
    # d - Delete
    # n - Rename the DN
    # v - View the entry
    #

    @encode_args(1)
    def can_delete(self, dn):
        """Returns True/False if the currently bound user has delete permissions
           on the entry.
        """
        (dn, attrs) = self.get_effective_rights(dn, ["*"])
        if 'entrylevelrights' in attrs:
            entry_rights = attrs['entrylevelrights'][0].decode('UTF-8')
            if 'd' in entry_rights:
                return True

        return False

    @encode_args(1)
    def can_add(self, dn):
        """Returns True/False if the currently bound user has add permissions
           on the entry.
        """
        (dn, attrs) = self.get_effective_rights(dn, ["*"])
        if 'entrylevelrights' in attrs:
            entry_rights = attrs['entrylevelrights'][0].decode('UTF-8')
            if 'a' in entry_rights:
                return True

        return False

    @encode_args(1, 2)
    def update_entry_rdn(self, dn, new_rdn, del_old=True):
        """
        Update entry's relative distinguished name.

        Keyword arguments:
        del_old -- delete old RDN value (default True)
        """
        dn = self.normalize_dn(dn)
        try:
            self.conn.rename_s(dn, new_rdn, delold=int(del_old))
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    def _generate_modlist(self, dn, entry_attrs, normalize):
        # get original entry
        (dn, entry_attrs_old) = self.get_entry(dn, entry_attrs.keys(), normalize)
        # get_entry returns a decoded entry, encode it back
        # we could call search_s directly, but this saves a lot of code at
        # the expense of a little bit of performace
        entry_attrs_old = self.encode(entry_attrs_old)
        # generate modlist
        # for multi value attributes: no MOD_REPLACE to handle simultaneous
        # updates better
        # for single value attribute: always MOD_REPLACE
        modlist = []
        for (k, v) in entry_attrs.iteritems():
            if v is None and k in entry_attrs_old:
                modlist.append((_ldap.MOD_DELETE, k, None))
            else:
                if not isinstance(v, (list, tuple)):
                    v = [v]
                v = set(filter(lambda value: value is not None, v))
                old_v = set(entry_attrs_old.get(k.lower(), []))

                adds = list(v.difference(old_v))
                rems = list(old_v.difference(v))

                force_replace = False
                if k in self._FORCE_REPLACE_ON_UPDATE_ATTRS:
                    force_replace = True
                elif self.schema:
                    obj = self.schema.get_obj(_ldap.schema.AttributeType, k)
                    if obj and obj.single_value:
                        force_replace = True
                elif len(adds) == 1 and len(rems) == 1:
                    force_replace = True

                if adds:
                    if force_replace:
                        modlist.append((_ldap.MOD_REPLACE, k, adds))
                    else:
                        modlist.append((_ldap.MOD_ADD, k, adds))
                if rems:
                    if not force_replace:
                        modlist.append((_ldap.MOD_DELETE, k, rems))

        return modlist

    @encode_args(1, 2)
    def update_entry(self, dn, entry_attrs, normalize=True):
        """
        Update entry's attributes.

        An attribute value set to None deletes all current values.
        """
        if normalize:
            dn = self.normalize_dn(dn)

        # generate modlist
        modlist = self._generate_modlist(dn, entry_attrs, normalize)
        if not modlist:
            raise errors.EmptyModlist()

        # pass arguments to python-ldap
        try:
            self.conn.modify_s(dn, modlist)
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    @encode_args(1)
    def delete_entry(self, dn, normalize=True):
        """Delete entry."""
        if normalize:
            dn = self.normalize_dn(dn)
        try:
            self.conn.delete_s(dn)
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    @encode_args(1, 2, 3)
    def modify_password(self, dn, new_pass, old_pass=''):
        """Set user password."""
        dn = self.normalize_dn(dn)
        try:
            self.conn.passwd_s(dn, old_pass, new_pass)
        except _ldap.LDAPError, e:
            _handle_errors(e, **{})

    def add_entry_to_group(self, dn, group_dn, member_attr='member'):
        """Add entry to group."""
        # check if the entry exists
        (dn, entry_attrs) = self.get_entry(dn, ['objectclass'])

        # get group entry
        (group_dn, group_entry_attrs) = self.get_entry(group_dn, [member_attr])

        # check if we're not trying to add group into itself
        if dn == group_dn:
            raise errors.SameGroupError()

        # add dn to group entry's `member_attr` attribute
        members = group_entry_attrs.get(member_attr, [])
        members.append(dn)
        group_entry_attrs[member_attr] = members

        # update group entry
        try:
            self.update_entry(group_dn, group_entry_attrs)
        except errors.EmptyModlist:
            raise errors.AlreadyGroupMember()

    def remove_entry_from_group(self, dn, group_dn, member_attr='member'):
        """Remove entry from group."""
        # get group entry
        (group_dn, group_entry_attrs) = self.get_entry(group_dn, [member_attr])

        # remove dn from group entry's `member_attr` attribute
        members = group_entry_attrs.get(member_attr, [])
        try:
            members.remove(dn)
        except ValueError:
            raise errors.NotGroupMember()
        group_entry_attrs[member_attr] = members

        # update group entry
        self.update_entry(group_dn, group_entry_attrs)

    def set_entry_active(self, dn, active):
        """Mark entry active/inactive."""
        assert isinstance(active, bool)
        # get the entry in question
        (dn, entry_attrs) = self.get_entry(dn, ['nsaccountlock', 'memberof'])

        # check nsAccountLock attribute
        account_lock_attr = entry_attrs.get('nsaccountlock', ['false'])
        account_lock_attr = account_lock_attr[0].lower()
        if active:
            if account_lock_attr == 'false':
                raise errors.AlreadyActive()
        else:
            if account_lock_attr == 'true':
                raise errors.AlreadyInactive()

        # check if nsAccountLock attribute is in the entry itself
        is_member = False
        member_of_attr = entry_attrs.get('memberof', [])
        for m in member_of_attr:
            if m.find('cn=activated') >= 0 or m.find('cn=inactivated') >=0:
                is_member = True
                break
        if not is_member and entry_attrs.has_key('nsaccountlock'):
            raise errors.HasNSAccountLock()

        activated_filter = '(cn=activated)'
        inactivated_filter = '(cn=inactivated)'
        parent_rdn = self.get_container_rdn('accounts')

        # try to remove the entry from activated/inactivated group
        if active:
            entries = self.find_entries(inactivated_filter, [], parent_rdn)[0]
        else:
            entries = self.find_entries(activated_filter, [], parent_rdn)[0]
        (group_dn, group_entry_attrs) = entries[0]
        try:
            self.remove_entry_from_group(dn, group_dn)
        except errors.NotGroupMember:
            pass

        # add the entry to the activated/inactivated group if necessary
        if active:
            (dn, entry_attrs) = self.get_entry(dn, ['nsaccountlock'])

            # check if we still need to add entry to the activated group
            account_lock_attr = entry_attrs.get('nsaccountlock', ['false'])
            account_lock_attr = account_lock_attr[0].lower()
            if account_lock_attr == 'false':
                return  # we don't

            entries = self.find_entries(activated_filter, [], parent_rdn)[0]
        else:
            entries = self.find_entries(inactivated_filter, [], parent_rdn)[0]
        (group_dn, group_entry_attrs) = entries[0]
        try:
            self.add_entry_to_group(dn, group_dn)
        except errors.EmptyModlist:
            if active:
                raise errors.AlreadyActive()
            else:
                raise errors.AlreadyInactive()

    def activate_entry(self, dn):
        """Mark entry active."""
        self.set_entry_active(dn, True)

    def deactivate_entry(self, dn):
        """Mark entry inactive."""
        self.set_entry_active(dn, False)

    def remove_principal_key(self, dn):
        """Remove a kerberos principal key."""

        dn = self.normalize_dn(dn)

        # We need to do this directly using the LDAP library because we
        # don't have read access to krbprincipalkey so we need to delete
        # it in the blind.
        mod = [(_ldap.MOD_REPLACE, 'krbprincipalkey', None),
               (_ldap.MOD_REPLACE, 'krblastpwdchange', None)]

        try:
            self.conn.modify_s(dn, mod)
        except _ldap.LDAPError, e:
            self._handle_errors(e, **{})

    # CrudBackend methods

    def _get_normalized_entry_for_crud(self, dn, attrs_list=None):
        (dn, entry_attrs) = self.get_entry(dn, attrs_list)
        entry_attrs['dn'] = dn
        return entry_attrs

    def create(self, **kw):
        """
        Create a new entry and return it as one dict (DN included).

        Extends CrudBackend.create.
        """
        assert 'dn' in kw
        dn = kw['dn']
        del kw['dn']
        self.add_entry(dn, kw)
        return self._get_normalized_entry_for_crud(dn)

    def retrieve(self, primary_key, attributes):
        """
        Get entry by primary_key (DN) as one dict (DN included).

        Extends CrudBackend.retrieve.
        """
        return self._get_normalized_entry_for_crud(primary_key, attributes)

    def update(self, primary_key, **kw):
        """
        Update entry's attributes and return it as one dict (DN included).

        Extends CrudBackend.update.
        """
        self.update_entry(primary_key, kw)
        return self._get_normalized_entry_for_crud(primary_key)

    def delete(self, primary_key):
        """
        Delete entry by primary_key (DN).

        Extends CrudBackend.delete.
        """
        self.delete_entry(primary_key)

    def search(self, **kw):
        """
        Return a list of entries (each entry is one dict, DN included) matching
        the specified criteria.

        Keyword arguments:
        filter -- search filter (default: '')
        attrs_list -- list of attributes to return, all if None (default None)
        base_dn -- dn of the entry at which to start the search (default '')
        scope -- search scope, see LDAP docs (default ldap2.SCOPE_SUBTREE)

        Extends CrudBackend.search.
        """
        # get keyword arguments
        filter = kw.pop('filter', None)
        attrs_list = kw.pop('attrs_list', None)
        base_dn = kw.pop('base_dn', '')
        scope = kw.pop('scope', self.SCOPE_SUBTREE)

        # generate filter
        filter_tmp = self.make_filter(kw)
        if filter:
            filter = self.combine_filters((filter, filter_tmp), self.MATCH_ALL)
        else:
            filter = filter_tmp
        if not filter:
            filter = '(objectClass=*)'

        # find entries and normalize the output for CRUD
        output = []
        (entries, truncated) = self.find_entries(
            filter, attrs_list, base_dn, scope
        )
        for (dn, entry_attrs) in entries:
            entry_attrs['dn'] = [dn]
            output.append(entry_attrs)

        if truncated:
            return (-1, output)
        return (len(output), output)

api.register(ldap2)

