# Authors:
#     Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2011  Red Hat
# see file 'COPYING' for use and warranty information
#
# Portions (C) Andrew Tridgell, Andrew Bartlett
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

# Make sure we only run this module at the server where samba4-python
# package is installed to avoid issues with unavailable modules

from ipalib.plugins.baseldap import *
from ipalib import api, Str, Password, DefaultFrom, _, ngettext, Object
from ipalib.parameters import Enum
from ipalib import Command
from ipalib import errors
from ipapython import ipautil
from ipapython.ipa_log_manager import *
from ipapython.dn import DN
from ipaserver.install import installutils
from ipalib.util import normalize_name

import os, string, struct, copy
import uuid
from samba import param
from samba import credentials
from samba.dcerpc import security, lsa, drsblobs, nbt, netlogon
from samba.ndr import ndr_pack
from samba import net
import samba
import random
from M2Crypto import RC4
try:
    from ldap.controls import RequestControl as LDAPControl #pylint: disable=F0401
except ImportError:
    from ldap.controls import LDAPControl as LDAPControl    #pylint: disable=F0401
import ldap as _ldap
from ipaserver.ipaldap import IPAdmin
from ipalib.session import krbccache_dir, krbccache_prefix
from dns import resolver, rdatatype
from dns.exception import DNSException

__doc__ = _("""
Classes to manage trust joins using DCE-RPC calls

The code in this module relies heavily on samba4-python package
and Samba4 python bindings.
""")

access_denied_error =  errors.ACIError(info=_('CIFS server denied your credentials'))
dcerpc_error_codes = {
    -1073741823:
        errors.RemoteRetrieveError(reason=_('communication with CIFS server was unsuccessful')),
    -1073741790: access_denied_error,
    -1073741715: access_denied_error,
    -1073741614: access_denied_error,
    -1073741603:
        errors.ValidationError(name=_('AD domain controller'), error=_('unsupported functional level')),
}

dcerpc_error_messages = {
    "NT_STATUS_OBJECT_NAME_NOT_FOUND":
         errors.NotFound(reason=_('Cannot find specified domain or server name')),
    "NT_STATUS_INVALID_PARAMETER_MIX":
         errors.RequirementError(name=_('At least the domain or IP address should be specified')),
}

def assess_dcerpc_exception(num=None,message=None):
    """
    Takes error returned by Samba bindings and converts it into
    an IPA error class.
    """
    if num and num in dcerpc_error_codes:
        return dcerpc_error_codes[num]
    if message and message in dcerpc_error_messages:
        return dcerpc_error_messages[message]
    reason = _('''CIFS server communication error: code "%(num)s",
                  message "%(message)s" (both may be "None")''') % dict(num=num, message=message)
    return errors.RemoteRetrieveError(reason=reason)

class ExtendedDNControl(LDAPControl):
    # This class attempts to implement LDAP control that would work
    # with both python-ldap 2.4.x and 2.3.x, thus there is mix of properties
    # from both worlds and encodeControlValue has default parameter
    def __init__(self):
        self.controlValue = 1
        self.controlType = "1.2.840.113556.1.4.529"
        self.criticality = False
        self.integerValue = 1

    def encodeControlValue(self, value=None):
        return '0\x03\x02\x01\x01'

class DomainValidator(object):
    ATTR_FLATNAME = 'ipantflatname'
    ATTR_SID = 'ipantsecurityidentifier'
    ATTR_TRUSTED_SID = 'ipanttrusteddomainsid'
    ATTR_TRUST_PARTNER = 'ipanttrustpartner'
    ATTR_TRUST_AUTHOUT = 'ipanttrustauthoutgoing'

    def __init__(self, api):
        self.api = api
        self.ldap = self.api.Backend.ldap2
        self.domain = None
        self.flatname = None
        self.dn = None
        self.sid = None
        self._domains = None
        self._info = dict()
        self._creds = None
        self._parm = None

    def is_configured(self):
        cn_trust_local = DN(('cn', self.api.env.domain), self.api.env.container_cifsdomains, self.api.env.basedn)
        try:
            (dn, entry_attrs) = self.ldap.get_entry(cn_trust_local, [self.ATTR_FLATNAME, self.ATTR_SID])
            self.flatname = entry_attrs[self.ATTR_FLATNAME][0]
            self.sid = entry_attrs[self.ATTR_SID][0]
            self.dn = dn
            self.domain = self.api.env.domain
        except errors.NotFound, e:
            return False
        return True

    def get_trusted_domains(self):
        """Returns dict of trusted domain tuples (flatname, sid, trust_auth_outgoing), keyed by domain name"""
        cn_trust = DN(('cn', 'ad'), self.api.env.container_trusts, self.api.env.basedn)
        try:
            search_kw = {'objectClass': 'ipaNTTrustedDomain'}
            filter = self.ldap.make_filter(search_kw, rules=self.ldap.MATCH_ALL)
            (entries, truncated) = self.ldap.find_entries(filter=filter, base_dn=cn_trust,
                                                          attrs_list=[self.ATTR_TRUSTED_SID,
                                                                      self.ATTR_FLATNAME,
                                                                      self.ATTR_TRUST_PARTNER,
                                                                      self.ATTR_TRUST_AUTHOUT])

            result = dict()
            for entry in entries:
                result[entry[1][self.ATTR_TRUST_PARTNER][0]] = (entry[1][self.ATTR_FLATNAME][0].lower(),
                                                                security.dom_sid(entry[1][self.ATTR_TRUSTED_SID][0]),
                                                                entry[1][self.ATTR_TRUST_AUTHOUT][0])
            return result
        except errors.NotFound, e:
            return []

    def is_trusted_sid_valid(self, sid):
        if not self.domain:
            # our domain is not configured or self.is_configured() never run
            # reject SIDs as we can't check correctness of them
            return False
        # Parse sid string to see if it is really in a SID format
        try:
            test_sid = security.dom_sid(sid)
        except TypeError, e:
            return False
        # At this point we have SID_NT_AUTHORITY family SID and really need to
        # check it against prefixes of domain SIDs we trust to
        if not self._domains:
            self._domains = self.get_trusted_domains()
        if len(self._domains) == 0:
            # Our domain is configured but no trusted domains are configured
            # This means we can't check the correctness of a trusted domain SIDs
            return False
        # We have non-zero list of trusted domains and have to go through them
        # one by one and check their sids as prefixes
        test_sid_subauths = test_sid.sub_auths
        for domain in self._domains:
            domsid = self._domains[domain][1]
            sub_auths = domsid.sub_auths
            num_auths = min(test_sid.num_auths, domsid.num_auths)
            if test_sid_subauths[:num_auths] == sub_auths[:num_auths]:
                return True
        return False

    def get_sid_trusted_domain_object(self, object_name):
        """Returns SID for the trusted domain object (user or group only)"""
        if not self.domain:
            # our domain is not configured or self.is_configured() never run
            return None
        if not self._domains:
            self._domains = self.get_trusted_domains()
        if len(self._domains) == 0:
            # Our domain is configured but no trusted domains are configured
            return None

        components = normalize_name(object_name)
        if not ('domain' in components or 'flatname' in components):
            # No domain or realm specified, ambiguous search
            return False

        entry = None
        if 'domain' in components and components['domain'] in self._domains:
            # Now we have a name to check against our list of trusted domains
            entry = self.resolve_against_gc(components['domain'], components['name'])
        elif 'flatname' in components:
            # Flatname was specified, traverse through the list of trusted
            # domains first to find the proper one
            for domain in self._domains:
                if self._domains[domain][0] == components['flatname']:
                    entry = self.resolve_against_gc(domain, components['name'])
                    if entry:
                        break
        if entry:
            try:
                test_sid = security.dom_sid(entry)
                return unicode(test_sid)
            except TypeError, e:
                return False
        return False

    def __sid_to_str(self, sid):
        """
        Converts binary SID to string representation
        Returns unicode string
        """
        sid_rev_num = ord(sid[0])
        number_sub_id = ord(sid[1])
        ia = struct.unpack('!Q','\x00\x00'+sid[2:8])[0]
        subs = [
            struct.unpack('<I',sid[8+4*i:12+4*i])[0]
            for i in range(number_sub_id)
        ]
        return u'S-%d-%d-%s' % ( sid_rev_num, ia, '-'.join([str(s) for s in subs]),)

    def __extract_trusted_auth(self, info):
        """
        Returns in clear trusted domain account credentials
        """
        clear = None
        auth = drsblobs.trustAuthInOutBlob()
        auth.__ndr_unpack__(info['auth'])
        auth_array = auth.current.array[0]
        if auth_array.AuthType == lsa.TRUST_AUTH_TYPE_CLEAR:
            clear = ''.join(map(chr, auth_array.AuthInfo.password)).decode('utf-16-le')
        return clear

    def __kinit_as_trusted_account(self, info, password):
        """
        Initializes ccache with trusted domain account credentials.

        Applies session code defaults for ccache directory and naming prefix.
        Session code uses krbccache_prefix+<pid>, we use
        krbccache_prefix+<TD>+<domain netbios name> so there is no clash

        Returns tuple (ccache name, principal) where (None, None) signifes an error
        on ccache initialization
        """
        ccache_name = os.path.join(krbccache_dir, "%sTD%s" % (krbccache_prefix, info['name'][0]))
        principal = '%s$@%s' % (self.flatname, info['dns_domain'].upper())
        (stdout, stderr, returncode) = ipautil.run(['/usr/bin/kinit', principal],
                                                   env={'KRB5CCNAME':ccache_name},
                                                   stdin=password, raiseonerr=False)
        if returncode == 0:
            return (ccache_name, principal)
        else:
            if returncode == 1:
                raise errors.ACIError(
                   info=_("KDC for %(domain)s denied trust account for IPA domain with a message '%(message)s'") %
                        dict(domain=info['dns_domain'],message=stderr.strip()))
            return (None, None)

    def resolve_against_gc(self, domain, name):
        """
        Resolves `name' against trusted domain `domain' using Global Catalog
        Returns SID of the `name' or None
        """
        entry = None
        sid = None
        info = self.__retrieve_trusted_domain_gc_list(domain)
        if not info:
            return None
        for (host, port) in info['gc']:
            entry = self.__resolve_against_gc(info, host, port, name)
            if entry:
                break

        if entry:
            l = len(entry)
            if l > 2:
                # Treat non-unique entries as invalid
                return None
            sid = self.__sid_to_str(entry[0][1]['objectSid'][0])
        return sid

    def __resolve_against_gc(self, info, host, port, name):
        """
        Actual resolution against LDAP server, using SASL GSSAPI authentication
        Returns LDAP result or None
        """
        conn = IPAdmin(host=host, port=port)
        auth = self.__extract_trusted_auth(info)
        if auth:
            (ccache_name, principal) = self.__kinit_as_trusted_account(info, auth)
            if ccache_name:
                cb_info = dict()
                # pass empty dict, SASL GSSAPI is able to get all from the ccache
                sasl_auth = _ldap.sasl.sasl(cb_info,'GSSAPI')
                old_ccache = os.environ.get('KRB5CCNAME')
                os.environ["KRB5CCNAME"] = ccache_name
                # OPT_X_SASL_NOCANON is used to avoid hard requirement for PTR
                # records pointing back to the same host name
                conn.set_option(_ldap.OPT_X_SASL_NOCANON, _ldap.OPT_ON)
                conn.sasl_interactive_bind_s(None, sasl_auth)
                base = DN(*map(lambda p: ('dc', p), info['dns_domain'].split('.')))
                # We don't use conn.getEntry() because it will attempt to fetch schema from GC and that will fail
                filterstr = conn.encode('(&(sAMAccountName=%(name)s)(|(objectClass=user)(objectClass=group)))' % dict(name=name))
                attrlist = conn.encode(['sAMAccountName', 'sAMAccountType', 'objectSid', 'groupType', 'description'])
                entry = conn.conn.search_s(str(base), _ldap.SCOPE_SUBTREE, filterstr, attrlist, 0)
                os.environ["KRB5CCNAME"] = old_ccache
                return entry

    def __retrieve_trusted_domain_gc_list(self, domain):
        """
        Retrieves domain information and preferred GC list
        Returns dictionary with following keys
             name       -- NetBIOS name of the trusted domain
             dns_domain -- DNS name of the trusted domain
             auth       -- encrypted credentials for trusted domain account
             gc         -- array of tuples (server, port) for Global Catalog
        """
        if domain in self._info:
            return self._info[domain]

        if not self._creds:
            self._parm = param.LoadParm()
            self._parm.load(os.path.join(ipautil.SHARE_DIR,"smb.conf.empty"))
            self._parm.set('netbios name', self.flatname)
            self._creds = credentials.Credentials()
            self._creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
            self._creds.guess(self._parm)
            self._creds.set_workstation(self.flatname)

        netrc = net.Net(creds=self._creds, lp=self._parm)
        finddc_error = None
        result = None
        try:
            result = netrc.finddc(domain=domain, flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_GC | nbt.NBT_SERVER_CLOSEST)
        except RuntimeError, e:
            finddc_error = e

        info = dict()
        info['auth'] = self._domains[domain][2]
        servers = []
        if result:
            info['name'] = unicode(result.domain_name)
            info['dns_domain'] = unicode(result.dns_domain)
            servers = [(unicode(result.pdc_dns_name), 3268)]
        else:
            info['name'] = self._domains[domain]
            info['dns_domain'] = domain
            # Retrieve GC servers list
            gc_name = '_gc._tcp.%s.' % info['dns_domain']

            try:
                answers = resolver.query(gc_name, rdatatype.SRV)
            except DNSException, e:
                answers = []

            for answer in answers:
                server = str(answer.target).rstrip(".")
                servers.append((server, answer.port))

        info['gc'] = servers

        # Both methods should not fail at the same time
        if finddc_error and len(info['gc']) == 0:
            raise assess_dcerpc_exception(message=str(finddc_error))

        self._info[domain] = info
        return info


class TrustDomainInstance(object):

    def __init__(self, hostname, creds=None):
        self.parm = param.LoadParm()
        self.parm.load(os.path.join(ipautil.SHARE_DIR,"smb.conf.empty"))
        if len(hostname) > 0:
            self.parm.set('netbios name', hostname)
        self.creds = creds
        self.hostname = hostname
        self.info = {}
        self._pipe = None
        self._policy_handle = None
        self.read_only = False

    def __gen_lsa_connection(self, binding):
       if self.creds is None:
           raise errors.RequirementError(name=_('CIFS credentials object'))
       try:
           result = lsa.lsarpc(binding, self.parm, self.creds)
           return result
       except RuntimeError, (num, message):
           raise assess_dcerpc_exception(num=num, message=message)

    def __init_lsa_pipe(self, remote_host):
        """
        Try to initialize connection to the LSA pipe at remote host.
        This method tries consequently all possible transport options
        and selects one that works. See __gen_lsa_bindings() for details.

        The actual result may depend on details of existing credentials.
        For example, using signing causes NO_SESSION_KEY with Win2K8 and
        using kerberos against Samba with signing does not work.
        """
        # short-cut: if LSA pipe is initialized, skip completely
        if self._pipe:
            return

        attempts = 0
        bindings = self.__gen_lsa_bindings(remote_host)
        for binding in bindings:
            try:
                self._pipe = self.__gen_lsa_connection(binding)
                if self._pipe:
                    break
            except errors.ACIError, e:
                attempts = attempts + 1

        if self._pipe is None and attempts == len(bindings):
            raise errors.ACIError(
                info=_('CIFS server %(host)s denied your credentials') % dict(host=remote_host))

        if self._pipe is None:
            raise errors.RemoteRetrieveError(
                reason=_('Cannot establish LSA connection to %(host)s. Is CIFS server running?') % dict(host=remote_host))
        self.binding = binding

    def __gen_lsa_bindings(self, remote_host):
        """
        There are multiple transports to issue LSA calls. However, depending on a
        system in use they may be blocked by local operating system policies.
        Generate all we can use. __init_lsa_pipe() will try them one by one until
        there is one working.

        We try NCACN_NP before NCACN_IP_TCP and signed sessions before unsigned.
        """
        transports = (u'ncacn_np', u'ncacn_ip_tcp')
        options = ( u',', u'')
        binding_template=lambda x,y,z: u'%s:%s[%s]' % (x, y, z)
        return [binding_template(t, remote_host, o) for t in transports for o in options]

    def retrieve_anonymously(self, remote_host, discover_srv=False):
        """
        When retrieving DC information anonymously, we can't get SID of the domain
        """
        netrc = net.Net(creds=self.creds, lp=self.parm)
        try:
            if discover_srv:
                result = netrc.finddc(domain=remote_host, flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS)
            else:
                result = netrc.finddc(address=remote_host, flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS)
        except RuntimeError, e:
            raise assess_dcerpc_exception(message=str(e))

        if not result:
            return False
        self.info['name'] = unicode(result.domain_name)
        self.info['dns_domain'] = unicode(result.dns_domain)
        self.info['dns_forest'] = unicode(result.forest)
        self.info['guid'] = unicode(result.domain_uuid)
        self.info['dc'] = unicode(result.pdc_dns_name)

        # Netlogon response doesn't contain SID of the domain.
        # We need to do rootDSE search with LDAP_SERVER_EXTENDED_DN_OID control to reveal the SID
        ldap_uri = 'ldap://%s' % (result.pdc_dns_name)
        conn = _ldap.initialize(ldap_uri)
        conn.set_option(_ldap.OPT_SERVER_CONTROLS, [ExtendedDNControl()])
        result = None
        try:
            (objtype, res) = conn.search_s('', _ldap.SCOPE_BASE)[0]
            result = res['defaultNamingContext'][0]
            self.info['dns_hostname'] = res['dnsHostName'][0]
        except _ldap.LDAPError, e:
            root_logger.error(
                "LDAP error when connecting to %(host)s: %(error)s" %
                    dict(host=unicode(result.pdc_name), error=str(e)))

        if result:
           self.info['sid'] = self.parse_naming_context(result)
        return True

    def parse_naming_context(self, context):
        naming_ref = re.compile('.*<SID=(S-.*)>.*')
        return naming_ref.match(context).group(1)

    def retrieve(self, remote_host):
        self.__init_lsa_pipe(remote_host)

        objectAttribute = lsa.ObjectAttribute()
        objectAttribute.sec_qos = lsa.QosInfo()
        try:
            self._policy_handle = self._pipe.OpenPolicy2(u"", objectAttribute, security.SEC_FLAG_MAXIMUM_ALLOWED)
            result = self._pipe.QueryInfoPolicy2(self._policy_handle, lsa.LSA_POLICY_INFO_DNS)
        except RuntimeError, (num, message):
            raise assess_dcerpc_exception(num=num, message=message)

        self.info['name'] = unicode(result.name.string)
        self.info['dns_domain'] = unicode(result.dns_domain.string)
        self.info['dns_forest'] = unicode(result.dns_forest.string)
        self.info['guid'] = unicode(result.domain_guid)
        self.info['sid'] = unicode(result.sid)
        self.info['dc'] = remote_host

    def generate_auth(self, trustdom_secret):
        def arcfour_encrypt(key, data):
            c = RC4.RC4(key)
            return c.update(data)
        def string_to_array(what):
            blob = [0] * len(what)

            for i in range(len(what)):
                blob[i] = ord(what[i])
            return blob

        password_blob = string_to_array(trustdom_secret.encode('utf-16-le'))

        clear_value = drsblobs.AuthInfoClear()
        clear_value.size = len(password_blob)
        clear_value.password = password_blob

        clear_authentication_information = drsblobs.AuthenticationInformation()
        clear_authentication_information.LastUpdateTime = samba.unix2nttime(int(time.time()))
        clear_authentication_information.AuthType = lsa.TRUST_AUTH_TYPE_CLEAR
        clear_authentication_information.AuthInfo = clear_value

        authentication_information_array = drsblobs.AuthenticationInformationArray()
        authentication_information_array.count = 1
        authentication_information_array.array = [clear_authentication_information]

        outgoing = drsblobs.trustAuthInOutBlob()
        outgoing.count = 1
        outgoing.current = authentication_information_array

        confounder = [3]*512
        for i in range(512):
            confounder[i] = random.randint(0, 255)

        trustpass = drsblobs.trustDomainPasswords()
        trustpass.confounder = confounder

        trustpass.outgoing = outgoing
        trustpass.incoming = outgoing

        trustpass_blob = ndr_pack(trustpass)

        encrypted_trustpass = arcfour_encrypt(self._pipe.session_key, trustpass_blob)

        auth_blob = lsa.DATA_BUF2()
        auth_blob.size = len(encrypted_trustpass)
        auth_blob.data = string_to_array(encrypted_trustpass)

        auth_info = lsa.TrustDomainInfoAuthInfoInternal()
        auth_info.auth_blob = auth_blob
        self.auth_info = auth_info



    def establish_trust(self, another_domain, trustdom_secret):
        """
        Establishes trust between our and another domain
        Input: another_domain -- instance of TrustDomainInstance, initialized with #retrieve call
               trustdom_secret -- shared secred used for the trust
        """
        self.generate_auth(trustdom_secret)

        info = lsa.TrustDomainInfoInfoEx()
        info.domain_name.string = another_domain.info['dns_domain']
        info.netbios_name.string = another_domain.info['name']
        info.sid = security.dom_sid(another_domain.info['sid'])
        info.trust_direction = lsa.LSA_TRUST_DIRECTION_INBOUND | lsa.LSA_TRUST_DIRECTION_OUTBOUND
        info.trust_type = lsa.LSA_TRUST_TYPE_UPLEVEL
        info.trust_attributes = lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE

        try:
            dname = lsa.String()
            dname.string = another_domain.info['dns_domain']
            res = self._pipe.QueryTrustedDomainInfoByName(self._policy_handle, dname, lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO)
            self._pipe.DeleteTrustedDomain(self._policy_handle, res.info_ex.sid)
        except RuntimeError, e:
            pass
        try:
            trustdom_handle = self._pipe.CreateTrustedDomainEx2(self._policy_handle, info, self.auth_info, security.SEC_STD_DELETE)
        except RuntimeError, (num, message):
            raise assess_dcerpc_exception(num=num, message=message)

        try:
            infoclass = lsa.TrustDomainInfoSupportedEncTypes()
            infoclass.enc_types = security.KERB_ENCTYPE_RC4_HMAC_MD5
            infoclass.enc_types |= security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
            infoclass.enc_types |= security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96
            self._pipe.SetInformationTrustedDomain(trustdom_handle, lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES, infoclass)
        except RuntimeError, e:
            pass

    def verify_trust(self, another_domain):
        def retrieve_netlogon_info_2(domain, function_code, data):
            try:
                netr_pipe = netlogon.netlogon(domain.binding, domain.parm, domain.creds)
                result = netr_pipe.netr_LogonControl2Ex(logon_server=None,
                                           function_code=function_code,
                                           level=2,
                                           data=data
                                           )
                return result
            except RuntimeError, (num, message):
                raise assess_dcerpc_exception(num=num, message=message)

        result = retrieve_netlogon_info_2(self,
                                          netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                          another_domain.info['dns_domain'])
        if (result and (result.flags and netlogon.NETLOGON_VERIFY_STATUS_RETURNED)):
            # netr_LogonControl2Ex() returns non-None result only if overall call
            # result was WERR_OK which means verification was correct.
            # We only check that it was indeed status for verification process
            return True
        return False

class TrustDomainJoins(object):
    def __init__(self, api):
        self.api = api
        self.local_domain = None
        self.remote_domain = None

        domain_validator = DomainValidator(api)
        self.configured = domain_validator.is_configured()

        if self.configured:
            self.local_flatname = domain_validator.flatname
            self.local_dn = domain_validator.dn
            self.__populate_local_domain()

    def __populate_local_domain(self):
        # Initialize local domain info using kerberos only
        ld = TrustDomainInstance(self.local_flatname)
        ld.creds = credentials.Credentials()
        ld.creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
        ld.creds.guess(ld.parm)
        ld.creds.set_workstation(ld.hostname)
        ld.retrieve(installutils.get_fqdn())
        self.local_domain = ld

    def __populate_remote_domain(self, realm, realm_server=None, realm_admin=None, realm_passwd=None):
        def get_instance(self):
            # Fetch data from foreign domain using password only
            rd = TrustDomainInstance('')
            rd.parm.set('workgroup', self.local_domain.info['name'])
            rd.creds = credentials.Credentials()
            rd.creds.set_kerberos_state(credentials.DONT_USE_KERBEROS)
            rd.creds.guess(rd.parm)
            return rd

        rd = get_instance(self)
        rd.creds.set_anonymous()
        rd.creds.set_workstation(self.local_domain.hostname)
        if realm_server is None:
            rd.retrieve_anonymously(realm, discover_srv=True)
        else:
            rd.retrieve_anonymously(realm_server, discover_srv=False)
        rd.read_only = True
        if realm_admin and realm_passwd:
            if 'name' in rd.info:
                names = realm_admin.split('\\')
                if len(names) > 1:
                    # realm admin is in DOMAIN\user format
                    # strip DOMAIN part as we'll enforce the one discovered
                    realm_admin = names[-1]
                auth_string = u"%s\%s%%%s" % (rd.info['name'], realm_admin, realm_passwd)
                td = get_instance(self)
                td.creds.parse_string(auth_string)
                td.creds.set_workstation(self.local_domain.hostname)
                if realm_server is None:
                    # we must have rd.info['dns_hostname'] then, part of anonymous discovery
                    td.retrieve(rd.info['dns_hostname'])
                else:
                    td.retrieve(realm_server)
                td.read_only = False
                self.remote_domain = td
                return
        # Otherwise, use anonymously obtained data
        self.remote_domain = rd

    def join_ad_full_credentials(self, realm, realm_server, realm_admin, realm_passwd):
        if not self.configured:
            return None

        self.__populate_remote_domain(realm, realm_server, realm_admin, realm_passwd)
        if not self.remote_domain.read_only:
            trustdom_pass = samba.generate_random_password(128, 128)
            self.remote_domain.establish_trust(self.local_domain, trustdom_pass)
            self.local_domain.establish_trust(self.remote_domain, trustdom_pass)
            result = self.remote_domain.verify_trust(self.local_domain)
            return dict(local=self.local_domain, remote=self.remote_domain, verified=result)
        return None

    def join_ad_ipa_half(self, realm, realm_server, trustdom_passwd):
        if not self.configured:
            return None

        self.__populate_remote_domain(realm, realm_server, realm_passwd=None)
        self.local_domain.establish_trust(self.remote_domain, trustdom_passwd)
        return dict(local=self.local_domain, remote=self.remote_domain, verified=False)
