#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

from io import StringIO
from ldap import SCOPE_SUBTREE
from ldif import LDIFParser
import logging
import os
import pwd
import shutil
import six
import tempfile
import time
import uuid
import base64

from ipalib import api
from ipalib import errors
from ipalib import constants
from ipalib.errors import NetworkError
from ipalib.install import certmonger, sysrestore
from ipaplatform import services
from ipaplatform.constants import constants as platformconstants
from ipaplatform.tasks import tasks
from ipaplatform.paths import paths
from ipapython import ipautil, ipaldap
from ipapython import dogtag
from ipapython.admintool import ScriptError
from ipapython.certdb import (IPA_CA_TRUST_FLAGS,
                              EXTERNAL_CA_TRUST_FLAGS)
from ipapython.dn import DN
from ipapython.kerberos import Principal
from ipaserver.dns_data_management import IPA_DEFAULT_GC_SRV_REC
from ipaserver.dns_data_management import IPADomainIsNotManagedByIPAError
from ipaserver.install import certs
from ipaserver.install import installutils
from ipaserver.install import service
from ipaserver.install.dsinstance import DS_USER, DS_GROUP
from ipaserver.install.dsinstance import (
    find_server_root,
    config_dirname,
    schema_dirname,
    remove_ds_instance,
    get_ds_instances,
    is_ds_running,
)
from ipapython.dnsutil import DNSName
from lib389 import DirSrv
from lib389.idm.ipadomain import IpaDomain
from lib389.instance.options import General2Base, Slapd2Base
from lib389.instance.setup import SetupDs


logger = logging.getLogger(__name__)

if six.PY3:
    unicode = str

GC_SCHEMA_FILES = ("00-ad-schema-2016.ldif",)

ALL_SCHEMA_FILES = GC_SCHEMA_FILES

GC_SERVER_ID = "GLOBAL-CATALOG"
GC_SERVICE_NAME = "globalcatalog"
GC_PORT = 3268
GC_SECURE_PORT = 3269


def check_ports():
    """
    Check if Global Catalog server ports are open.

    Returns a tuple with two booleans, one for unsecure port 3268 and one for
    secure port 3269. True means that the port is free, False means that the
    port is taken.
    """
    gc_unsecure = not ipautil.host_port_open(None, GC_PORT)
    gc_secure = not ipautil.host_port_open(None, GC_SECURE_PORT)
    return (gc_unsecure, gc_secure)


def is_gc_configured():
    """
    Using the state and index install files determine if Global Catalog
    is already configured.
    """
    sstore = sysrestore.StateFile(paths.SYSRESTORE)
    return sstore.has_state(GC_SERVICE_NAME)


class GCInstance(service.Service):
    def __init__(
        self,
        realm_name=None,
        domain_name=None,
        fstore=None,
        domainlevel=None,
        config_ldif=None,
    ):
        super(GCInstance, self).__init__(
            GC_SERVICE_NAME,
            service_desc="global catalog server",
            fstore=fstore,
            service_prefix=u"ldap",
            keytab=paths.DS_KEYTAB,
            service_user=DS_USER,
            realm_name=realm_name,
        )
        self.nickname = "Server-Cert"
        self.sub_dict = None
        self.domain = domain_name
        self.pkcs12_info = None
        self.cacert_name = None
        self.ca_is_configured = True
        self.cert = None
        self.ca_subject = None
        self.subject_base = None
        self.open_ports = []
        self.config_ldif = config_ldif  # updates for dse.ldif
        self.domainlevel = domainlevel
        if realm_name:
            self.suffix = ipautil.realm_to_suffix(self.realm)
            self.__setup_sub_dict()
        else:
            self.suffix = DN()
        self.serverid = GC_SERVER_ID
        self.conn = None

    subject_base = ipautil.dn_attribute_property("_subject_base")

    # GC uses special three-element SPN
    @property
    def principal(self):
        if any(attr is None for attr in (self.realm, self.fqdn, self.domain,
                                         self.service_prefix)):
            return None

        return unicode(Principal(
            (self.service_prefix, self.fqdn, self.domain), realm=self.realm))

    def __common_setup(self):
        self.step("creating global catalog instance", self.__create_instance)
        self.step("configure autobind for root", self.__root_autobind)
        self.step("Enable objectGUID generator",
                  self.__add_objectguid_generator)
        self.step("stopping global catalog", self.__stop_instance)
        self.step("updating configuration in dse.ldif", self.__update_dse_ldif)
        self.step("starting global catalog", self.__start_instance)
        self.step("adding default schema", self.__add_default_schemas)
        self.step("creating indices", self.__create_indices)
        self.step("add global catalog service principal aliases",
                  self.__add_service_alias)
        self.step("configure dirsrv ccache and keytab",
                  self.configure_systemd_ipa_env)
        self.step("enabling SASL mapping fallback",
                  self.__enable_sasl_mapping_fallback)

    def __common_post_setup(self):
        self.step("configuring global catalog to start on boot", self.__enable)

    def init_info(
        self,
        realm_name,
        fqdn,
        domain_name,
        dm_password,
        subject_base,
        ca_subject,
        pkcs12_info,
        ca_file=None,
    ):
        self.realm = realm_name.upper()
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.fqdn = fqdn
        self.ldap_uri = ipaldap.get_ldap_uri(realm="GLOBAL.CATALOG",
                                             protocol='ldapi')
        self.dm_password = dm_password
        self.domain = domain_name
        self.subject_base = subject_base
        self.ca_subject = ca_subject
        self.pkcs12_info = pkcs12_info
        if pkcs12_info:
            self.ca_is_configured = False
        self.ca_file = ca_file

        self.__setup_sub_dict()

    def create_instance(
        self,
        realm_name,
        fqdn,
        domain_name,
        dm_password,
        pkcs12_info=None,
        subject_base=None,
        ca_subject=None,
        ca_file=None,
        populate=False
    ):
        self.init_info(
            realm_name,
            fqdn,
            domain_name,
            dm_password,
            subject_base,
            ca_subject,
            pkcs12_info,
            ca_file=ca_file,
        )

        self.__common_setup()
        self.step("restarting global catalog", self.__restart_instance)
        self.step("adding sasl mappings to the global catalog",
                  self.__configure_sasl_mappings)
        self.step("adding default layout", self.__add_default_layout)
        self.step("adding default access controls", self.__add_default_aci)
        self.step("enabling global catalog", self.__enable_instance)
        self.__common_post_setup()
        self.step("configuring TLS for global catalog", self.__enable_ssl)
        self.step("importing CA certificates from LDAP",
                  self.__import_ca_certs)
        self.step("restarting global catalog", self.__restart_instance)
        if populate:
            self.step("Initializing global catalog content", self.__populate)
        self.start_creation()

    def __configure_sasl_mappings(self):
        # we need to remove any existing SASL mappings in the directory as
        # otherwise they may conflict.
        try:
            res = self.conn.get_entries(
                DN(("cn", "mapping"), ("cn", "sasl"), ("cn", "config")),
                api.Backend.ldap2.SCOPE_ONELEVEL,
                "(objectclass=nsSaslMapping)",
            )
            for r in res:
                try:
                    self.conn.delete_entry(r)
                except Exception as e:
                    logger.critical(
                        "Error during SASL mapping removal: %s", e)
                    raise
        except Exception as e:
            logger.critical("Error while enumerating SASL mappings %s", e)
            raise

        entry = self.conn.make_entry(
            DN(
                ("cn", "Read-Only Principal"),
                ("cn", "mapping"),
                ("cn", "sasl"),
                ("cn", "config"),
            ),
            objectclass=["top", "nsSaslMapping"],
            cn=["Read-Only Principal"],
            nsSaslMapRegexString=[r'^[^:]+$'],
            nsSaslMapBaseDNTemplate=[DN(('cn', 'configuration')) +
                                     self.suffix],
            nsSaslMapFilterTemplate=['(uid=read-only-principal)'],
            nsSaslMapPriority=['10'],
        )
        self.conn.add_entry(entry)

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # At the end of the installation ipa-gc-install will enable the
        # globalcatalog svc which takes care of starting/stopping gc
        self.disable()

    def __setup_sub_dict(self):
        from samba.dcerpc import security
        from samba.ndr import ndr_pack

        server_root = find_server_root()
        trustconfig = api.Command.trustconfig_show()['result']
        domainguid = base64.b64encode(
            uuid.UUID(trustconfig['ipantdomainguid'][0]).bytes
        ).decode('utf-8')
        domainsid = base64.b64encode(ndr_pack(
            security.dom_sid(trustconfig['ipantsecurityidentifier'][0]))
        ).decode('utf-8')

        self.sub_dict = dict(
            FQDN=self.fqdn,
            SERVERID=self.serverid,
            PASSWORD=self.dm_password,
            RANDOM_PASSWORD=ipautil.ipa_generate_password(),
            SUFFIX=self.suffix,
            REALM=self.realm,
            USER=DS_USER,
            SERVER_ROOT=server_root,
            DOMAIN=self.domain,
            TIME=int(time.time()),
            HOST=self.fqdn,
            ESCAPED_SUFFIX=str(self.suffix),
            GROUP=DS_GROUP,
            DOMAIN_LEVEL=self.domainlevel,
            MAX_DOMAIN_LEVEL=constants.MAX_DOMAIN_LEVEL,
            MIN_DOMAIN_LEVEL=constants.MIN_DOMAIN_LEVEL,
            NAME=DN(self.suffix)[0].value,
            DOMAINGUID=domainguid,
            DOMAINSID=domainsid
        )

    def __create_instance(self):
        self.backup_state("serverid", self.serverid)

        # The new installer is api driven. We can pass it a log function
        # and it will use it. Because of this, we can pass verbose true,
        # and allow our logger to control the display based on level.
        sds = SetupDs(verbose=True, dryrun=False, log=logger)

        # General environmental options.
        general_options = General2Base(logger)
        general_options.set('strict_host_checking', False)
        # Check that our requested configuration is actually valid ...
        general_options.verify()
        general = general_options.collect()

        # Slapd options, ie instance name.
        slapd_options = Slapd2Base(logger)
        slapd_options.set('instance_name', self.serverid)
        slapd_options.set('root_password', self.dm_password)
        slapd_options.set('port', GC_PORT)
        slapd_options.set('secure_port', GC_SECURE_PORT)
        slapd_options.verify()
        slapd = slapd_options.collect()

        # Create userroot. Note that the new install does NOT
        # create sample entries, so this is *empty*.
        userroot = {
            'cn': 'userRoot',
            'nsslapd-suffix': self.suffix.ldap_text()
        }

        backends = [userroot]

        sds.create_from_args(general, slapd, backends, None)

        # Now create the new domain root object in the format that IPA expects.
        # Get the instance ....

        inst = DirSrv(verbose=True, external_log=logger)
        inst.local_simple_allocate(
            serverid=self.serverid,
            ldapuri=self.ldap_uri,
            password=self.dm_password
        )

        # local_simple_allocate() configures LDAPI but doesn't set up the
        # DirSrv object to use LDAPI. Modify the DirSrv() object to use
        # LDAPI with password bind. autobind is not available, yet.
        inst.ldapi_enabled = 'on'
        inst.ldapi_socket = paths.SLAPD_INSTANCE_SOCKET_TEMPLATE % (
            self.serverid
        )
        inst.ldapi_autobind = 'off'

        # This actually opens the conn and binds.
        inst.open()

        try:
            ipadomain = IpaDomain(inst, dn=self.suffix.ldap_text())
            ipadomain.create(properties={
                'dc': self.realm.split('.')[0].lower(),
                'info': 'IPA V2.0',
            })
        finally:
            inst.close()

        # Done!
        logger.debug("completed creating global catalog instance")

    def __update_dse_ldif(self):
        """
        This method updates dse.ldif right after instance creation. This is
        supposed to allow admin modify configuration of the DS which has to be
        done before IPA is fully installed (for example: settings for
        replication on replicas)
        DS must be turned off.
        """
        dse_filename = os.path.join(
            paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % self.serverid,
            "dse.ldif"
        )

        with tempfile.NamedTemporaryFile(
                mode="w", delete=False) as new_dse_ldif:
            temp_filename = new_dse_ldif.name
            with open(dse_filename, "r") as input_file:
                parser = installutils.ModifyLDIF(input_file, new_dse_ldif)
                parser.replace_value(
                    "cn=config,cn=ldbm database,cn=plugins,cn=config",
                    "nsslapd-db-locks",
                    [b"50000"],
                )
                if self.config_ldif:
                    # parse modifications from ldif file supplied by the admin
                    with open(self.config_ldif, "r") as config_ldif:
                        parser.modifications_from_ldif(config_ldif)
                parser.parse()
            new_dse_ldif.flush()
        shutil.copy2(temp_filename, dse_filename)
        tasks.restore_context(dse_filename)
        try:
            os.remove(temp_filename)
        except OSError as e:
            logger.debug("Failed to clean temporary file: %s", e)

    def __add_default_schemas(self):
        pent = pwd.getpwnam(DS_USER)
        for schema_fname in GC_SCHEMA_FILES:
            target_fname = schema_dirname(self.serverid) + schema_fname
            shutil.copyfile(
                os.path.join(paths.USR_SHARE_IPA_GC_DIR, schema_fname),
                target_fname
            )
            os.chmod(target_fname, 0o440)  # read access for dirsrv user/group
            os.chown(target_fname, pent.pw_uid, pent.pw_gid)

    def start(self, *args, **kwargs):
        super(GCInstance, self).start(*args, **kwargs)
        self.conn = ipaldap.LDAPClient(self.ldap_uri)
        self.conn.external_bind()

    def stop(self, *args, **kwargs):
        if self.conn:
            self.conn.close()
            self.conn = None
        super(GCInstance, self).stop(*args, **kwargs)

    def restart(self, instance=GC_SERVER_ID):
        if self.conn:
            self.conn.close()
            self.conn = None
        try:
            super(GCInstance, self).restart(instance)
            if not is_ds_running(instance):
                logger.critical(
                    "Failed to restart the global catalog. "
                    "See the installation log for details."
                )
                raise ScriptError()
        except SystemExit as e:
            raise e
        except Exception as e:
            # TODO: roll back here?
            logger.critical(
                "Failed to restart the global catalog (%s). "
                "See the installation log for details.", e
            )
        self.conn = ipaldap.LDAPClient(self.ldap_uri)
        self.conn.external_bind()

    def __start_instance(self):
        self.start(self.serverid)

    def __stop_instance(self):
        self.stop(self.serverid)

    def __restart_instance(self):
        self.restart(self.serverid)

    def __populate(self):
        from ipaserver.globalcatalog.transfo import GCTransformer

        class AddLDIF(LDIFParser):
            def __init__(self, input, conn):
                LDIFParser.__init__(self, StringIO(input))
                self._conn = conn

            def handle(self, dn, entry):
                try:
                    newentry = self._conn.make_entry(DN(dn), entry)
                    self._conn.add_entry(newentry)
                except errors.DuplicateEntry:
                    logger.debug("Entry %s already exists", dn)

        ldapuri_ds = ipaldap.get_ldap_uri(realm=api.env.realm,
                                          protocol='ldapi')
        ds_ldap = ipaldap.LDAPClient(ldapuri_ds)
        ds_ldap.external_bind()

        gc = GCTransformer(api, ds_ldap)

        attrs = [
            'objectclass',
            'cn',
            'displayname',
            'gidnumber',
            'givenname',
            'homedirectory',
            'ipantsecurityidentifier',
            'ipauniqueid',
            'krbcanonicalname',
            'krbprincipalname',
            'mail',
            'memberof',
            'sn',
            'uid',
            'uidnumber',
        ]

        users, truncated = ds_ldap.find_entries(
            '(objectclass=person)', attrs,
            DN(api.env.container_user, api.env.basedn), scope=SCOPE_SUBTREE,
            time_limit=0, size_limit=-1)

        if truncated:
            logger.info("Initialization of Global Catalog may be incomplete, "
                        "number of users exceeded size limit")

        for entry in users:
            ldif_add = gc.create_ldif_user(entry)
            parser = AddLDIF(ldif_add, self.conn)
            parser.parse()

        attrs = [
            'objectclass',
            'cn',
            'ipauniqueid',
            'ipantsecurityidentifier',
            'member',
            'ipaexternalmember',
        ]

        groups, truncated = ds_ldap.find_entries(
            '(objectclass=groupofnames)', attrs,
            DN(api.env.container_group, api.env.basedn), scope=SCOPE_SUBTREE,
            time_limit=0, size_limit=-1)
        if truncated:
            logger.info("Initialization of Global Catalog may be incomplete, "
                        "number of groups exceeded size limit")

        for entry in groups:
            ldif_add = gc.create_ldif_group(entry)
            parser = AddLDIF(ldif_add, self.conn)
            parser.parse()

        logger.debug("Global catalog initialized")

    def configure_systemd_ipa_env(self):
        pent = pwd.getpwnam(platformconstants.DS_USER)
        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ds-ipa-env.conf.template"
        )
        # We need to use different KRB5CCNAME than what is used by the primary
        # instance because these are two separate processes and they should not
        # overlap.
        krb5ccname = ("-".join([paths.TMP_KRB5CC,
                                self.serverid])) % pent.pw_uid
        sub_dict = dict(
            KRB5_KTNAME=paths.DS_KEYTAB,
            KRB5CCNAME=krb5ccname
        )
        conf = ipautil.template_file(template, sub_dict)

        destfile = paths.SLAPD_INSTANCE_SYSTEMD_IPA_ENV_TEMPLATE % (
            self.serverid
        )
        destdir = os.path.dirname(destfile)

        if not os.path.isdir(destdir):
            # create dirsrv-$SERVERID.service.d
            os.mkdir(destdir, 0o755)
        with open(destfile, 'w') as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(conf)
        tasks.restore_context(destfile)

        # remove variables from old /etc/sysconfig/dirsrv file
        if os.path.isfile(paths.SYSCONFIG_DIRSRV):
            self.fstore.backup_file(paths.SYSCONFIG_DIRSRV)
            ipautil.config_replace_variables(
                paths.SYSCONFIG_DIRSRV,
                removevars={'KRB5_KTNAME', 'KRB5CCNAME'}
            )
        # reload systemd to materialize new config file
        tasks.systemd_daemon_reload()

    def __enable_ssl(self):
        dirname = config_dirname(self.serverid)
        dsdb = certs.CertDB(
            self.realm,
            nssdir=dirname,
            subject_base=self.subject_base,
            ca_subject=self.ca_subject,
        )
        if self.pkcs12_info:
            if self.ca_is_configured:
                trust_flags = IPA_CA_TRUST_FLAGS
            else:
                trust_flags = EXTERNAL_CA_TRUST_FLAGS
            dsdb.create_from_pkcs12(
                self.pkcs12_info[0],
                self.pkcs12_info[1],
                ca_file=self.ca_file,
                trust_flags=trust_flags,
            )
            # rewrite the pin file with current password
            dsdb.create_pin_file()
            server_certs = dsdb.find_server_certs()
            if len(server_certs) == 0:
                raise RuntimeError(
                    "Could not find a suitable server cert in import in %s"
                    % self.pkcs12_info[0]
                )

            # We only handle one server cert
            self.nickname = server_certs[0][0]
            self.cert = dsdb.get_cert_from_db(self.nickname)

            if self.ca_is_configured:
                dsdb.track_server_cert(
                    self.nickname,
                    self.principal,
                    dsdb.passwd_fname,
                    'restart_dirsrv %s' % self.serverid,
                )

            self.add_cert_to_service()
        else:
            dsdb.create_from_cacert()
            # rewrite the pin file with current password
            dsdb.create_pin_file()
            cmd = 'restart_dirsrv %s' % self.serverid
            certmonger.request_and_wait_for_cert(
                certpath=dirname,
                storage='NSSDB',
                nickname=self.nickname,
                principal=self.principal,
                passwd_fname=dsdb.passwd_fname,
                subject=str(DN(("CN", self.fqdn), self.subject_base)),
                ca="IPA",
                profile=dogtag.DEFAULT_PROFILE,
                dns=[self.fqdn],
                post_command=cmd,
                resubmit_timeout=api.env.certmonger_wait_timeout
            )

            # restart_dirsrv in the request above restarts DS, reconnect ldap2
            if self.conn:
                self.conn.close()
            self.conn = ipaldap.LDAPClient(self.ldap_uri)
            self.conn.external_bind()

            self.cert = dsdb.get_cert_from_db(self.nickname)

        self.cacert_name = dsdb.cacert_name

        conn = ipaldap.LDAPClient(self.ldap_uri)
        conn.external_bind()

        encrypt_entry = conn.make_entry(
            DN(('cn', 'encryption'), ('cn', 'config')),
            nsSSLClientAuth=b'allowed',
            nsSSL3Ciphers=b'default',
            allowWeakCipher=b'off'
        )
        try:
            conn.update_entry(encrypt_entry)
        except errors.EmptyModlist:
            logger.debug(
                "cn=encryption,cn=config is already properly configured")

        conf_entry = conn.make_entry(
            DN(('cn', 'config')),
            # one does not simply uses '-' in variable name
            **{'nsslapd-security': b'on'}
        )
        try:
            conn.update_entry(conf_entry)
        except errors.EmptyModlist:
            logger.debug("nsslapd-security is already on")

        entry = conn.make_entry(
            DN(('cn', 'RSA'), ('cn', 'encryption'), ('cn', 'config')),
            objectclass=["top", "nsEncryptionModule"],
            cn=["RSA"],
            nsSSLPersonalitySSL=[self.nickname],
            nsSSLToken=["internal (software)"],
            nsSSLActivation=["on"],
        )
        try:
            conn.add_entry(entry)
        except errors.DuplicateEntry:
            # 389-DS >= 1.4.0 has a default entry, update it.
            conn.update_entry(entry)

        conn.unbind()

        # check for open secure port GC_SECURE_PORT from now on
        self.open_ports.append(GC_SECURE_PORT)

    def __import_ca_certs(self):
        dirname = config_dirname(self.serverid)
        dsdb = certs.CertDB(self.realm, nssdir=dirname,
                            subject_base=self.subject_base)

        with ipaldap.LDAPClient(self.ldap_uri) as conn:
            conn.external_bind()
            self.export_ca_certs_nssdb(dsdb, self.ca_is_configured, conn)

    def __add_default_layout(self):
        self._ldap_mod("gc/base/00-ad-bootstrap-template.ldif", self.sub_dict,
                       ldap_uri=self.ldap_uri)

    def __add_default_aci(self):
        self._ldap_mod("gc/base/default-aci.ldif", self.sub_dict,
                       ldap_uri=self.ldap_uri)

    def __add_objectguid_generator(self):
        self._ldap_mod("uuid-conf.ldif", ldap_uri=self.ldap_uri)
        self._ldap_mod("gc/base/objectguid.ldif", self.sub_dict,
                       ldap_uri=self.ldap_uri)

    def __enable_instance(self):
        basedn = ipautil.realm_to_suffix(self.realm)
        self.ldap_configure(self.serverid, self.fqdn, None, basedn)

    def __create_indices(self):
        self._ldap_mod("gc/base/00-ad-indices.ldif", ldap_uri=self.ldap_uri)

    def __enable_sasl_mapping_fallback(self):
        self._ldap_mod(
            "sasl-mapping-fallback.ldif", self.sub_dict,
            ldap_uri=self.ldap_uri
        )

    def __add_service_alias(self):
        # We share principal with the primary ldap service
        principal = unicode(Principal(
            (self.service_prefix, self.fqdn), realm=self.realm))
        api.Command.service_add_principal(principal, self.principal)

    def __remove_service_alias(self):
        # We share principal with the primary ldap service
        principal = unicode(Principal(
            (self.service_prefix, api.env.host),
            realm=api.env.realm))
        principal_alias = unicode(Principal(
            (self.service_prefix, api.env.host, api.env.domain),
            realm=api.env.realm))
        try:
            api.Command.service_remove_principal(principal, principal_alias)
        except errors.AttrValueNotFound:
            pass

    def __remove_gc_dns_records(self):
        # Remove all the Global Catalog DNS records
        delkw = {'del_all': True}
        domain_abs = DNSName(api.env.domain).make_absolute()
        for record in IPA_DEFAULT_GC_SRV_REC:
            try:
                api.Command.dnsrecord_del(
                    domain_abs,
                    record[0].to_text(),
                    **delkw)
            except errors.NotFound:
                pass
            except IPADomainIsNotManagedByIPAError:
                pass

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring global catalog")

        # Just eat this state if it exists
        self.restore_state("enabled")
        self.restore_state("running")

        try:
            api.Backend.ldap2.connect()
        except NetworkError:
            logger.error("Unable to connect to directory server, "
                         "you may need to remove service container and "
                         "service principal manually.")
        else:
            # Remove the DNS records for global catalog
            self.__remove_gc_dns_records()

            # Remove the service container entry
            self.ldap_remove_service_container(self.serverid, api.env.host,
                                               api.env.basedn)
            # Remove the principal entry
            self.__remove_service_alias()

        serverid = self.restore_state("serverid")
        if serverid is not None:
            self.stop_tracking_certificates(serverid)
            # Calling stop will remove the service from the services.list
            self.stop()
            logger.debug("Removing global catalog instance %s", serverid)
            try:
                remove_ds_instance(serverid)
            except ipautil.CalledProcessError:
                logger.error(
                    "Failed to remove global catalog instance. You may "
                    "need to remove instance data manually"
                )
        else:
            logger.error("Failed to remove global catalog instance. No "
                         "serverid present in sysrestore file.")

        ipautil.remove_keytab(paths.GC_KEYTAB)
        ipautil.remove_ccache(run_as=DS_USER)

        if serverid is None:
            # Remove scripts dir
            scripts = paths.VAR_LIB_DIRSRV_INSTANCE_SCRIPTS_TEMPLATE % (
                self.serverid)
            ipautil.rmtree(scripts)

            # remove systemd unit file
            unitfile = paths.SLAPD_INSTANCE_SYSTEMD_IPA_ENV_TEMPLATE % (
                self.serverid
            )
            ipautil.remove_file(unitfile)
            try:
                os.rmdir(os.path.dirname(unitfile))
            except OSError:
                # not empty
                pass

        # If any dirsrv instances remain after we've removed ours then
        # (re)start them.
        for ds_instance in get_ds_instances():
            try:
                services.knownservices.dirsrv.restart(ds_instance, wait=False)
            except Exception as e:
                logger.error(
                    "Unable to restart DS instance %s: %s", ds_instance, e
                )

    def stop_tracking_certificates(self, serverid=None):
        if serverid is None:
            serverid = self.get_state("serverid")
        if serverid is not None:
            # drop the trailing / off the config_dirname so the directory
            # will match what is in certmonger
            dirname = config_dirname(serverid)[:-1]
            dsdb = certs.CertDB(self.realm, nssdir=dirname)
            dsdb.untrack_server_cert(self.nickname)

    def __root_autobind(self):
        ldap_uri = ipaldap.get_ldap_uri(self.fqdn, port=GC_PORT)
        self._ldap_mod(
            "root-autobind.ldif",
            ldap_uri=ldap_uri,
            dm_password=self.dm_password
        )
        self.conn = ipaldap.LDAPClient(self.ldap_uri)
        self.conn.external_bind()
