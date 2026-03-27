import logging
import os
import json
import uuid

from abc import ABC
from datetime import datetime

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.dn import DN

# ipalib is unavailable during install
ANON_USER = 'WELLKNOWN/ANONYMOUS'
PKI_GSSAPI_SERVICE_NAME = 'dogtag'

logger = logging.getLogger(__name__)

_KEYTABS = [
    paths.DS_KEYTAB,
    paths.HTTP_KEYTAB,
    paths.ANON_KEYTAB,
    paths.DOGTAG_KEYTAB,
    paths.NAMED_KEYTAB,
    paths.IPA_DNSKEYSYNCD_KEYTAB,
    paths.SAMBA_KEYTAB,
]

# ANON is special and handled separately
_KEYTAB_PRINCIPALS_MAP = {
    paths.DS_KEYTAB: 'ldap',
    paths.HTTP_KEYTAB: 'HTTP',
    paths.DOGTAG_KEYTAB: PKI_GSSAPI_SERVICE_NAME,
    paths.NAMED_KEYTAB: 'DNS',
    paths.IPA_DNSKEYSYNCD_KEYTAB: 'ipa-dnskeysyncd',
    paths.SAMBA_KEYTAB: 'cifs',
}

TIMER_PREFIX = "ipa-keytab-cleaner."
TIMER_SUFFIX = ".timer"


class KeytabRecordBase(ABC):
    """Base class for Keytab Records

    Equivalent of modern @dataclass
    """

    filepath: str
    kvno: int
    principal: str

    def __init__(self, filepath: str, kvno: int, principal: str):
        assert isinstance(filepath, str)
        assert isinstance(kvno, int)
        assert isinstance(principal, str)

        self.filepath = filepath
        self.kvno = kvno
        self.principal = principal

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(" + ", ".join(
            (f"{k}={v}" for k, v in vars(self).items())
        ) + ")"

    def __str__(self) -> str:
        return self.__repr__()


class KeytabDeletion(KeytabRecordBase):
    """
    Used for IPC, ipa-keytab-cleaner@.service takes a file as an argument
    This class is used as the config file for such service, allows dumping
    the class into a json file, and retrieving object from a file.
    """

    def __eq__(self, other):
        if self is other:
            return True

        if not isinstance(other, KeytabDeletion):
            return False

        return (
            self.filepath == other.filepath
            and self.kvno == other.kvno
            and self.principal == other.principal
        )

    def __hash__(self):
        return hash((self.filepath, self.kvno, self.principal))

    @staticmethod
    def from_file(filepath: str) -> KeytabDeletion:
        with open(filepath, 'r') as f:
            return KeytabDeletion(**json.load(f))

    def to_file(self, filepath: str) -> None:
        with open(filepath, 'w') as f:
            json.dump(vars(self), f)


class KeytabEntry(KeytabRecordBase):
    """
    Utility struct for holding temporary keytab entries, retrieved through
    klist -ekt
    """

    timestamp: datetime
    enctypes: list[str]

    def __init__(
        self,
        filepath: str,
        kvno: int,
        timestamp: datetime,
        principal: str,
        enctype: str,
    ):
        assert isinstance(timestamp, datetime)
        assert isinstance(enctype, str)

        super().__init__(filepath, kvno, principal)

        self.timestamp = timestamp
        self.enctypes = [enctype]

    def valid_enctypes(self, permitted_enctypes) -> bool:
        """
        Validates that current enctypes are equal to permitted encryption
        types. Validates order as well.

        :param permitted_enctypes: Types, should be gathered through
        _get_krb_permitted_types
        :type permitted_enctypes: list[str]

        :return: Are enctypes valid?
        :rtype: bool
        """
        assert isinstance(permitted_enctypes, list)

        if len(self.enctypes) != len(permitted_enctypes):
            return False

        for e, pe in zip(self.enctypes, permitted_enctypes):
            if e != pe:
                return False

        return True

    def known_principal(self, host: str, realm: str) -> bool:
        anonymous_principal = ANON_USER + "@" + realm
        if self.principal == anonymous_principal:
            return True

        principal = host + "@" + realm
        if self.principal == principal:
            return True

        if '/' not in self.principal:
            return False

        return self.principal.rsplit('/', maxsplit=1)[1] == principal

    def as_deletion(self) -> KeytabDeletion:
        return KeytabDeletion(self.filepath, self.kvno, self.principal)


def _get_krb_permitted_types() -> list[str]:
    """
    Retrieves permitted keys as a list of strings, normalizes :special, :normal
    by removing these.

    :return: permitted keys
    :rtype: list[str]
    """
    result = ipautil.run(
        [paths.IPA_GETKEYTAB, "--permitted-enctypes"], capture_output=True
    )
    permitted_enctypes: list[str] = result.output.splitlines()

    for i in range(len(permitted_enctypes)):
        if ":" in permitted_enctypes[i]:
            permitted_enctypes[i] = permitted_enctypes[i].split(":", 1)[0]

    return permitted_enctypes


def _list_keytab(keytab: str) -> list[KeytabEntry]:
    """
    Reads keytab and gathers it's entries as a list of KeytabEntry.
    Errors are skipped and logged.

    :param keytab: Filepath
    :type keytab: str

    :return: Keytab entries in the file
    :rtype: list[KeytabEntry]
    """
    # LANG=C to override locale
    result = ipautil.run(
        [paths.KLIST, "-ekt", keytab], env={"LANG": "C"}, capture_output=True
    )
    lines: list[str] = result.output.splitlines()

    # Keytab is not guaranteed to have records ordered by KVNO
    keytab_records: list[KeytabEntry] = []

    # First skip header lines, such as KVNO Timestamp... and ----
    for line in lines[3:]:
        kvno, time, date, principal, enctype = line.strip().split(" ")

        try:
            kvno = int(kvno)
        except ValueError:
            logger.error("Error when reading kvno %s from %s", kvno, keytab)
            continue

        enctype = enctype[1:-1]  # strip (, )

        for record in keytab_records:
            if record.kvno == kvno:
                record.enctypes.append(enctype)
                break
        else:
            timestamp = time + " " + date

            try:
                timestamp = datetime.strptime(timestamp, "%m/%d/%y %H:%M:%S")
            except ValueError:
                logger.error(
                    "Error when converting timestamp %s from %s",
                    timestamp,
                    keytab,
                )
                continue

            keytab_records.append(
                KeytabEntry(keytab, kvno, timestamp, principal, enctype)
            )

    return keytab_records


def _schedule_deletion(
    keytab: KeytabEntry,
    krbmaxrenewableage: int,
) -> None:
    """
    Schedules deletion of keytab on today + krbmaxrenewableage.
    On failure deletions are repeated daily, see: ipa-keytab-cleaner@.service

    :param keytab: KeytabEntry we want to delete
    :type keytab: KeytabEntry
    :param krbmaxrenewableage: Max renewable age for all the keytab entries
    :type krbmaxrenewableage: int
    """
    # We use randomly generated file names
    filename = str(uuid.uuid4().hex)
    filepath = paths.IPA_KEYTAB_CLEANER_CONF_DIR + "/" + filename
    keytab.as_deletion().to_file(filepath)
    ipautil.run(
        [
            paths.SYSTEMD_RUN,
            '--on-active',
            str(krbmaxrenewableage),
            '--timer-property',
            'Persistent=True',
            '--unit',
            TIMER_PREFIX + filename,
            paths.SYSTEMCTL,
            'start',
            (
                paths.SYSTEMD_KEYTAB_CLEANER_SERVICE_TEMPLATE.rsplit(
                    '/', maxsplit=1
                )[1]
            )
            % filename,
        ],
    )


def _generate_keys(
    krb_principal: str,
    keytab_entries: list[tuple[str, str]],
) -> None:
    """
    Generates new keys in keytabs.

    :param krb_prinicpal: Principal for krb5.keytab
    :type krb_principal: str
    :param keytab_entries: List of tuples of (filepath, principal)
    :type keytab_entries: list[tuple[str, str]]:
    """
    if len(keytab_entries) == 0:
        return

    ipautil.run([paths.KINIT, "-kt", paths.KRB5_KEYTAB, krb_principal])

    for keytab in keytab_entries:
        keytab_filepath, principal = keytab
        ipautil.run(
            [paths.IPA_GETKEYTAB, "-p", principal, "-k", keytab_filepath],
        )

    ipautil.run([paths.KDESTROY])


def _get_files_from_directory(directory: str) -> list[str]:
    """
    Retrieves all entries from a directory or an empty list.
    Logs a warning when unable to read the directory.

    :param directory: Filepath
    :type directory: str

    :return: Entries in the directory
    :rtype: list[str]
    """
    try:
        return os.listdir(directory)
    except OSError as e:
        logger.warning("Error while processing %s: %s", directory, e)
        return []


def _get_realm_suffix(instance) -> DN:
    """
    Should behave the same way as
    ipaserver/install/krbinstance.py:get_realm_service

    :param instance: instance of Service, simply pass self when in Service
    :type instance: PlatformService
    :return: realm suffix for kerberos
    :rtype: DN
    """
    realm = instance.api.env.realm
    suffix = ipautil.realm_to_suffix(realm)
    return DN(("cn", realm), ("cn", "kerberos"), suffix)


def _get_krbmaxrenewableage(instance) -> int:
    """
    Handles ldap connection in itself if not already connected.

    :param instance: instance of Service, simply pass self when in Service
    :type instance: PlatformService
    :return: krbmaxrenewableage
    :rtype: int
    """
    ldap = instance.api.Backend.ldap2
    temporary_connect = not ldap.isconnected()
    if temporary_connect:
        ldap.connect()
    entry_attrs = ldap.get_entry(
        _get_realm_suffix(instance), ["krbmaxrenewableage"]
    )
    krbmaxrenewableage = int(entry_attrs["krbmaxrenewableage"][0])
    if temporary_connect:
        ldap.disconnect()

    return krbmaxrenewableage


def _get_systemd_scheduled_units() -> list[str]:
    result = ipautil.run([
        paths.SYSTEMCTL, 'list-timers'
    ], capture_output=True)
    lines: list[str] = result.output.splitlines()
    start_index = lines[0].find("UNIT")

    units: list[str] = []
    for line in lines[1:-3]:
        unit = line[start_index:].split(' ', maxsplit=1)[0]
        units.append(unit)

    return units


def _get_scheduled_keytabs() -> list[KeytabDeletion]:
    units = _get_systemd_scheduled_units()

    keytabs: list[KeytabDeletion] = []
    for unit in units:
        if unit.startswith(TIMER_PREFIX):
            filename = unit.replace(TIMER_PREFIX, "")
            filename = filename.replace(TIMER_SUFFIX, "")
            filepath = paths.IPA_KEYTAB_CLEANER_CONF_DIR + "/" + filename
            try:
                keytabs.append(KeytabDeletion.from_file(filepath))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(
                    'Unable to parse config file: %s, skipping: %s',
                    filepath,
                    e,
                )

    return keytabs


def cleanup_scheduled_keytab_removals() -> None:
    units = _get_systemd_scheduled_units()

    for unit in units:
        if unit.startswith(TIMER_PREFIX):
            ipautil.run([paths.SYSTEMCTL, "stop", unit])

    files = _get_files_from_directory(paths.IPA_KEYTAB_CLEANER_CONF_DIR)
    for file in files:
        try:
            filepath = os.path.join(paths.IPA_KEYTAB_CLEANER_CONF_DIR, file)
            os.unlink(filepath)
        except FileNotFoundError:
            pass


def _get_principal_by_keytab(keytab: str, host: str, realm: str) -> str:
    """Returns prinicipal based on keytab filepath

    :param keytab: Path to the keytab
    :type keytab: str
    :param host: Host
    :type host: str
    :param realm: Realm
    :type realm: str
    :return: Principal for the keytab
    :rtype: str
    """

    if keytab == paths.ANON_KEYTAB:
        return ANON_USER + "@" + realm

    entry_principal = _KEYTAB_PRINCIPALS_MAP.get(keytab, '')
    principal = host + "@" + realm
    if entry_principal != '':
        return entry_principal + "/" + principal
    else:
        return principal


def check_and_rotate_keytabs(instance, host: str, realm: str) -> bool:
    """
    Checks the encryption keys for all the keytabs, schedules removal of
    old invalid ones and generates new pairs.

    :param instance: instance of Service, simply pass self when in Service
    :type instance: PlatformService
    :param host: Host
    :type host: str
    :param realm: Realm
    :type realm: str
    :returns: True if the keys have been rotated
    :rtype: bool
    """

    krbmaxrenewableage = _get_krbmaxrenewableage(instance)
    permitted_types = _get_krb_permitted_types()

    # For generate_keys, tuples of filepath and principal
    keytab_entries: list[tuple[str, str]] = []
    scheduled_deletions = _get_scheduled_keytabs()
    for keytab in (
        *(
            os.path.join(paths.SSSD_KEYTABS_DIR, f)
            for f in _get_files_from_directory(paths.SSSD_KEYTABS_DIR)
        ),
        *_KEYTABS,
    ):
        if not os.path.isfile(keytab):
            logger.debug("filepath %s is not a file", keytab)
            continue

        try:
            items: list[KeytabEntry] = _list_keytab(keytab)
        except ipautil.CalledProcessError as e:
            logger.error(
                "File %s seems to not be a valid keytab: %s",
                keytab,
                e
            )
            items: list[KeytabEntry] = []

        invalid = False
        max_kvno = max(i.kvno for i in items)
        for i in range(len(items)):
            entry = items[i]

            if not entry.known_principal(host, realm):
                logger.debug(
                    'Skipping %s %s, unexpected prinicpal',
                    entry.filepath,
                    entry.principal
                )
                continue

            # Don't delete last KVNO if it's valid
            if entry.kvno == max_kvno and entry.valid_enctypes(permitted_types):
                continue

            # Skip already scheduled deletions
            if entry.as_deletion() in scheduled_deletions:
                logger.debug(
                    'Skipping %s %s, as it is already scheduled for deletion',
                    entry.filepath,
                    entry.kvno
                )
                continue

            invalid = True
            _schedule_deletion(entry, krbmaxrenewableage)

        if invalid:
            entry_principal = _get_principal_by_keytab(keytab, host, realm)
            entry = (keytab, entry_principal)
            keytab_entries.append(entry)

    if len(keytab_entries) == 0:
        return False

    # Read krb5 keytab, for rotation, if there are no keys well...
    krb5_items: list[KeytabEntry] = _list_keytab(paths.KRB5_KEYTAB)
    krb_principal = krb5_items[-1].principal

    # We do not handle if krb_prinicpal doesn't exist, because
    # if we can't obtain krb keytab, then we should crash...
    _generate_keys(krb_principal, keytab_entries)
    return True
