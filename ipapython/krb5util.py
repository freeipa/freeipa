from datetime import datetime
import logging
import os

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.dn import DN

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


class KeytabEntry:
    """
    Utility struct for holding keytab entries.
    """

    filepath: str
    kvno: int
    timestamp: datetime
    principal: str
    enctypes: list[str]

    def __init__(
        self,
        filepath: str,
        kvno: int,
        timestamp: datetime,
        principal: str,
        enctype: str,
    ):
        assert isinstance(filepath, str)
        assert isinstance(kvno, int)
        assert isinstance(timestamp, datetime)
        assert isinstance(principal, str)
        assert isinstance(enctype, str)

        self.filepath = filepath
        self.kvno = kvno
        self.timestamp = timestamp
        self.principal = principal
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

    def __repr__(self):
        return f"{self.__class__.__name__}(" + ", ".join(
            ("{k}={v}" for k, v in vars(self)) + ")"
        )

    def __str__(self):
        return self.__repr__()


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

        if len(keytab_records) == 0 or keytab_records[-1].kvno != kvno:
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
        else:
            keytab_records[-1].enctypes.append(enctype)

    return keytab_records


def _schedule_deletion(
    keytab: KeytabEntry,
    krbmaxrenewableage: int,
) -> None:
    """
    Schedules deletion of keytab on today + krbmaxrenewableage.

    :param keytab: KeytabEntry we want to delete
    :type keytab: KeytabEntry
    :param krbmaxrenewableage: Max renewable age for all the keytab entries
    :type krbmaxrenewableage: int
    """
    # TODO: FILL IN CRON TASK
    logger.error(
        [
            paths.KADMIN_LOCAL,
            "ktremove",
            "-k",
            keytab.filepath,
            keytab.principal,
            keytab.kvno,
        ]
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

    principal = keytab_entries[0][1]
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


def __get_realm_suffix(instance) -> DN:
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


def __get_krbmaxrenewableage(instance, ldap) -> int:
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
        __get_realm_suffix(instance), ["krbmaxrenewableage"]
    )
    krbmaxrenewableage = int(entry_attrs["krbmaxrenewableage"][0])
    if temporary_connect:
        ldap.disconnect()

    return krbmaxrenewableage


def check_and_rotate_keytabs(instance) -> bool:
    """
    Checks the encryption keys for all the keytabs, schedules removal of
    old invalid ones and generates new pairs.

    :param instance: instance of Service, simply pass self when in Service
    :type instance: PlatformService
    :returns: True if the keys have been rotated
    :rtype: bool
    """

    krbmaxrenewableage = __get_krbmaxrenewableage(instance)
    permitted_types = _get_krb_permitted_types()

    # For generate_keys, tuples of filepath and principal
    keytab_entries: list[tuple[str, str]] = []
    for keytab in (
        *_get_files_from_directory(paths.SSSD_KEYTABS_DIR),
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
        for entry in items:
            if entry.valid_enctypes(permitted_types):
                continue

            # TODO: Handle registered deletions, they shouldn't set invalid

            invalid = True
            _schedule_deletion(entry, krbmaxrenewableage)

        if invalid:
            entry = (keytab, items[-1].principal)
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
