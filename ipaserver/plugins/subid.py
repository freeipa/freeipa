#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

import uuid

from ipalib import api
from ipalib import constants
from ipalib import errors
from ipalib import output
from ipalib.plugable import Registry
from ipalib.parameters import Int, Str
from ipalib.request import context
from ipalib.text import _, ngettext
from ipapython.dn import DN

from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPQuery,
    DNA_MAGIC,
)

__doc__ = _(
    """
Subordinate ids

Manage subordinate user and group ids for users

EXAMPLES:

 Auto-assign a subordinate id range to current user
   ipa subid-generate

 Auto-assign a subordinate id range to user alice:
   ipa subid-generate --owner=alice

 Find subordinate ids for user alice:
   ipa subid-find --owner=alice

 Match entry by any subordinate uid in range:
   ipa subid-match --subuid=2147483649
"""
)

register = Registry()


@register()
class subid(LDAPObject):
    """Subordinate id object."""

    container_dn = api.env.container_subids

    object_name = _("Subordinate id")
    object_name_plural = _("Subordinate ids")
    label = _("Subordinate ids")
    label_singular = _("Subordinate id")

    object_class = ["ipasubordinateidentry"]
    possible_objectclasses = [
        "ipasubordinategid",
        "ipasubordinateuid",
        "ipasubordinateid",
    ]
    default_attributes = [
        "ipauniqueid",
        "ipaowner",
        "ipasubuidnumber",
        "ipasubuidcount",
        "ipasubgidnumber",
        "ipasubgidcount",
    ]
    allow_rename = False

    permission_filter_objectclasses_string = (
        "(objectclass=ipasubordinateidentry)"
    )
    managed_permissions = {
        # all authenticated principals can read subordinate id information
        "System: Read Subordinate Id Attributes": {
            "ipapermbindruletype": "all",
            "ipapermright": {"read", "search", "compare"},
            "ipapermtargetfilter": [
                permission_filter_objectclasses_string,
            ],
            "ipapermdefaultattr": {
                "objectclass",
                "ipauniqueid",
                "description",
                "ipaowner",
                "ipasubuidnumber",
                "ipasubuidcount",
                "ipasubgidnumber",
                "ipasubgidcount",
            },
        },
        "System: Read Subordinate Id Count": {
            "ipapermbindruletype": "all",
            "ipapermright": {"read", "search", "compare"},
            "ipapermtargetfilter": [],
            "ipapermtarget": DN(container_dn, api.env.basedn),
            "ipapermdefaultattr": {"numSubordinates"},
        },
        # user administrators can remove subordinate ids or update the
        # ipaowner attribute. This enables user admins to remove users
        # with assigned subids or move them to staging area (--preserve).
        "System: Manage Subordinate Ids": {
            "ipapermright": {"write"},
            "ipapermtargetfilter": [
                permission_filter_objectclasses_string,
            ],
            "ipapermdefaultattr": {
                "description",
                "ipaowner",  # allow user admins to preserve users
            },
            "default_privileges": {"User Administrators"},
        },
        "System: Remove Subordinate Ids": {
            "ipapermright": {"delete"},
            "ipapermtargetfilter": [
                permission_filter_objectclasses_string,
            ],
            "default_privileges": {"User Administrators"},
        },
    }

    takes_params = (
        Str(
            "ipauniqueid",
            cli_name="id",
            label=_("Unique ID"),
            primary_key=True,
            flags={"optional_create"},
        ),
        Str(
            "description?",
            cli_name="desc",
            label=_("Description"),
            doc=_("Subordinate id description"),
        ),
        Str(
            "ipaowner",
            cli_name="owner",
            label=_("Owner"),
            doc=_("Owning user of subordinate id entry"),
            flags={"no_update"},
        ),
        Int(
            "ipasubuidnumber?",
            label=_("SubUID range start"),
            cli_name="subuid",
            doc=_("Start value for subordinate user ID (subuid) range"),
            flags={"no_update"},
            minvalue=constants.SUBID_RANGE_START,
            maxvalue=constants.SUBID_RANGE_MAX,
        ),
        Int(
            "ipasubuidcount?",
            label=_("SubUID range size"),
            cli_name="subuidcount",
            doc=_("Subordinate user ID count"),
            flags={"no_create", "no_update", "no_search"},  # auto-assigned
            minvalue=constants.SUBID_COUNT,
            maxvalue=constants.SUBID_COUNT,
        ),
        Int(
            "ipasubgidnumber?",
            label=_("SubGID range start"),
            cli_name="subgid",
            doc=_("Start value for subordinate group ID (subgid) range"),
            flags={"no_create", "no_update"},  # auto-assigned
            minvalue=constants.SUBID_RANGE_START,
            maxvalue=constants.SUBID_RANGE_MAX,
        ),
        Int(
            "ipasubgidcount?",
            label=_("SubGID range size"),
            cli_name="subgidcount",
            doc=_("Subordinate group ID count"),
            flags={"no_create", "no_update", "no_search"},  # auto-assigned
            minvalue=constants.SUBID_COUNT,
            maxvalue=constants.SUBID_COUNT,
        ),
    )

    def fixup_objectclass(self, entry_attrs):
        """Add missing object classes to entry"""
        has_subuid = "ipasubuidnumber" in entry_attrs
        has_subgid = "ipasubgidnumber" in entry_attrs

        candicates = set(self.object_class)
        if has_subgid:
            candicates.add("ipasubordinategid")
        if has_subuid:
            candicates.add("ipasubordinateuid")
        if has_subgid and has_subuid:
            candicates.add("ipasubordinateid")

        entry_oc = entry_attrs.setdefault("objectclass", [])
        current_oc = {x.lower() for x in entry_oc}
        for oc in candicates.difference(current_oc):
            entry_oc.append(oc)

    def handle_duplicate_entry(self, *keys):
        if hasattr(context, "subid_owner_dn"):
            uid = context.subid_owner_dn[0].value
            msg = _(
                '%(oname)s with with name "%(pkey)s" or for user "%(uid)s" '
                "already exists."
            ) % {
                "uid": uid,
                "pkey": keys[-1] if keys else "",
                "oname": self.object_name,
            }
            raise errors.DuplicateEntry(message=msg) from None
        else:
            super().handle_duplicate_entry(*keys)

    def convert_owner(self, entry_attrs, options):
        """Change owner from DN to uid string"""
        if not options.get("raw", False) and "ipaowner" in entry_attrs:
            userobj = self.api.Object.user
            entry_attrs["ipaowner"] = [
                userobj.get_primary_key_from_dn(entry_attrs["ipaowner"][0])
            ]

    def get_owner_dn(self, *keys, **options):
        """Get owning user entry entry (username or DN)"""
        owner = keys[-1]
        userobj = self.api.Object.user
        if isinstance(owner, DN):
            # it's already a DN, validate it's either an active or preserved
            # user. Ref integrity plugin checks that it's not a dangling DN.
            user_dns = (
                DN(userobj.active_container_dn, self.api.env.basedn),
                DN(userobj.delete_container_dn, self.api.env.basedn),
            )
            if not owner.endswith(user_dns):
                raise errors.ValidationError(
                    name="ipaowner",
                    error=_("'%(dn)s is not a valid user") % {"dn": owner},
                )
            return owner

        # similar to user.get_either_dn() but with error reporting and
        # returns an entry
        ldap = self.backend
        try:
            active_dn = userobj.get_dn(owner, **options)
            entry = ldap.get_entry(active_dn, attrs_list=[])
            return entry.dn
        except errors.NotFound:
            # fall back to deleted user
            try:
                delete_dn = userobj.get_delete_dn(owner, **options)
                entry = ldap.get_entry(delete_dn, attrs_list=[])
                return entry.dn
            except errors.NotFound:
                raise userobj.handle_not_found(owner)

    def handle_subordinate_ids(self, ldap, dn, entry_attrs):
        """Handle ipaSubordinateId object class"""
        new_subuid = entry_attrs.single_value.get("ipasubuidnumber")
        new_subgid = entry_attrs.single_value.get("ipasubgidnumber")

        if new_subuid is None:
            new_subuid = DNA_MAGIC

        # enforce subuid == subgid
        if new_subgid is not None and new_subgid != new_subuid:
            raise errors.ValidationError(
                name="ipasubgidnumber",
                error=_("subgidnumber must be equal to subuidnumber"),
            )

        self.set_subordinate_ids(ldap, dn, entry_attrs, new_subuid)
        return True

    def set_subordinate_ids(self, ldap, dn, entry_attrs, subuid):
        """Set subuid value of an entry

        Takes care of objectclass and sibbling attributes
        """
        if "objectclass" not in entry_attrs:
            _entry_attrs = ldap.get_entry(dn, ["objectclass"])
            entry_attrs["objectclass"] = _entry_attrs["objectclass"]

        entry_attrs["ipasubuidnumber"] = subuid
        # enforce subuid == subgid for now
        entry_attrs["ipasubgidnumber"] = subuid
        # hard-coded constants
        entry_attrs["ipasubuidcount"] = constants.SUBID_COUNT
        entry_attrs["ipasubgidcount"] = constants.SUBID_COUNT

        self.fixup_objectclass(entry_attrs)

    def get_subid_match_candidate_filter(
        self,
        ldap,
        *,
        subuid,
        subgid,
        extra_filters=(),
        offset=None,
    ):
        """Create LDAP filter to locate matching/overlapping subids"""
        if subuid is None and subgid is None:
            raise ValueError("subuid and subgid are both None")
        if offset is None:
            # assumes that no subordinate count is larger than SUBID_COUNT
            offset = constants.SUBID_COUNT - 1

        class_filters = "(objectclass=ipasubordinateid)"
        subid_filters = []
        if subuid is not None:
            subid_filters.append(
                ldap.combine_filters(
                    [
                        f"(ipasubuidnumber>={subuid - offset})",
                        f"(ipasubuidnumber<={subuid + offset})",
                    ],
                    rules=ldap.MATCH_ALL,
                )
            )
        if subgid is not None:
            subid_filters.append(
                ldap.combine_filters(
                    [
                        f"(ipasubgidnumber>={subgid - offset})",
                        f"(ipasubgidnumber<={subgid + offset})",
                    ],
                    rules=ldap.MATCH_ALL,
                )
            )

        subid_filters = ldap.combine_filters(
            subid_filters, rules=ldap.MATCH_ANY
        )
        filters = [class_filters, subid_filters]
        filters.extend(extra_filters)
        return ldap.combine_filters(filters, rules=ldap.MATCH_ALL)


@register()
class subid_add(LDAPCreate):
    __doc__ = _("Add a new subordinate id.")
    msg_summary = _('Added subordinate id "%(value)s"')

    # internal command, use subid-auto to auto-assign subids
    NO_CLI = True

    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ):
        # XXX let ref integrity plugin validate DN?
        owner_dn = self.obj.get_owner_dn(entry_attrs["ipaowner"], **options)
        context.subid_owner_dn = owner_dn
        entry_attrs["ipaowner"] = owner_dn

        self.obj.handle_subordinate_ids(ldap, dn, entry_attrs)
        attrs_list.append("objectclass")

        return dn

    def execute(self, ipauniqueid=None, **options):
        if ipauniqueid is None:
            ipauniqueid = str(uuid.uuid4())
        return super().execute(ipauniqueid, **options)

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_owner(entry_attrs, options)
        return super(subid_add, self).post_callback(
            ldap, dn, entry_attrs, *keys, **options
        )


@register()
class subid_del(LDAPDelete):
    __doc__ = _("Delete a subordinate id.")
    msg_summary = _('Deleted subordinate id "%(value)s"')

    # internal command, subids cannot be removed
    NO_CLI = True


@register()
class subid_mod(LDAPUpdate):
    __doc__ = _("Modify a subordinate id.")
    msg_summary = _('Modified subordinate id "%(value)s"')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_owner(entry_attrs, options)
        return super(subid_mod, self).post_callback(
            ldap, dn, entry_attrs, *keys, **options
        )


@register()
class subid_find(LDAPSearch):
    __doc__ = _("Search for subordinate id.")
    msg_summary = ngettext(
        "%(count)d subordinate id matched",
        "%(count)d subordinate ids matched",
        0,
    )

    def pre_callback(
        self, ldap, filters, attrs_list, base_dn, scope, *args, **options
    ):
        attrs_list.append("objectclass")
        return super(subid_find, self).pre_callback(
            ldap, filters, attrs_list, base_dn, scope, *args, **options
        )

    def args_options_2_entry(self, *args, **options):
        entry_attrs = super(subid_find, self).args_options_2_entry(
            *args, **options
        )
        owner = entry_attrs.get("ipaowner")
        if owner is not None:
            owner_dn = self.obj.get_owner_dn(owner, **options)
            entry_attrs["ipaowner"] = owner_dn
        return entry_attrs

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry in entries:
            self.obj.convert_owner(entry, options)
        return super(subid_find, self).post_callback(
            ldap, entries, truncated, *args, **options
        )


@register()
class subid_show(LDAPRetrieve):
    __doc__ = _("Display information about a subordinate id.")

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        attrs_list.append("objectclass")
        return super(subid_show, self).pre_callback(
            ldap, dn, attrs_list, *keys, **options
        )

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_owner(entry_attrs, options)
        return super(subid_show, self).post_callback(
            ldap, dn, entry_attrs, *keys, **options
        )


@register()
class subid_generate(LDAPQuery):
    __doc__ = _(
        "Generate and auto-assign subuid and subgid range to user entry"
    )

    has_output = output.standard_entry

    takes_options = LDAPQuery.takes_options + (
        Str(
            "ipaowner?",
            cli_name="owner",
            label=_("Owner"),
            doc=_("Owning user of subordinate id entry"),
        ),
    )

    def get_args(self):
        return []

    def execute(self, *keys, **options):
        owner_uid = options.get("ipaowner")
        # default to current user
        if owner_uid is None:
            owner_dn = DN(self.api.Backend.ldap2.conn.whoami_s()[4:])
            # validate it's a user and not a service or host
            owner_dn = self.obj.get_owner_dn(owner_dn)
            owner_uid = owner_dn[0].value

        return self.api.Command.subid_add(
            description="auto-assigned subid",
            ipaowner=owner_uid,
            version=options["version"],
        )


@register()
class subid_match(subid_find):
    __doc__ = _("Match users by any subordinate uid in their range")

    def get_options(self):
        base_options = {p.name for p in self.obj.takes_params}
        for option in super().get_options():
            if option.name == "ipasubuidnumber":
                yield option.clone(
                    label=_("SubUID match"),
                    doc=_("Match value for subordinate user ID"),
                    required=True,
                )
            elif option.name not in base_options:
                # raw, version
                yield option.clone()

    def pre_callback(
        self, ldap, filters, attrs_list, base_dn, scope, *args, **options
    ):
        # search for candidates in range
        # Code assumes that no subordinate count is larger than SUBID_COUNT
        filters = self.obj.get_subid_match_candidate_filter(
            ldap,
            subuid=options["ipasubuidnumber"],
            subgid=None,
        )
        attrs_list.extend(self.obj.default_attributes)

        return filters, base_dn, scope

    def post_callback(self, ldap, entries, truncated, *args, **options):
        # filter out mismatches manually
        osubuid = options["ipasubuidnumber"]
        new_entries = []
        for entry in entries:
            self.obj.convert_owner(entry, options)
            esubuid = int(entry.single_value["ipasubuidnumber"])
            esubcount = int(entry.single_value["ipasubuidcount"])
            minsubuid = esubuid
            maxsubuid = esubuid + esubcount - 1
            if minsubuid <= osubuid <= maxsubuid:
                new_entries.append(entry)

        entries[:] = new_entries

        return truncated


@register()
class subid_stats(LDAPQuery):
    __doc__ = _("Subordinate id statistics")

    takes_options = ()
    has_output = (
        output.summary,
        output.Entry("result"),
    )

    def get_args(self):
        return ()

    def get_remaining_dna(self, ldap, **options):
        base_dn = DN(
            self.api.env.container_dna_subordinate_ids, self.api.env.basedn
        )
        entries, _truncated = ldap.find_entries(
            "(objectClass=dnaSharedConfig)",
            attrs_list=["dnaRemainingValues"],
            base_dn=base_dn,
            scope=ldap.SCOPE_ONELEVEL,
        )
        return sum(
            int(entry.single_value["dnaRemainingValues"]) for entry in entries
        )

    def get_idrange(self, ldap, **options):
        cn = f"{self.api.env.realm}_subid_range"
        result = self.api.Command.idrange_show(cn, version=options["version"])
        baseid = int(result["result"]["ipabaseid"][0])
        rangesize = int(result["result"]["ipaidrangesize"][0])
        return baseid, rangesize

    def get_subid_assigned(self, ldap, **options):
        dn = DN(self.api.env.container_subids, self.api.env.basedn)
        entry = ldap.get_entry(dn=dn, attrs_list=["numSubordinates"])
        return int(entry.single_value["numSubordinates"])

    def execute(self, *keys, **options):
        ldap = self.obj.backend
        dna_remaining = self.get_remaining_dna(ldap, **options)
        baseid, rangesize = self.get_idrange(ldap, **options)
        assigned_subids = self.get_subid_assigned(ldap, **options)
        remaining_subids = dna_remaining // constants.SUBID_COUNT
        return dict(
            summary=_("%(remaining)i remaining subordinate id ranges")
            % {
                "remaining": remaining_subids,
            },
            result=dict(
                baseid=baseid,
                rangesize=rangesize,
                dna_remaining=dna_remaining,
                assigned_subids=assigned_subids,
                remaining_subids=remaining_subids,
            ),
        )
