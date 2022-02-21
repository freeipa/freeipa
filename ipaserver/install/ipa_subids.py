#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

import logging

from ipalib import api
from ipalib import errors
from ipalib.facts import is_ipa_configured
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool, ScriptError
from ipapython.dn import DN
from ipapython.version import API_VERSION

logger = logging.getLogger(__name__)


class IPASubids(AdminTool):
    command_name = "ipa-subids"
    usage = "%prog [--group GROUP|--all-users]"
    description = "Mass-assign subordinate ids to users"

    @classmethod
    def add_options(cls, parser):
        super(IPASubids, cls).add_options(parser, debug_option=True)
        parser.add_option(
            "--group",
            dest="group",
            action="store",
            default=None,
            help="Updates members of a user group.",
        )
        parser.add_option(
            "--all-users",
            dest="all_users",
            action="store_true",
            default=False,
            help="Update all users.",
        )
        parser.add_option(
            "--filter",
            dest="user_filter",
            action="store",
            default="(!(nsaccountlock=TRUE))",
            help="Additional raw LDAP filter (default: active users).",
        )
        parser.add_option(
            "--dry-run",
            dest="dry_run",
            action="store_true",
            default=False,
            help="Dry run mode.",
        )

    def validate_options(self, needs_root=False):
        super().validate_options(needs_root=True)
        opt = self.safe_options

        if opt.all_users and opt.group:
            raise ScriptError("--group and --all-users are mutually exclusive")
        if not opt.all_users and not opt.group:
            raise ScriptError("Either --group or --all-users required")

    def get_group_info(self):
        assert api.isdone("finalize")
        group = self.safe_options.group
        if group is None:
            return None
        try:
            result = api.Command.group_show(group, no_members=True)
            return result["result"]
        except errors.NotFound:
            raise ScriptError(f"Unknown users group '{group}'.")

    def make_filter(self, groupinfo, user_filter):
        filters = [
            # only users with posixAccount
            "(objectClass=posixAccount)",
            # without subordinate ids
            f"(!(memberOf=*,cn=subids,cn=accounts,{api.env.basedn}))",
        ]
        if groupinfo is not None:
            filters.append(
                self.ldap2.make_filter({"memberof": groupinfo["dn"]})
            )
        if user_filter:
            filters.append(user_filter)
        return self.ldap2.combine_filters(filters, self.ldap2.MATCH_ALL)

    def search_users(self, filters):
        users_dn = DN(api.env.container_user, api.env.basedn)
        attrs = ["objectclass", "uid"]

        logger.debug("basedn: %s", users_dn)
        logger.debug("attrs: %s", attrs)
        logger.debug("filter: %s", filters)

        try:
            entries = self.ldap2.get_entries(
                base_dn=users_dn,
                filter=filters,
                attrs_list=attrs,
            )
        except errors.NotFound:
            logger.debug("No entries found")
            return []
        else:
            return entries

    def run(self):
        if not is_ipa_configured():
            print("IPA is not configured.")
            return 2

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        api.Backend.ldap2.connect()
        self.ldap2 = api.Backend.ldap2
        subid_generate = api.Command.subid_generate

        dry_run = self.safe_options.dry_run
        group_info = self.get_group_info()
        filters = self.make_filter(
            group_info, self.safe_options.user_filter
        )

        entries = self.search_users(filters)
        total = len(entries)
        logger.info("Found %i user(s) without subordinate ids", total)

        total = len(entries)
        for i, entry in enumerate(entries, start=1):
            logger.info(
                "  Processing user '%s' (%i/%i)",
                entry.single_value["uid"],
                i,
                total
            )
            if not dry_run:
                # TODO: check for duplicate entry (race condition)
                # TODO: log new subid
                subid_generate(
                    ipaowner=entry.single_value["uid"],
                    version=API_VERSION
                )

        if dry_run:
            logger.info("Dry run mode, no user was modified")
        else:
            logger.info("Updated %s user(s)", total)

        return 0


if __name__ == "__main__":
    IPASubids.run_cli()
