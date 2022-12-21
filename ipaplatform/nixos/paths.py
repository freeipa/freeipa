#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

from ipaplatform.fedora.paths import FedoraPathNamespace

# Note that we cannot use real paths, as they will be meaningless on nixos, as
# nixos stores all its packages in the nixstore under version/hash specific
# paths. The `@xxx@` are placeholders which will be instantiated to the correct
# nixstore paths at build time, by the nixpkgs freeipa derivation.


class NixOSPathNamespace(FedoraPathNamespace):
    SBIN_IPA_JOIN = "@out@/bin/ipa-join"
    IPA_GETCERT = "@out@/bin/ipa-getcert"
    IPA_RMKEYTAB = "@out@/bin/ipa-rmkeytab"
    IPA_GETKEYTAB = "@out@/bin/ipa-getkeytab"
    NSUPDATE = "@bind@/bin/nsupdate"
    BIN_CURL = "@curl@/bin/curl"
    KINIT = "@kerberos@/bin/kinit"
    KDESTROY = "@kerberos@/bin/kdestroy"


paths = NixOSPathNamespace()
