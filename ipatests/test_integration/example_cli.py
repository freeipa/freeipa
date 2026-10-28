import os

import ipalib
from ipaplatform.paths import paths

# authenticate with host keytab and custom ccache
os.environ.update(
    KRB5_CLIENT_KTNAME=paths.KRB5_KEYTAB,
)

# custom options
overrides = {"context": "example_cli"}
ipalib.api.bootstrap(**overrides)

with ipalib.api as api:
    user = api.Command.user_show("admin")
    print(user)

assert not api.Backend.rpcclient.isconnected()
