#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

import os
import logging
import subprocess
from ipaclient.frontend import MethodOverride
from ipalib import errors
from ipalib import Bool, Flag, StrEnum
from ipalib.text import _
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)


class baseuser_add_passkey(MethodOverride):
    takes_options = (
        Flag(
            'register',
            cli_name='register',
            doc=_('Register the passkey'),
        ),
        Bool(
            'require_user_verification?',
            cli_name='require_user_verification',
            doc=_('Require user verification during authentication with '
                  'the passkey')
        ),
        StrEnum(
            'cosetype?',
            cli_name='cose_type',
            doc=_('COSE type to use for registration'),
            values=('es256', 'rs256', 'eddsa'),
        ),
        StrEnum(
            'credtype?',
            cli_name="cred_type",
            doc=_('Credential type'),
            values=('server-side', 'discoverable'),
        ),
    )

    def get_args(self):
        # ipapasskey is not mandatory as it can be built
        # from the registration step
        for arg in super(baseuser_add_passkey, self).get_args():
            if arg.name == 'ipapasskey':
                yield arg.clone(required=False, alwaysask=False)
            else:
                yield arg.clone()

    def forward(self, *args, **options):
        if self.api.env.context == 'cli':
            # 2 formats are possible for ipa user-add-passkey:
            # --register [--require-user-verification] [--cose-type ...]
            # or
            # passkey:<key id>,<pub key>
            for option in super(baseuser_add_passkey, self).get_options():
                if args and option in options:
                    raise errors.MutuallyExclusiveError(
                        reason=_("cannot specify both %s and "
                                 "passkey mapping").format(option))
            # if the first format is used, need to register the key first
            # and obtained the data
            if 'register' in options:
                # Ensure the executable exists
                if not os.path.exists(paths.PASSKEY_CHILD):
                    raise errors.ValidationError(name="register", error=_(
                        "Missing executable %s, use the command with "
                        "LOGIN PASSKEY instead of LOGIN --register")
                        % paths.PASSKEY_CHILD)

                options.pop('register')
                cosetype = options.pop('cosetype', None)
                require_verif = options.pop('require_user_verification', None)
                credtype = options.pop('credtype', None)
                cmd = [paths.PASSKEY_CHILD, "--register",
                       "--domain", self.api.env.domain,
                       "--username", args[0]]
                if cosetype:
                    cmd.append("--type")
                    cmd.append(cosetype)
                if require_verif is not None:
                    cmd.append("--user-verification")
                    cmd.append(str(require_verif).lower())
                if credtype:
                    cmd.append("--cred-type")
                    cmd.append(credtype)

                logger.debug("Executing command: %s", cmd)
                passkey = None
                with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                      bufsize=1,
                                      universal_newlines=True) as subp:
                    for line in subp.stdout:
                        if line.startswith("passkey:"):
                            passkey = line.strip()
                        else:
                            print(line.strip())

                if subp.returncode != 0:
                    raise errors.NotFound(reason="Failed to generate passkey")

                args = (args[0], [passkey])

        return super(baseuser_add_passkey, self).forward(*args, **options)
