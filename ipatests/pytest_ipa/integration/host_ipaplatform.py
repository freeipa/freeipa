#
# Copyright (C) 2021  FreeIPA Contributors. See COPYING for license
#

"""Expose locally remote ipaplatform"""

from collections.abc import Mapping
import base64
import json
import textwrap


class HostPlatformNameSpace(Mapping):
    def __init__(self, d):
        self._d = d

    def __getitem__(self, key):
        return self._d[key]

    def __iter__(self):
        return iter(self._d)

    def __len__(self):
        return len(self._d)

    def __getattr__(self, name):
        try:
            return self._d[name]
        except KeyError:
            raise AttributeError(name)


class HostPlatformPaths(HostPlatformNameSpace):
    def __init__(self, host):
        code = textwrap.dedent(
            """\
                import base64
                import json

                from ipaplatform.paths import paths


                remote_paths = {}
                for name in sorted(dir(paths)):
                    if name.startswith("_"):
                        continue

                    value = getattr(paths, name)
                    try:
                        json.dumps(value)
                    except TypeError:
                        continue

                    remote_paths[name] = value

                json_data = json.dumps(remote_paths)
                json_base64 = base64.b64encode(
                    json_data.encode("utf-8")
                ).decode("ascii")
                print(json_base64)
            """
        )
        cmd = ["python3", "-c", code]
        res = host.run_command(cmd, log_stdout=False)
        json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
        super().__init__(
            json.loads(
                json_data, object_hook=lambda x: HostPlatformNameSpace(x)
            )
        )


class HostPlatformOSInfo(HostPlatformNameSpace):
    def __init__(self, host):
        code = textwrap.dedent(
            """\
                import base64
                import json

                from ipaplatform.osinfo import osinfo


                remote_osinfo = {}
                for name in sorted(dir(osinfo)):
                    if name.startswith("_"):
                        continue

                    value = getattr(osinfo, name)
                    try:
                        json.dumps(value)
                    except TypeError:
                        continue

                    remote_osinfo[name] = value

                json_data = json.dumps(remote_osinfo)
                json_base64 = base64.b64encode(
                    json_data.encode("utf-8")
                ).decode("ascii")
                print(json_base64)
            """
        )
        cmd = ["python3", "-c", code]
        res = host.run_command(cmd, log_stdout=False)
        json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
        super().__init__(
            json.loads(
                json_data, object_hook=lambda x: HostPlatformNameSpace(x)
            )
        )


class HostPlatformConstants(HostPlatformNameSpace):
    def __init__(self, host):
        code = textwrap.dedent(
            """\
                import base64
                import json
                from ipaplatform.constants import constants


                remote_constants = {}
                for name in sorted(dir(constants)):
                    if name.startswith("_"):
                        continue

                    value = getattr(constants, name)
                    try:
                        json.dumps(value)
                    except TypeError:
                        continue

                    remote_constants[name] = value

                json_data = json.dumps(remote_constants)
                json_base64 = base64.b64encode(
                    json_data.encode("utf-8")
                ).decode("ascii")
                print(json_base64)
            """
        )
        cmd = ["python3", "-c", code]
        res = host.run_command(cmd, log_stdout=False)
        json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
        super().__init__(
            json.loads(
                json_data, object_hook=lambda x: HostPlatformNameSpace(x)
            )
        )


class HostPlatformKnownservices(HostPlatformNameSpace):
    def __init__(self, host):
        code = textwrap.dedent(
            """\
                import base64
                import json

                from ipaplatform.services import knownservices


                remote_knownservices = {}
                for k,v in knownservices.items():
                    remote_knownservices[k] = {}

                    for name in sorted(dir(v)):
                        if name.startswith("_"):
                            continue

                        value = getattr(v, name)
                        try:
                            json.dumps(value)
                        except TypeError:
                            continue

                        remote_knownservices[k][name] = value

                json_data = json.dumps(remote_knownservices)
                json_base64 = base64.b64encode(
                    json_data.encode("utf-8")
                ).decode("ascii")
                print(json_base64)
            """
        )
        cmd = ["python3", "-c", code]
        res = host.run_command(cmd, log_stdout=False)
        json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")

        super().__init__(
            json.loads(
                json_data, object_hook=lambda x: HostPlatformNameSpace(x)
            )
        )


class HostPlatformTasks:
    def __init__(self, host):
        self.host = host
        self._pkcs11_modules = None

    @property
    def pkcs11_modules(self):
        if self._pkcs11_modules is None:
            code = textwrap.dedent(
                """\
                    import base64
                    import json

                    from ipaplatform.tasks import tasks


                    pkcs11_modules = tasks.get_pkcs11_modules()
                    json_data = json.dumps(pkcs11_modules)
                    json_base64 = base64.b64encode(
                        json_data.encode("utf-8")
                    ).decode("ascii")
                    print(json_base64)
                """
            )
            cmd = ["python3", "-c", code]
            res = self.host.run_command(cmd, log_stdout=False)
            json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
            self._pkcs11_modules = json.loads(json_data)

        return self._pkcs11_modules
