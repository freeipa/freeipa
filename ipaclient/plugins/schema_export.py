#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""``schema-export`` — export the cached server schema to a local file.

The exported file is in the IPA schema ZIP format — the same format used
by the Python client cache at ``~/.cache/ipa/schema/1/<fingerprint>``.

Behaviour:

``ipa schema-export``
    Write ``ipa-schema-<fp>.zip`` in the current directory.

``ipa schema-export --out FILE``
    Write to ``FILE``.

The exported ZIP can be inspected with standard ZIP tools.  It contains one
JSON member per command (``commands/<full_name>``), one per object class
(``classes/<full_name>``), one per help topic (``topics/<full_name>``), a
``_help`` index, a ``version`` string, and a ``fingerprint`` string.
"""

import json
import os
import shutil
import sys
import zipfile

from ipalib import _
from ipalib import frontend
from ipalib.parameters import Str
from ipalib.plugable import Registry

register = Registry()

# Schema cache directory layout mirrors ipaclient/remote_plugins/schema.py.
_SCHEMA_FORMAT = '1'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _schema_dir(api):
    """Return the path to the Python schema cache directory."""
    return os.path.join(api.env.cache_dir, 'schema', _SCHEMA_FORMAT)


def _find_schema_path(api):
    """Return the path to the best schema ZIP file to export.

    Prefers the schema whose fingerprint matches the fingerprint recorded for
    the current server in ``~/.cache/ipa/servers/<server_hostname>``.  Falls
    back to the most recently modified file in the schema cache directory when
    no server information is available.

    Returns ``None`` when no cached schema is found.
    """
    schema_dir = _schema_dir(api)

    # Try to look up the fingerprint from the current server's info file.
    fingerprint = None
    try:
        server_host = str(api.env.server)
        server_info_path = os.path.join(
            api.env.cache_dir, 'servers', server_host)
        with open(server_info_path) as f:
            info = json.load(f)
        fingerprint = info.get('fingerprint')
    except (OSError, ValueError, AttributeError, KeyError):
        pass  # fall through to the mtime-based fallback

    if fingerprint:
        candidate = os.path.join(schema_dir, fingerprint)
        if os.path.isfile(candidate):
            return candidate

    # Fallback: pick the most recently modified file in the schema cache dir.
    try:
        entries = [
            os.path.join(schema_dir, f)
            for f in os.listdir(schema_dir)
            if not f.startswith('.')
        ]
    except OSError:
        return None

    if not entries:
        return None

    return max(entries, key=os.path.getmtime)


def _read_schema_meta(schema_path):
    """Extract metadata from a schema ZIP without fully extracting it.

    Returns a ``(api_version, num_commands)`` tuple.  ``api_version`` is an
    empty string when the ``version`` entry is absent or unreadable.
    ``num_commands`` counts entries under ``commands/``.
    """
    with zipfile.ZipFile(schema_path, 'r') as zf:
        names = zf.namelist()
        num_commands = sum(1 for n in names if n.startswith('commands/'))
        api_version = ''
        if 'version' in names:
            raw = zf.read('version')
            api_version = json.loads(raw.decode('utf-8'))
    return api_version, num_commands


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

@register()
class schema_export(frontend.Local):
    """Export the cached server schema to a local file."""

    topic = 'schema_export'

    takes_args = tuple()

    takes_options = (
        Str(
            'out?',
            label=_('Output file'),
            doc=_('Write schema to FILE instead of the default name'),
        ),
    )

    has_output = tuple()

    def execute(self, **options):
        schema_path = _find_schema_path(self.api)
        if schema_path is None:
            print(
                "ipa: ERROR: No cached schema found. "
                "Run 'ipa ping' first to populate the cache.",
                file=sys.stderr,
            )
            return {}

        fingerprint = os.path.basename(schema_path)

        try:
            api_version, num_commands = _read_schema_meta(schema_path)
        except (zipfile.BadZipFile, OSError, ValueError) as e:
            print(
                "ipa: ERROR: Failed to read the cached schema: {}".format(e),
                file=sys.stderr,
            )
            return {}

        out_path = options.get('out') or 'ipa-schema-{}.zip'.format(fingerprint)

        shutil.copy2(schema_path, out_path)

        print('Schema exported to: {}'.format(out_path))
        if api_version:
            print('  API version: {}'.format(api_version))
        print('  Fingerprint: {}'.format(fingerprint))
        print('  Commands:    {}'.format(num_commands))

        return {}
