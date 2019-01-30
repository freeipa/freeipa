#
# Copyright (C) 2019  IPA Project Contributors, see COPYING for license
#
"""Common helpers for handlers
"""
import argparse
import base64
import json
import shutil
import tempfile


def default_json(obj):
    """JSON encoder default handler
    """
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(obj).decode('ascii')
    raise TypeError(
        "Object of type {} is not JSON serializable".format(type(obj))
    )


def json_dump(data, exportfile):
    """Dump JSON to file
    """
    json.dump(
        data,
        exportfile,
        default=default_json,
        separators=(',', ':'),
        sort_keys=True
    )


def mkparser(supports_import=True, **kwargs):
    """Create default parser for handler with export / import args

    All commands support export to file or stdout. Most commands can also
    import from a file or stdin. Export and import are mutually exclusive
    options.
    """
    parser = argparse.ArgumentParser(**kwargs)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--export',
        help='JSON export file ("-" for stdout)',
        dest='exportfile',
        type=argparse.FileType('w')
    )
    if supports_import:
        group.add_argument(
            '--import',
            help='JSON import file ("-" for stdin)',
            dest='importfile',
            type=argparse.FileType('r')
        )

    return parser


def main(parser, export_func, import_func=None, **kwargs):
    """Common main function for handlers
    """
    args = parser.parse_args()
    if args.exportfile is not None:
        func = export_func
    else:
        func = import_func

    tmpdir = tempfile.mkdtemp()
    try:
        func(args, tmpdir, **kwargs)
    finally:
        shutil.rmtree(tmpdir)
