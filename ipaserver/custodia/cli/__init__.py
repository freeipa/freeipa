# Copyright (C) 2016  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import, print_function

import argparse
import operator
import os
import traceback

import pkg_resources

import requests.exceptions

import six

from custodia import log
from custodia.client import CustodiaSimpleClient, requests_gssapi
from custodia.compat import unquote, url_escape, urlparse

if six.PY2:
    from StringIO import StringIO  # pylint: disable=import-error
else:
    from io import StringIO

try:
    from json import JSONDecodeError
except ImportError:
    # Python 2.7 has no JSONDecodeError
    JSONDecodeError = ValueError


log.warn_provisional(__name__)

# exit codes
E_HTTP_ERROR = 1
E_CONNECTION_ERROR = 2
E_JSON_ERROR = 3
E_OTHER = 100


main_parser = argparse.ArgumentParser(
    prog='custodia-cli',
    description='Custodia command line interface'
)


def server_check(arg):
    """Check and format --server arg
    """
    if arg.startswith(('http://', 'https://', 'http+unix://')):
        return arg
    if arg.startswith('./'):
        arg = os.path.abspath(arg)
    elif not arg.startswith('/'):
        raise argparse.ArgumentTypeError(
            'Unix socket path must start with / or ./')
    # assume it is a unix socket
    return 'http+unix://{}'.format(url_escape(arg, ''))


def instance_check(arg):
    if set(arg).intersection(':/@'):
        raise argparse.ArgumentTypeError(
            'Instance name contains invalid characters')
    return arg


def split_header(arg):
    name, value = arg.split('=')
    return name, value


def timeout(arg):
    try:
        arg = float(arg)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('Argument is not a float')
    if arg < 0.0:
        raise argparse.ArgumentTypeError('Argument is negative')
    if arg == 0.0:
        # no timeout
        return None
    return arg


group = main_parser.add_mutually_exclusive_group()
group.add_argument(
    '--server',
    type=server_check,
    help=('Custodia server location, supports http://, https://, '
          'or path to a unix socket.')
)
group.add_argument(
    '--instance',
    default=os.getenv('CUSTODIA_INSTANCE', 'custodia'),
    type=instance_check,
    help="Instance name (default: CUSTODIA_INSTANCE or 'custodia')",
)

main_parser.add_argument(
    '--uds-urlpath', type=str, default='/secrets/',
    help='URL path for Unix Domain Socket'
)

main_parser.add_argument(
    '--header', type=split_header, action='append',
    help='Extra headers'
)

main_parser.add_argument(
    '--verbose', action='store_true',
)
main_parser.add_argument(
    '--debug', action='store_true',
)

main_parser.add_argument(
    '--timeout', type=timeout, default=10.,
    help='Connection timeout'
)

# TLS
main_parser.add_argument(
    '--cafile', type=str, default=None,
    help='PEM encoded file with root CAs'
)

# authentication mechanisms
# TLS client cert auth
tlsclient_group = main_parser.add_argument_group(
    title="TLS client cert auth"
)
tlsclient_group.add_argument(
    '--certfile', type=str, default=None,
    help='PEM encoded file with certs for TLS client authentication'
)
tlsclient_group.add_argument(
    '--keyfile', type=str, default=None,
    help='PEM encoded key file (if not given, key is read from certfile)'
)

# Use Negotiate / GSSAPI
gssapi_group = main_parser.add_argument_group(
    title="GSSAPI auth"
)
gssapi_group.add_argument(
    '--gssapi', action='store_true',
    help='Use Negotiate / GSSAPI auth'
)


# handlers
def handle_name(args):
    client = args.client_conn
    func = getattr(client, args.command)
    return func(args.name)


def handle_name_value(args):
    client = args.client_conn
    func = getattr(client, args.command)
    return func(args.name, args.value)


# subparsers
subparsers = main_parser.add_subparsers()
subparsers.required = True

parser_create_container = subparsers.add_parser(
    'mkdir',
    help='Create a container')
parser_create_container.add_argument('name', type=str, help='key')
parser_create_container.set_defaults(
    func=handle_name,
    command='create_container',
    sub='mkdir',
)

parser_delete_container = subparsers.add_parser(
    'rmdir',
    help='Delete a container')
parser_delete_container.add_argument('name', type=str, help='key')
parser_delete_container.set_defaults(
    func=handle_name,
    command='delete_container',
    sub='rmdir',
)

parser_list_container = subparsers.add_parser(
    'ls', help='List content of a container')
parser_list_container.add_argument('name', type=str, help='key')
parser_list_container.set_defaults(
    func=handle_name,
    command='list_container',
    sub='ls',
)

parser_get_secret = subparsers.add_parser(
    'get', help='Get secret')
parser_get_secret.add_argument('name', type=str, help='key')
parser_get_secret.set_defaults(
    func=handle_name,
    command='get_secret',
    sub='get',
)

parser_set_secret = subparsers.add_parser(
    'set', help='Set secret')
parser_set_secret.add_argument('name', type=str, help='key')
parser_set_secret.add_argument('value', type=str, help='value')
parser_set_secret.set_defaults(
    command='set_secret',
    func=handle_name_value,
    sub='set'
)

parser_del_secret = subparsers.add_parser(
    'del', help='Delete a secret')
parser_del_secret.add_argument('name', type=str, help='key')
parser_del_secret.set_defaults(
    func=handle_name,
    command='del_secret',
    sub='del',
)


# plugins
PLUGINS = [
    'custodia.authenticators', 'custodia.authorizers', 'custodia.clients',
    'custodia.consumers', 'custodia.stores'
]


def handle_plugins(args):
    result = []
    errmsg = "**ERR** {0} ({1.__class__.__name__}: {1})"
    for plugin in PLUGINS:
        result.append('[{}]'.format(plugin))
        eps = pkg_resources.iter_entry_points(plugin)
        eps = sorted(eps, key=operator.attrgetter('name'))
        for ep in eps:
            try:
                if hasattr(ep, 'resolve'):
                    ep.resolve()
                else:
                    ep.load(require=False)
            except Exception as e:  # pylint: disable=broad-except
                if args.verbose:
                    result.append(errmsg.format(ep, e))
            else:
                result.append(str(ep))
        result.append('')
    return result[:-1]


parser_plugins = subparsers.add_parser(
    'plugins', help='List plugins')
parser_plugins.set_defaults(
    func=handle_plugins,
    command='plugins',
    sub='plugins',
    name=None,
)
parser_plugins.add_argument(
    '--verbose',
    action='store_true',
    help="Verbose mode, show failing plugins."
)


def error_message(args, exc):
    out = StringIO()
    parts = urlparse(args.server)

    if args.debug:
        traceback.print_exc(file=out)
        out.write('\n')

    out.write("ERROR: Custodia command '{args.sub} {args.name}' failed.\n")
    if args.verbose:
        out.write("Custodia server '{args.server}'.\n")

    if isinstance(exc, requests.exceptions.HTTPError):
        errcode = E_HTTP_ERROR
        out.write("{exc.__class__.__name__}: {exc}\n")
    elif isinstance(exc, requests.exceptions.ConnectionError):
        errcode = E_CONNECTION_ERROR
        if parts.scheme == 'http+unix':
            out.write("Failed to connect to Unix socket '{unix_path}':\n")
        else:
            out.write("Failed to connect to '{parts.netloc}' "
                      "({parts.scheme}):\n")
        # ConnectionError always contains an inner exception
        out.write("    {exc.args[0]}\n")
    elif isinstance(exc, JSONDecodeError):
        errcode = E_JSON_ERROR
        out.write("Server returned invalid JSON response:\n")
        out.write("    {exc}\n")
    else:
        errcode = E_OTHER
        out.write("{exc.__class__.__name__}: {exc}\n")

    msg = out.getvalue()
    if not msg.endswith('\n'):
        msg += '\n'
    return errcode, msg.format(args=args, exc=exc, parts=parts,
                               unix_path=unquote(parts.netloc))


def parse_args(arglist=None):
    args = main_parser.parse_args(arglist)

    if args.keyfile and not args.certfile:
        main_parser.error("keyfile without certfile is not supported\n")
    # mutually exclusive groups don't supported nested subgroups
    if args.gssapi and args.certfile:
        main_parser.error("gssapi and certfile are mutually exclusive.\n")
    if args.gssapi and requests_gssapi is None:
        main_parser.error(
            "'requests_gssapi' package is not available! You can install "
            "it with: 'pip install custodia[gssapi]'.\n"
        )

    if args.debug:
        args.verbose = True

    if not args.server:
        instance_socket = '/var/run/custodia/{}.sock'.format(args.instance)
        args.server = 'http+unix://{}'.format(url_escape(instance_socket, ''))

    if args.server.startswith('http+unix://'):
        # append uds-path
        if not args.server.endswith('/'):
            udspath = args.uds_urlpath
            if not udspath.startswith('/'):
                udspath = '/' + udspath
            args.server += udspath

    args.client_conn = CustodiaSimpleClient(args.server)
    args.client_conn.timeout = args.timeout
    if args.header is not None:
        args.client_conn.headers.update(args.header)
    if args.cafile:
        args.client_conn.set_ca_cert(args.cafile)
    # authentication
    if args.certfile:
        args.client_conn.set_client_cert(args.certfile, args.keyfile)
        args.client_conn.headers['CUSTODIA_CERT_AUTH'] = 'true'
    elif args.gssapi:
        args.client_conn.set_gssapi_auth()

    return args


def main():
    args = parse_args()

    log.setup_logging(debug=args.debug, auditfile=None)

    try:
        result = args.func(args)
    except BaseException as e:
        errcode, msg = error_message(args, e)
        main_parser.exit(errcode, msg)
    else:
        if result is not None:
            if isinstance(result, list):
                print('\n'.join(result))
            else:
                print(result)


if __name__ == '__main__':
    main()
