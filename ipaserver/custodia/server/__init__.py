# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import importlib
import os

import pkg_resources

import six

from custodia import log
from custodia.httpd.server import HTTPServer

from .args import default_argparser
from .args import parse_args as _parse_args
from .config import parse_config as _parse_config

logger = log.getLogger('custodia')

__all__ = ['default_argparser', 'main']


def attach_store(typename, plugins, stores):
    for name, c in six.iteritems(plugins):
        if getattr(c, 'store_name', None) is None:
            continue
        try:
            c.store = stores[c.store_name]
        except KeyError:
            raise ValueError('[%s%s] references unexisting store '
                             '"%s"' % (typename, name, c.store_name))


def _load_plugin_class(menu, name):
    """Load Custodia plugin

    Entry points are preferred over dotted import path.
    """
    group = 'custodia.{}'.format(menu)
    eps = list(pkg_resources.iter_entry_points(group, name))
    if len(eps) > 1:
        raise ValueError(
            "Multiple entry points for {} {}: {}".format(menu, name, eps))
    elif len(eps) == 1:
        # backwards compatibility with old setuptools
        ep = eps[0]
        if hasattr(ep, 'resolve'):
            return ep.resolve()
        else:
            return ep.load(require=False)
    elif '.' in name:
        # fall back to old style dotted name
        module, classname = name.rsplit('.', 1)
        m = importlib.import_module(module)
        return getattr(m, classname)
    else:
        raise ValueError("{}: {} not found".format(menu, name))


def _create_plugin(cfgparser, section, menu):
    if not cfgparser.has_option(section, 'handler'):
        raise ValueError('Invalid section, missing "handler"')

    handler_name = cfgparser.get(section, 'handler')
    hconf = {'facility_name': section}
    try:
        handler = _load_plugin_class(menu, handler_name)
        classname = handler.__name__
        hconf['facility_name'] = '%s-[%s]' % (classname, section)
    except Exception as e:  # pylint: disable=broad-except
        raise ValueError('Invalid format for "handler" option '
                         '[%r]: %s' % (e, handler_name))

    if handler._options is not None:  # pylint: disable=protected-access
        # new-style plugin with parser and section
        plugin = handler(cfgparser, section)
    else:
        # old-style plugin with config dict
        hconf.update(cfgparser.items(section))
        hconf.pop('handler')
        plugin = handler(hconf)
        plugin.section = section
    return plugin


def _load_plugins(config, cfgparser):
    """Load and initialize plugins
    """
    # set umask before any plugin gets a chance to create a file
    os.umask(config['umask'])

    for s in cfgparser.sections():
        if s in {'ENV', 'global'}:
            # ENV section is only used for interpolation
            continue

        if s.startswith('/'):
            menu = 'consumers'
            path_chain = s.split('/')
            if path_chain[-1] == '':
                path_chain = path_chain[:-1]
            name = tuple(path_chain)
        else:
            if s.startswith('auth:'):
                menu = 'authenticators'
                name = s[5:]
            elif s.startswith('authz:'):
                menu = 'authorizers'
                name = s[6:]
            elif s.startswith('store:'):
                menu = 'stores'
                name = s[6:]
            else:
                raise ValueError('Invalid section name [%s].\n' % s)

        try:
            config[menu][name] = _create_plugin(cfgparser, s, menu)
        except Exception as e:
            logger.debug("Plugin '%s' failed to load.", name, exc_info=True)
            raise RuntimeError(menu, name, e)

    # 2nd initialization stage
    for menu in ['authenticators', 'authorizers', 'consumers', 'stores']:
        plugins = config[menu]
        for name in sorted(plugins):
            plugin = plugins[name]
            plugin.finalize_init(config, cfgparser, context=None)


def main(argparser=None):
    args = _parse_args(argparser=argparser)
    # parse arguments and populate config with basic settings
    cfgparser, config = _parse_config(args)
    # initialize logging
    log.setup_logging(config['debug'], config['auditlog'])
    logger.info('Custodia instance %s', args.instance or '<main>')
    logger.debug('Config file(s) %s loaded', config['configfiles'])
    # load plugins after logging
    _load_plugins(config, cfgparser)
    # create and run server
    httpd = HTTPServer(config['server_url'], config)
    httpd.serve()
