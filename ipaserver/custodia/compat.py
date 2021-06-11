# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
"""Python 2/3 compatibility
"""
# pylint: disable=no-name-in-module,import-error
from __future__ import absolute_import

import six


if six.PY2:
    # use https://pypi.python.org/pypi/configparser/ on Python 2
    from backports import configparser
    from urllib import quote as url_escape
    from urllib import quote_plus, unquote
    from urlparse import parse_qs, urlparse
else:
    import configparser
    from urllib.parse import quote as url_escape
    from urllib.parse import parse_qs, quote_plus, unquote, urlparse


__all__ = (
    'configparser',
    'parse_qs', 'quote_plus', 'unquote', 'url_escape', 'urlparse'
)
