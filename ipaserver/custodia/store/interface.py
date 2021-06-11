# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import warnings

from custodia.plugin import CSStore, CSStoreError, CSStoreExists

__all__ = ('CSStore', 'CSStoreError', 'CSStoreExists')


warnings.warn('custodia.store.interface is deprecated, import from '
              'custodia.plugin instead.', DeprecationWarning,)
