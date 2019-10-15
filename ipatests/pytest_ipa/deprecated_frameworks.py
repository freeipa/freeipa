#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""Warns about xunit/unittest/nose tests.

FreeIPA is a rather old project and hereby includes all the most
famous in the past and present Python test idioms. Of course,
this is difficult to play around all of them. For now, the runner
of the IPA's test suite is Pytest.

Pytest supports xunit style setups, unittest, nose tests. But this
support is limited and may be dropped in the future releases.
Worst of all is that the mixing of various test frameworks results
in weird conflicts and of course, is not widely tested. In other
words, there is a big risk. To eliminate this risk and to not pin
Pytest to 3.x branch IPA's tests were refactored.

This plugin is intended to issue warnings on collecting tests,
which employ unittest/nose frameworks or xunit style.

To treat these warnings as errors it's enough to run Pytest with:

-W error:'xunit style is deprecated':pytest.PytestDeprecationWarning

"""
from unittest import TestCase

import pytest

forbidden_module_scopes = [
    'setup_module',
    'setup_function',
    'teardown_module',
    'teardown_function',
]

forbidden_class_scopes = [
    'setup_class',
    'setup_method',
    'teardown_class',
    'teardown_method',
]


def pytest_collection_finish(session):
    for item in session.items:
        cls = getattr(item, 'cls', None)
        if cls is not None and issubclass(cls, TestCase):
            item.warn(pytest.PytestDeprecationWarning(
                "unittest is deprecated in favour of fixtures style"))
            continue

        def xunit_depr_warn(item, attr, names):
            for n in names:
                obj = getattr(item, attr, None)
                method = getattr(obj, n, None)
                fixtured = hasattr(method, '__pytest_wrapped__')
                if method is not None and not fixtured:
                    item.warn(
                        pytest.PytestDeprecationWarning(
                            "xunit style is deprecated in favour of "
                            "fixtures style"))

        xunit_depr_warn(item, 'module', forbidden_module_scopes)
        xunit_depr_warn(item, 'cls', forbidden_class_scopes)
