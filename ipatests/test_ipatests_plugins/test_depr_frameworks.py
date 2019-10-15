#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

import pytest


@pytest.fixture
def ipa_testdir(testdir):
    """
    Create conftest within testdir.
    """
    testdir.makeconftest(
        """
        pytest_plugins = ["ipatests.pytest_ipa.deprecated_frameworks"]
        """
    )
    return testdir


@pytest.fixture
def xunit_testdir(ipa_testdir):
    """
    Create xnit style test module within testdir.
    """
    ipa_testdir.makepyfile("""
        def setup_module():
            pass
        def teardown_module():
            pass
        def setup_function():
            pass
        def teardown_function():
            pass

        class TestClass:
            @classmethod
            def setup_class(cls):
                pass
            @classmethod
            def teardown_class(cls):
                pass
            def setup_method(self):
                pass
            def teardown_method(self):
                pass
            def test_m(self):
                pass
        """)
    return ipa_testdir


@pytest.fixture
def unittest_testdir(ipa_testdir):
    """
    Create unittest style test module within testdir.
    """
    ipa_testdir.makepyfile("""
        import unittest
        def setUpModule():
            pass
        def tearDownModule():
            pass
        class TestClass(unittest.TestCase):
            @classmethod
            def setUp(self):
                pass
            def tearDown(self):
                pass
            @classmethod
            def setUpClass(cls):
                pass
            @classmethod
            def tearDownClass(cls):
                pass
            def test_m(self):
                pass
        """)
    return ipa_testdir


def test_xunit(xunit_testdir):
    result = xunit_testdir.runpytest()
    result.assert_outcomes(passed=1)
    result.stdout.fnmatch_lines([
        "* PytestDeprecationWarning: xunit style is deprecated in favour of "
        "fixtures style",
        "* 8 warning*",
    ])


def test_unittest(unittest_testdir):
    result = unittest_testdir.runpytest()
    result.assert_outcomes(passed=1)
    result.stdout.fnmatch_lines([
        "* PytestDeprecationWarning: unittest is deprecated in favour of "
        "fixtures style",
        "* 1 warning*",
    ])
