#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

import os

import pytest

MOD_NAME = "test_module_{}"
FUNC_NAME = "test_func_{}"
MODS_NUM = 5


@pytest.fixture
def ipatestdir(testdir, monkeypatch):
    """
    Create MODS_NUM test modules within testdir/ipatests.
    Each module contains 1 test function.
    Patch PYTHONPATH with created package path to override the system's
    ipatests
    """
    ipatests_dir = testdir.mkpydir("ipatests")
    for i in range(MODS_NUM):
        ipatests_dir.join("{}.py".format(MOD_NAME.format(i))).write(
            "def {}(): pass".format(FUNC_NAME.format(i)))

    python_path = os.pathsep.join(
        filter(None, [str(testdir.tmpdir), os.environ.get("PYTHONPATH", "")]))
    monkeypatch.setenv("PYTHONPATH", python_path)

    def run_ipa_tests(*args):
        cmdargs = ["ipa-run-tests", "-v"] + list(args)
        return testdir.run(*cmdargs, timeout=60)

    testdir.run_ipa_tests = run_ipa_tests
    return testdir


def test_ipa_run_tests_basic(ipatestdir):
    """
    Run ipa-run-tests with default arguments
    """
    result = ipatestdir.run_ipa_tests()
    assert result.ret == 0
    result.assert_outcomes(passed=MODS_NUM)
    for mod_num in range(MODS_NUM):
        result.stdout.fnmatch_lines(["*{mod}.py::{func} PASSED*".format(
            mod=MOD_NAME.format(mod_num),
            func=FUNC_NAME.format(mod_num))])


def test_ipa_run_tests_glob1(ipatestdir):
    """
    Run ipa-run-tests using glob patterns to collect tests
    """
    result = ipatestdir.run_ipa_tests("{mod}".format(
        mod="test_modul[!E]?[0-5]*"))
    assert result.ret == 0
    result.assert_outcomes(passed=MODS_NUM)
    for mod_num in range(MODS_NUM):
        result.stdout.fnmatch_lines(["*{mod}.py::{func} PASSED*".format(
            mod=MOD_NAME.format(mod_num),
            func=FUNC_NAME.format(mod_num))])


def test_ipa_run_tests_glob2(ipatestdir):
    """
    Run ipa-run-tests using glob patterns to collect tests
    """
    result = ipatestdir.run_ipa_tests("{mod}".format(
        mod="test_module_{0,1}*"))
    assert result.ret == 0
    result.assert_outcomes(passed=2)
    for mod_num in range(2):
        result.stdout.fnmatch_lines(["*{mod}.py::{func} PASSED*".format(
            mod=MOD_NAME.format(mod_num),
            func=FUNC_NAME.format(mod_num))])


def test_ipa_run_tests_specific_nodeid(ipatestdir):
    """
    Run ipa-run-tests using nodeid to collect test
    """
    mod_num = 0
    result = ipatestdir.run_ipa_tests("{mod}.py::{func}".format(
        mod=MOD_NAME.format(mod_num),
        func=FUNC_NAME.format(mod_num)))
    assert result.ret == 0
    result.assert_outcomes(passed=1)
    result.stdout.fnmatch_lines(["*{mod}.py::{func} PASSED*".format(
        mod=MOD_NAME.format(mod_num),
        func=FUNC_NAME.format(mod_num))])


@pytest.mark.parametrize(
    "expr",
    [["-k", "not {func}".format(func=FUNC_NAME.format(0))],
     ["-k not {func}".format(func=FUNC_NAME.format(0))]])
def test_ipa_run_tests_expression(ipatestdir, expr):
    """
    Run ipa-run-tests using expression
    """
    result = ipatestdir.run_ipa_tests(*expr)
    assert result.ret == 0
    result.assert_outcomes(passed=4)
    for mod_num in range(1, MODS_NUM):
        result.stdout.fnmatch_lines(["*{mod}.py::{func} PASSED*".format(
            mod=MOD_NAME.format(mod_num),
            func=FUNC_NAME.format(mod_num))])


def test_ipa_run_tests_ignore_basic(ipatestdir):
    """
    Run ipa-run-tests ignoring one test module
    """
    result = ipatestdir.run_ipa_tests(
        "--ignore", "{mod}.py".format(mod=MOD_NAME.format(0)),
        "--ignore", "{mod}.py".format(mod=MOD_NAME.format(1)),
    )
    assert result.ret == 0
    result.assert_outcomes(passed=MODS_NUM - 2)
    for mod_num in range(2, MODS_NUM):
        result.stdout.fnmatch_lines(["*{mod}.py::{func} PASSED*".format(
            mod=MOD_NAME.format(mod_num),
            func=FUNC_NAME.format(mod_num))])


def test_ipa_run_tests_defaultargs(ipatestdir):
    """
    Checking the ipa-run-tests defaults:
    * cachedir
    * rootdir
    """
    mod_num = 0
    result = ipatestdir.run_ipa_tests("{mod}.py::{func}".format(
        mod=MOD_NAME.format(mod_num),
        func=FUNC_NAME.format(mod_num)))
    assert result.ret == 0
    result.assert_outcomes(passed=1)
    result.stdout.re_match_lines([
        "^cachedir: {cachedir}$".format(
            cachedir=os.path.join(os.getcwd(), ".pytest_cache")),
        "^rootdir: {rootdir}([,].*)?$".format(
            rootdir=os.path.join(str(ipatestdir.tmpdir), "ipatests"))
    ])


def test_ipa_run_tests_confcutdir(ipatestdir):
    """
    Checking the ipa-run-tests defaults:
    * confcutdir
    """
    mod_num = 0
    ipatestdir.makeconftest("import somenotexistedpackage")
    result = ipatestdir.run_ipa_tests("{mod}.py::{func}".format(
        mod=MOD_NAME.format(mod_num),
        func=FUNC_NAME.format(mod_num)))
    assert result.ret == 0
    result.assert_outcomes(passed=1)
    result.stdout.fnmatch_lines(["*{mod}.py::{func} PASSED*".format(
        mod=MOD_NAME.format(mod_num),
        func=FUNC_NAME.format(mod_num))])
