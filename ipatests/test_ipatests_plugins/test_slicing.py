#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

import glob

import pytest

MOD_NAME = "test_module_{}"
FUNC_NAME = "test_func_{}"
PYTEST_INTERNAL_ERROR = 3
MODS_NUM = 5


@pytest.fixture
def ipatestdir(testdir):
    """
    Create MODS_NUM test modules within testdir.
    Each module contains 1 test function.
    """
    testdir.makeconftest(
        """
        pytest_plugins = ["ipatests.pytest_ipa.slicing"]
        """
    )
    for i in range(MODS_NUM):
        testdir.makepyfile(
            **{MOD_NAME.format(i):
                """
                def {func}():
                    pass
                """.format(func=FUNC_NAME.format(i))
               }
        )
    return testdir


@pytest.mark.parametrize(
    "nslices,nslices_d,groups",
    [(2, 0, [[x for x in range(MODS_NUM) if x % 2 == 0],
             [x for x in range(MODS_NUM) if x % 2 != 0]]),
     (2, 1, [[0], [x for x in range(1, MODS_NUM)]]),
     (1, 0, [[x for x in range(MODS_NUM)]]),
     (1, 1, [[x for x in range(MODS_NUM)]]),
     (MODS_NUM, MODS_NUM, [[x] for x in range(MODS_NUM)]),
     ])
def test_slicing(ipatestdir, nslices, nslices_d, groups):
    """
    Positive tests.

    Run `nslices` slices, including `nslices_d` dedicated slices.
    The `groups` is an expected result of slices grouping.

    For example, there are 5 test modules. If one runs them in
    two slices (without dedicated ones) the expected result will
    be [[0, 2, 4], [1, 3]]. This means, that first slice will run
    modules 0, 2, 4, second one - 1 and 3.

    Another example, there are 5 test modules. We want to run them
    in two slices. Also we specify module 0 as dedicated.
    The expected result will be [[0], [1, 2, 3, 4]], which means, that
    first slice will run module 0, second one - 1, 2, 3, 4.

    If the given slice count is one, then this plugin does nothing.
    """
    for sl in range(nslices):
        args = [
            "-v",
            "--slices={}".format(nslices),
            "--slice-num={}".format(sl + 1)
        ]
        for dslice in range(nslices_d):
            args.append(
                "--slice-dedicated={}.py".format(MOD_NAME.format(dslice)))
        result = ipatestdir.runpytest(*args)
        assert result.ret == 0
        result.assert_outcomes(passed=len(groups[sl]))
        for mod_num in groups[sl]:
            result.stdout.fnmatch_lines(["*{mod}.py::{func} PASSED*".format(
                mod=MOD_NAME.format(mod_num),
                func=FUNC_NAME.format(mod_num))])


@pytest.mark.parametrize(
    "nslices,nslices_d,nslice,dmod,err_message",
    [(2, 3, 1, None,
      "Dedicated slice number({}) shouldn't be greater than"
      " the number of slices({})".format(3, 2)),
     (MODS_NUM, 0, MODS_NUM + 1, None,
      "Slice number({}) shouldn't be greater than the number of slices"
      "({})".format(
          MODS_NUM + 1, MODS_NUM)),
     (MODS_NUM + 1, 1, 1, None,
      "Total number of slices({}) shouldn't be greater"
      " than the number of Python test modules({})".format(
          MODS_NUM + 1, MODS_NUM)),
     (MODS_NUM, MODS_NUM, 1, "notexisted_module",
      "The number of dedicated slices({}) should be equal to the "
      "number of dedicated modules({})".format(
          [], ["notexisted_module.py"])),
     (MODS_NUM - 1, MODS_NUM - 1, 1, None,
      "The total number of slices({}) is not sufficient to"
      " run dedicated modules({}) as well as usual ones({})".format(
          MODS_NUM - 1, MODS_NUM - 1, 1)),
     ])
def test_slicing_negative(ipatestdir, nslices, nslices_d, nslice, dmod,
                          err_message):
    """
    Negative scenarios
    """
    args = [
        "-v",
        "--slices={}".format(nslices),
        "--slice-num={}".format(nslice)
    ]
    if dmod is None:
        for dslice in range(nslices_d):
            args.append(
                "--slice-dedicated={}.py".format(MOD_NAME.format(dslice)))
    else:
        args.append(
            "--slice-dedicated={}.py".format(dmod))
    result = ipatestdir.runpytest(*args)
    assert result.ret == PYTEST_INTERNAL_ERROR
    result.assert_outcomes()
    result.stdout.fnmatch_lines(["*ValueError: {err_message}*".format(
        err_message=glob.escape(err_message))])
