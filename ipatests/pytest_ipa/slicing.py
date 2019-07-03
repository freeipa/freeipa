#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""
The main purpose of this plugin is to slice a test suite into
several pieces to run each within its own test environment(for example,
an Agent of Azure Pipelines).

Tests within a slice are grouped by test modules because not all of the tests
within the module are independent from each other.

Slices are balanced by the number of tests within test module.
* Actually, tests should be grouped by the execution duration.
This could be achieved by the caching of tests results. Azure Pipelines
caching is in development. *
To workaround slow tests a dedicated slice is added.

:param slices: A total number of slices to split the test suite into
:param slice-num: A number of slice to run
:param slice-dedicated: A file path to the module to run in its own slice

**Examples**

Inputs:
ipa-run-tests test_cmdline --collectonly -qq
...
test_cmdline/test_cli.py: 39
test_cmdline/test_help.py: 7
test_cmdline/test_ipagetkeytab.py: 16
...

* Split tests into 2 slices and run the first one:

ipa-run-tests --slices=2 --slice-num=1 test_cmdline

The outcome would be:
...
Running slice: 1 (46 tests)
Modules:
test_cmdline/test_cli.py: 39
test_cmdline/test_help.py: 7
...

* Split tests into 2 slices, move one module out to its own slice
and run the second one

ipa-run-tests --slices=2 --slice-dedicated=test_cmdline/test_cli.py \
    --slice-num=2 test_cmdline

The outcome would be:
...
Running slice: 2 (23 tests)
Modules:
test_cmdline/test_ipagetkeytab.py: 16
test_cmdline/test_help.py: 7
...

"""
import pytest


def pytest_addoption(parser):
    group = parser.getgroup("slicing")
    group.addoption(
        '--slices', dest='slices_num', type=int,
        help='The number of slices to split the test suite into')
    group.addoption(
        '--slice-num', dest='slice_num', type=int,
        help='The specific number of slice to run')
    group.addoption(
        '--slice-dedicated', action="append", dest='slices_dedicated',
        help='The file path to the module to run in dedicated slice')


@pytest.hookimpl(hookwrapper=True)
def pytest_collection_modifyitems(session, config, items):
    yield
    slice_count = config.getoption('slices_num')
    slice_id = config.getoption('slice_num')
    modules_dedicated = config.getoption('slices_dedicated')
    # deduplicate
    if modules_dedicated:
        modules_dedicated = list(set(modules_dedicated))

    # sanity check
    if not slice_count or not slice_id:
        return

    # nothing to do
    if slice_count == 1:
        return

    if modules_dedicated and len(modules_dedicated) > slice_count:
        raise ValueError(
            "Dedicated slice number({}) shouldn't be greater than the number "
            "of slices({})".format(len(modules_dedicated), slice_count))

    if slice_id > slice_count:
        raise ValueError(
            "Slice number({}) shouldn't be greater than the number of slices"
            "({})".format(slice_id, slice_count))

    modules = []
    # Calculate modules within collection
    # Note: modules within pytest collection could be placed in not consecutive
    # order
    for number, item in enumerate(items):
        name = item.nodeid.split("::", 1)[0]
        if not modules or name != modules[-1]["name"]:
            modules.append({"name": name, "begin": number, "end": number})
        else:
            modules[-1]["end"] = number

    if slice_count > len(modules):
        raise ValueError(
            "Total number of slices({}) shouldn't be greater than the number "
            "of Python test modules({})".format(slice_count, len(modules)))

    slices_dedicated = []
    if modules_dedicated:
        slices_dedicated = [
            [m] for m in modules for x in modules_dedicated if x in m["name"]
        ]
    if modules_dedicated and len(slices_dedicated) != len(modules_dedicated):
        raise ValueError(
            "The number of dedicated slices({}) should be equal to the "
            "number of dedicated modules({})".format(
                slices_dedicated, modules_dedicated))

    if (slices_dedicated and len(slices_dedicated) == slice_count and
            len(slices_dedicated) != len(modules)):
        raise ValueError(
            "The total number of slices({}) is not sufficient to run dedicated"
            " modules({}) as well as usual ones({})".format(
                slice_count, len(slices_dedicated),
                len(modules) - len(slices_dedicated)))

    # remove dedicated modules from usual ones
    for s in slices_dedicated:
        for m in s:
            if m in modules:
                modules.remove(m)

    avail_slice_count = slice_count - len(slices_dedicated)
    # initialize slices with empty lists
    slices = [[] for i in range(slice_count)]

    # initialize slices with dedicated ones
    for sn, s in enumerate(slices_dedicated):
        slices[sn] = s

    # initial reverse sort by the number of tests in a test module
    modules.sort(reverse=True, key=lambda x: x["end"] - x["begin"] + 1)
    reverse = True
    while modules:
        for sslice_num, sslice in enumerate(sorted(
                modules[:avail_slice_count],
                reverse=reverse, key=lambda x: x["end"] - x["begin"] + 1)):
            slices[len(slices_dedicated) + sslice_num].append(sslice)

        modules[:avail_slice_count] = []
        reverse = not reverse

    calc_ntests = sum(x["end"] - x["begin"] + 1 for s in slices for x in s)
    assert calc_ntests == len(items)
    assert len(slices) == slice_count

    # the range of the given argument `slice_id` begins with 1(one)
    sslice = slices[slice_id - 1]

    new_items = []
    for m in sslice:
        new_items += items[m["begin"]:m["end"] + 1]
    items[:] = new_items

    tw = config.get_terminal_writer()
    if tw:
        tw.line()
        tw.write(
            "Running slice: {} ({} tests)\n".format(
                slice_id,
                len(items),
            ),
            cyan=True,
            bold=True,
        )
        tw.write(
            "Modules:\n",
            yellow=True,
            bold=True,
        )
        for module in sslice:
            tw.write(
                "{}: {}\n".format(
                    module["name"],
                    module["end"] - module["begin"] + 1),
                yellow=True,
            )
        tw.line()
