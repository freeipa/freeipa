#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


def pytest_addoption(parser):
    parser.addoption("--no-pretty-print", action="store_false",
                     dest="pretty_print", help="Don't pretty-print structures")
