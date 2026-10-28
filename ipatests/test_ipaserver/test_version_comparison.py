#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
tests for correct RPM version comparison
"""

from __future__ import absolute_import

from ipaplatform.tasks import tasks
import pytest

version_strings = [
    ("3.0.0-1.el6", "3.0.0-2.el6", "older"),
    ("3.0.0-1.el6_8", "3.0.0-1.el6_8.1", "older"),
    ("3.0.0-42.el6", "3.0.0-1.el6", "newer"),
    ("3.0.0-1.el6", "3.0.0-42.el6", "older"),
    ("3.0.0-42.el6", "3.3.3-1.fc20", "older"),
    ("4.2.0-15.el7", "4.2.0-15.el7_2.3", "older"),
    ("4.2.0-15.el7_2", "4.2.0-15.el7_2.3", "older"),
    ("4.2.0-15.el7_2.3", "4.2.0-15.el7_2.3", "equal"),
    ("4.2.0-15.el7_2.3", "4.2.0-15.el7_2.2", "newer"),
    ("4.2.0-1.fc23", "4.2.1-1.fc23", "older"),
    ("4.2.3-alpha1.fc23", "4.2.3-2.fc23", "older"),  # numeric version elements
                                                     # have precedence over
                                                     # non-numeric ones
    ("4.3.90.201601080923GIT55aeea7-0.fc23", "4.3.0-1.fc23", "newer")
]


@pytest.fixture(params=version_strings)
def versions(request):
    return request.param


class TestVersionComparsion:

    def test_versions(self, versions):
        version_string1, version_string2, expected_comparison = versions

        ver1 = tasks.parse_ipa_version(version_string1)
        ver2 = tasks.parse_ipa_version(version_string2)

        if expected_comparison == "newer":
            assert ver1 > ver2
        elif expected_comparison == "older":
            assert ver1 < ver2
        elif expected_comparison == "equal":
            assert ver1 == ver2
        else:
            raise TypeError(
                "Unexpected comparison string: {}".format(expected_comparison)
            )
