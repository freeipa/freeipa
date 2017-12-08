#
# Copyright (C) 2017  FreeIPA Contributors.  See COPYING for license
#

import os
import shutil
import tempfile

import pytest

from ipaserver.install import installutils

EXAMPLE_CONFIG = [
    'foo=1\n',
    'foobar=2\n',
]


@pytest.fixture
def tempdir(request):
    tempdir = tempfile.mkdtemp()

    def fin():
        shutil.rmtree(tempdir)

    request.addfinalizer(fin)
    return tempdir


class test_set_directive_lines(object):
    def test_remove_directive(self):
        lines = installutils.set_directive_lines(
            False, '=', 'foo', None, EXAMPLE_CONFIG)
        assert list(lines) == ['foobar=2\n']

    def test_add_directive(self):
        lines = installutils.set_directive_lines(
            False, '=', 'baz', '4', EXAMPLE_CONFIG)
        assert list(lines) == ['foo=1\n', 'foobar=2\n', 'baz=4\n']

    def test_set_directive_does_not_clobber_suffix_key(self):
        lines = installutils.set_directive_lines(
            False, '=', 'foo', '3', EXAMPLE_CONFIG)
        assert list(lines) == ['foo=3\n', 'foobar=2\n']


class test_set_directive(object):
    def test_set_directive(self):
        """Check that set_directive writes the new data and preserves mode."""
        fd, filename = tempfile.mkstemp()
        try:
            os.close(fd)
            stat_pre = os.stat(filename)

            with open(filename, 'w') as f:
                for line in EXAMPLE_CONFIG:
                    f.write(line)

            installutils.set_directive(filename, 'foo', '3', False, '=')

            stat_post = os.stat(filename)
            with open(filename, 'r') as f:
                lines = list(f)

            assert lines == ['foo=3\n', 'foobar=2\n']
            assert stat_pre.st_mode == stat_post.st_mode
            assert stat_pre.st_uid == stat_post.st_uid
            assert stat_pre.st_gid == stat_post.st_gid

        finally:
            os.remove(filename)


def test_directivesetter(tempdir):
    filename = os.path.join(tempdir, 'example.conf')
    with open(filename, 'w') as f:
        for line in EXAMPLE_CONFIG:
            f.write(line)

    ds = installutils.DirectiveSetter(filename)
    assert ds.lines is None
    with ds:
        assert ds.lines == EXAMPLE_CONFIG
        ds.set('foo', '3')  # quoted, space separated, doesn't change 'foo='
        ds.set('foobar', None, separator='=')  # remove
        ds.set('baz', '4', False, '=')  # add
        ds.setitems([
            ('list1', 'value1'),
            ('list2', 'value2'),
        ])
        ds.setitems({
            'dict1': 'value1',
            'dict2': 'value2',
        })

    with open(filename, 'r') as f:
        lines = list(f)

    assert lines == [
        'foo=1\n',
        'foo "3"\n',
        'baz=4\n',
        'list1 "value1"\n',
        'list2 "value2"\n',
        'dict1 "value1"\n',
        'dict2 "value2"\n',
    ]

    with installutils.DirectiveSetter(filename, True, '=') as ds:
        ds.set('foo', '4')  # doesn't change 'foo '

    with open(filename, 'r') as f:
        lines = list(f)

    assert lines == [
        'foo="4"\n',
        'foo "3"\n',
        'baz=4\n',
        'list1 "value1"\n',
        'list2 "value2"\n',
        'dict1 "value1"\n',
        'dict2 "value2"\n',

    ]
