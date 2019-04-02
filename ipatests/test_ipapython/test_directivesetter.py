#
# Copyright (C) 2017  FreeIPA Contributors.  See COPYING for license
#
from __future__ import absolute_import

import os
import tempfile

from ipapython import directivesetter

EXAMPLE_CONFIG = [
    'foo=1\n',
    'foobar=2\n',
]

WHITESPACE_CONFIG = [
    'foo 1\n',
    'foobar\t2\n',
]


class test_set_directive_lines:
    def test_remove_directive(self):
        lines = directivesetter.set_directive_lines(
            False, '=', 'foo', None, EXAMPLE_CONFIG, comment="#")
        assert list(lines) == ['foobar=2\n']

    def test_add_directive(self):
        lines = directivesetter.set_directive_lines(
            False, '=', 'baz', '4', EXAMPLE_CONFIG, comment="#")
        assert list(lines) == ['foo=1\n', 'foobar=2\n', 'baz=4\n']

    def test_set_directive_does_not_clobber_suffix_key(self):
        lines = directivesetter.set_directive_lines(
            False, '=', 'foo', '3', EXAMPLE_CONFIG, comment="#")
        assert list(lines) == ['foo=3\n', 'foobar=2\n']


class test_set_directive_lines_whitespace:
    def test_remove_directive(self):
        lines = directivesetter.set_directive_lines(
            False, ' ', 'foo', None, WHITESPACE_CONFIG, comment="#")
        assert list(lines) == ['foobar\t2\n']

    def test_add_directive(self):
        lines = directivesetter.set_directive_lines(
            False, ' ', 'baz', '4', WHITESPACE_CONFIG, comment="#")
        assert list(lines) == ['foo 1\n', 'foobar\t2\n', 'baz 4\n']

    def test_set_directive_does_not_clobber_suffix_key(self):
        lines = directivesetter.set_directive_lines(
            False, ' ', 'foo', '3', WHITESPACE_CONFIG, comment="#")
        assert list(lines) == ['foo 3\n', 'foobar\t2\n']

    def test_set_directive_with_tab(self):
        lines = directivesetter.set_directive_lines(
            False, ' ', 'foobar', '6', WHITESPACE_CONFIG, comment="#")
        assert list(lines) == ['foo 1\n', 'foobar 6\n']


class test_set_directive:
    def test_set_directive(self):
        """Check that set_directive writes the new data and preserves mode."""
        fd, filename = tempfile.mkstemp()
        try:
            os.close(fd)
            stat_pre = os.stat(filename)

            with open(filename, 'w') as f:
                for line in EXAMPLE_CONFIG:
                    f.write(line)

            directivesetter.set_directive(
                filename, 'foo', '3', False, '=', "#")

            stat_post = os.stat(filename)
            with open(filename, 'r') as f:
                lines = list(f)

            assert lines == ['foo=3\n', 'foobar=2\n']
            assert stat_pre.st_mode == stat_post.st_mode
            assert stat_pre.st_uid == stat_post.st_uid
            assert stat_pre.st_gid == stat_post.st_gid

        finally:
            os.remove(filename)


class test_get_directive:
    def test_get_directive(self, tmpdir):
        configfile = tmpdir.join('config')
        configfile.write(''.join(EXAMPLE_CONFIG))

        assert '1' == directivesetter.get_directive(str(configfile),
                                                    'foo',
                                                    separator='=')
        assert '2' == directivesetter.get_directive(str(configfile),
                                                    'foobar',
                                                    separator='=')


class test_get_directive_whitespace:
    def test_get_directive(self, tmpdir):
        configfile = tmpdir.join('config')
        configfile.write(''.join(WHITESPACE_CONFIG))

        assert '1' == directivesetter.get_directive(str(configfile),
                                                    'foo')
        assert '2' == directivesetter.get_directive(str(configfile),
                                                    'foobar')


def test_directivesetter(tempdir):
    filename = os.path.join(tempdir, 'example.conf')
    with open(filename, 'w') as f:
        for line in EXAMPLE_CONFIG:
            f.write(line)

    ds = directivesetter.DirectiveSetter(filename)
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

    with directivesetter.DirectiveSetter(filename, True, '=') as ds:
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
