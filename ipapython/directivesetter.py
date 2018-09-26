#
# Copyright (C) 2018 FreeIPA Contributors see COPYING for license
#

import six

import io
import os
import re
import stat
import tempfile

from ipapython.ipautil import unescape_seq, escape_seq

_SENTINEL = object()


class DirectiveSetter:
    """Safe directive setter

    with DirectiveSetter('/path/to/conf') as ds:
        ds.set(key, value)
    """
    def __init__(self, filename, quotes=True, separator=' ', comment='#'):
        self.filename = os.path.abspath(filename)
        self.quotes = quotes
        self.separator = separator
        self.comment = comment
        self.lines = None
        self.stat = None

    def __enter__(self):
        with io.open(self.filename) as f:
            self.stat = os.fstat(f.fileno())
            self.lines = list(f)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # something went wrong, reset
            self.lines = None
            self.stat = None
            return

        directory, prefix = os.path.split(self.filename)
        # use tempfile in same directory to have atomic rename
        fd, name = tempfile.mkstemp(prefix=prefix, dir=directory, text=True)
        with io.open(fd, mode='w', closefd=True) as f:
            for line in self.lines:
                if not isinstance(line, six.text_type):
                    line = line.decode('utf-8')
                f.write(line)
            self.lines = None
            os.fchmod(f.fileno(), stat.S_IMODE(self.stat.st_mode))
            os.fchown(f.fileno(), self.stat.st_uid, self.stat.st_gid)
            self.stat = None
            # flush and sync tempfile inode
            f.flush()
            os.fsync(f.fileno())

        # rename file and sync directory inode
        os.rename(name, self.filename)
        dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)

    def set(self, directive, value, quotes=_SENTINEL, separator=_SENTINEL,
            comment=_SENTINEL):
        """Set a single directive
        """
        if quotes is _SENTINEL:
            quotes = self.quotes
        if separator is _SENTINEL:
            separator = self.separator
        if comment is _SENTINEL:
            comment = self.comment
        # materialize lines
        # set_directive_lines() modify item, shrink or enlage line count
        self.lines = list(set_directive_lines(
            quotes, separator, directive, value, self.lines, comment
        ))

    def setitems(self, items):
        """Set multiple directives from a dict or list with key/value pairs
        """
        if isinstance(items, dict):
            # dict-like, use sorted for stable order
            items = sorted(items.items())
        for k, v in items:
            self.set(k, v)


def set_directive(filename, directive, value, quotes=True, separator=' ',
                  comment='#'):
    """Set a name/value pair directive in a configuration file.

    A value of None means to drop the directive.

    Does not tolerate (or put) spaces around the separator.

    :param filename: input filename
    :param directive: directive name
    :param value: value of the directive
    :param quotes: whether to quote `value` in double quotes. If true, then
        any existing double quotes are first escaped to avoid
        unparseable directives.
    :param separator: character serving as separator between directive and
        value.  Correct value required even when dropping a directive.
    :param comment: comment character for the file to keep new values near
                    their commented-out counterpart
    """
    st = os.stat(filename)
    with open(filename, 'r') as f:
        lines = list(f)  # read the whole file
        # materialize new list
        new_lines = list(set_directive_lines(
            quotes, separator, directive, value, lines, comment
        ))
    with open(filename, 'w') as f:
        # don't construct the whole string; write line-wise
        for line in new_lines:
            f.write(line)
    os.chown(filename, st.st_uid, st.st_gid)  # reset perms


def set_directive_lines(quotes, separator, k, v, lines, comment):
    """Set a name/value pair in a configuration (iterable of lines).

    Replaces the value of the key if found, otherwise adds it at
    end.  If value is ``None``, remove the key if found.

    Takes an iterable of lines (with trailing newline).
    Yields lines (with trailing newline).

    """
    new_line = ""
    if v is not None:
        v_quoted = quote_directive_value(v, '"') if quotes else v
        new_line = ''.join([k, separator, v_quoted, '\n'])

    # Special case: consider space as "white space" so tabs are allowed
    if separator == ' ':
        separator = '[ \t]+'

    found = False
    addnext = False  # add on next line, found a comment
    matcher = re.compile(r'\s*{}\s*{}'.format(re.escape(k), separator))
    cmatcher = re.compile(r'\s*{}\s*{}\s*{}'.format(comment,
                                                    re.escape(k), separator))
    for line in lines:
        if matcher.match(line):
            found = True
            addnext = False
            if v is not None:
                yield new_line
        elif addnext:
            found = True
            addnext = False
            yield new_line
            yield line
        elif cmatcher.match(line):
            addnext = True
            yield line
        else:
            yield line

    if not found and v is not None:
        yield new_line


def get_directive(filename, directive, separator=' '):
    """
    A rather inefficient way to get a configuration directive.

    :param filename: input filename
    :param directive: directive name
    :param separator: separator between directive and value

    :returns: The (unquoted) value if the directive was found, None otherwise
    """
    # Special case: consider space as "white space" so tabs are allowed
    if separator == ' ':
        separator = '[ \t]+'

    result = None
    with open(filename, "r") as fd:
        for line in fd:
            if line.lstrip().startswith(directive):
                line = line.strip()

                match = re.match(
                    r'{}\s*{}\s*(.*)'.format(directive, separator), line)
                if match:
                    value = match.group(1)
                else:
                    raise ValueError("Malformed directive: {}".format(line))

                result = unquote_directive_value(value.strip(), '"')
                result = result.strip(' ')
                break
    return result


def quote_directive_value(value, quote_char):
    """Quote a directive value
    :param value: string to quote
    :param quote_char: character which is used for quoting. All prior
        occurences will be escaped before quoting to avoid unparseable value.
    :returns: processed value
    """
    if value.startswith(quote_char) and value.endswith(quote_char):
        return value

    return "{quote}{value}{quote}".format(
        quote=quote_char,
        value="".join(escape_seq(quote_char, value))
    )


def unquote_directive_value(value, quote_char):
    """Unquote a directive value
    :param value: string to unquote
    :param quote_char: character to strip. All escaped occurences of
        `quote_char` will be uncescaped during processing
    :returns: processed value
    """
    unescaped_value = "".join(unescape_seq(quote_char, value))
    if (unescaped_value.startswith(quote_char) and
            unescaped_value.endswith(quote_char)):
        return unescaped_value[1:-1]

    return unescaped_value
