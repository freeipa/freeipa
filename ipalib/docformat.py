#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""``ipalib.docformat`` — convert IPA plugin docstrings to Markdown, man, RST.

This module provides:

* Pure text utilities: :func:`man_escape`, :func:`md_escape`,
  :func:`rst_escape`, :func:`rst_heading`, :func:`first_line`, etc.
* :func:`convert_docstring` — the main docstring body converter.
* API-aware helpers: :func:`all_canonical_commands`,
  :func:`topic_commands`, :func:`get_topic_doc`, :func:`build_xref`.
* Page generators: :func:`rst_all_topics`, :func:`rst_topic`,
  :func:`md_all_topics`, :func:`md_topic`, :func:`man_all_topics`,
  :func:`man_topic`, etc.

Both the :class:`ipalib.cli.help` command and :mod:`makeapi`
use this module as their shared back-end.
"""

import datetime
import importlib
import re
import sys


# ---------------------------------------------------------------------------
# CLI name helpers (duplicated from ipalib.cli to avoid a circular import)
# ---------------------------------------------------------------------------

def _to_cli(name):
    """Convert an IPA API identifier to its CLI hyphenated form."""
    assert isinstance(name, str)
    return name.replace('_', '-')


def _from_cli(cli_name):
    """Convert a CLI hyphenated name back to an IPA API identifier."""
    return str(cli_name).replace('-', '_')


# ---------------------------------------------------------------------------
# Pure text utilities (no IPA API access)
# ---------------------------------------------------------------------------

def current_year():
    """Return the current year as a string."""
    return str(datetime.date.today().year)


def man_escape(s):
    """Escape a string for groff/man output.

    - ``\\`` → ``\\\\`` (literal backslash in troff)
    - ``-`` → ``\\-`` (non-breaking hyphen-minus)
    - Lines starting with ``.`` or ``'`` get ``\\&`` prepended so that groff
      does not interpret them as requests.
    """
    lines = s.splitlines()
    out = []
    for i, line in enumerate(lines):
        if i:
            out.append('\n')
        if line and line[0] in ('.', "'"):
            out.append('\\&')
        out.append(line.replace('\\', '\\\\').replace('-', '\\-'))
    return ''.join(out)


def md_escape(s):
    """Escape pipe characters for use inside a Markdown table cell."""
    return s.replace('|', '\\|')


def rst_escape(s):
    """Escape a string for use in RST output.

    Backslash-escapes characters that RST interprets as inline markup:
    ``\\``, ``*``, `` ` ``, ``_``, and ``|``.
    """
    out = []
    for ch in s:
        if ch in ('\\', '*', '`', '_', '|'):
            out.append('\\')
        out.append(ch)
    return ''.join(out)


def rst_heading(text, ch, w):
    """Write an RST heading: *text* underlined with *ch* repeated to match."""
    w.write('{}\n{}\n\n'.format(text, ch * len(text)))


def md_inline(text):
    """Convert RST inline markup within *text* to Markdown equivalents."""
    return re.sub(r'``(.+?)``', r'`\1`', text)


def strip_rst_inline(text):
    """Strip RST inline markup from *text* (for plain-text man output)."""
    text = re.sub(r'``(.+?)``', r'\1', text)
    text = re.sub(r'`(.+?)`', r'\1', text)
    return text


def first_line(s):
    """Return the first non-empty stripped line of *s*."""
    for line in s.splitlines():
        line = line.strip()
        if line:
            return line
    return ''


# ---------------------------------------------------------------------------
# Docstring body converter
# ---------------------------------------------------------------------------
#
# IPA plugin module docstrings follow a loose convention:
#
# * ALL-CAPS labels (optionally ending with ':') followed by a blank line
#   act as section headers (e.g. ``EXAMPLES:``, ``GLOBAL TRUST CONFIGURATION``).
# * Some files use RST-style heading underlines (``====``, ``----``, ``~~~~``).
# * Example blocks use 1-space-indented description labels and 3-space-indented
#   shell commands.
# * Dash or star bullet lists (``- item``, ``* item``).
# * Numbered list items (``N. text``) sometimes followed by
#   3-space-indented code.
# * Double-backtick (`` ``code`` ``) and single-backtick (`` `name` ``)
#   inline markup from RST.
#
# convert_docstring() converts such text to Markdown, man, or RST without
# destroying the content.

_RE_UNDERLINE = re.compile(r'^[=\-~^#+]{3,}\s*$')
_RE_ALLCAPS = re.compile(r'^[A-Z][A-Z0-9 _,.-]*:?\s*$')
# Short title-case phrase ending with ':' — e.g. "Examples:", "Usage Notes:".
# Each word must begin with an uppercase letter; at most 4 words total.
_RE_TITLE_HEADING = re.compile(r'^(?:[A-Z][A-Za-z]+ ){0,3}[A-Z][A-Za-z]+:$')
_RE_NUMBERED = re.compile(r'^(\s*)(\d+)\.\s+(.*)')
_RE_BULLET = re.compile(r'^(\s*)([-*])\s+(.*)')
# RST underline characters ordered by conventional heading priority.
_RST_LEVEL = {'=': 1, '-': 2, '~': 3, '^': 4, '#': 1, '+': 2}


def emit_docstring_heading(text, src_level, fmt, out):
    """Append a heading to *out* in the given output *fmt*.

    *src_level* is the heading level from the source (1 = most prominent).
    Because body text always sits below a document-level H1 (topic or command
    name), source level 1 maps to H2 in the output, etc.
    """
    if fmt == 'markdown':
        # Shift one level down relative to the page H1 and cap at H4.
        md_level = min(src_level + 1, 4)
        out.append('\n{} {}\n'.format('#' * md_level, text))
    elif fmt == 'man':
        if src_level <= 1:
            out.append('.SH {}'.format(man_escape(text.upper())))
        else:
            out.append('.SS {}'.format(man_escape(text)))
    else:  # rst
        # Render in-body headings as bold text to avoid interfering with the
        # document-level heading hierarchy (= - ~ ^ established by the topic
        # page structure).  RST heading markup here would scramble the levels
        # seen by docutils and cause "Inconsistent title style" errors.
        out.append('')
        out.append('**{}**'.format(text))
        out.append('')


def convert_docstring(text, fmt):
    """Convert an IPA module docstring body to *fmt* (``'markdown'``, ``'man'``,
    or ``'rst'``).

    The input is the raw docstring text **after** the title line has been
    extracted by the caller.  The function handles the heading, bullet, code,
    and numbered-list conventions used across ``ipaserver/plugins/*.py``.
    """
    lines = text.split('\n')
    out = []
    i = 0
    in_list_item = False    # True after emitting a numbered list item
    in_list = False         # True while in any bullet or numbered list
    pending_pp = False      # man only: emit .PP before next plain text
    # rst only: emit blank before next zero-indent line (closes a block quote)
    pending_rst_blank = False
    bullet_prefix_len = 0   # spaces before '-' in the current bullet item
    bullet_text_col = 0     # column where bullet text starts (prefix + 2)
    context_indent = 0      # rst: indent of last text line (code-block prefix)

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(' ')) if line else 0

        # ── Blank line ────────────────────────────────────────────────────
        if not stripped:
            in_list_item = False
            in_list = False
            pending_rst_blank = False
            if fmt == 'man':
                pending_pp = True
            else:
                out.append('')
            i += 1
            continue

        # ── RST overline+underline heading  ====\nTitle\n==== ───────────
        if (i + 2 < len(lines)
                and _RE_UNDERLINE.match(stripped)
                and lines[i + 1].strip()
                and not _RE_UNDERLINE.match(lines[i + 1].strip())
                and _RE_UNDERLINE.match(lines[i + 2].strip())
                and stripped[0] == lines[i + 2].strip()[0]):
            heading = lines[i + 1].strip()
            level = _RST_LEVEL.get(stripped[0], 2)
            emit_docstring_heading(heading, level, fmt, out)
            pending_pp = False
            pending_rst_blank = False
            in_list_item = False
            in_list = False
            i += 3
            continue

        # ── RST underline heading  Title\n==== ──────────────────────────
        if (i + 1 < len(lines)
                and stripped
                and not _RE_UNDERLINE.match(stripped)
                and _RE_UNDERLINE.match(lines[i + 1].strip())
                and len(lines[i + 1].strip()) >= max(len(stripped) - 2, 2)):
            heading = stripped
            ch = lines[i + 1].strip()[0]
            level = _RST_LEVEL.get(ch, 2)
            emit_docstring_heading(heading, level, fmt, out)
            pending_pp = False
            pending_rst_blank = False
            in_list_item = False
            in_list = False
            i += 2
            continue

        # ── Orphaned underline line (no heading text matched above) ──────
        if _RE_UNDERLINE.match(stripped) and len(stripped) >= 3:
            i += 1
            continue

        # ── Section label: ALL-CAPS or short Title-Case:, followed by blank ─
        next_blank = (i + 1 >= len(lines) or not lines[i + 1].strip())
        if (indent == 0
                and not _RE_NUMBERED.match(stripped)
                and not _RE_BULLET.match(stripped)
                and (_RE_ALLCAPS.match(stripped)
                     or _RE_TITLE_HEADING.match(stripped))
                and next_blank
                and len(stripped) >= 2):
            heading = stripped.rstrip(':').strip()
            emit_docstring_heading(heading, 2, fmt, out)
            pending_pp = False
            pending_rst_blank = False
            in_list_item = False
            in_list = False
            i += 1
            if i < len(lines) and not lines[i].strip():
                i += 1      # skip the blank that follows the label
            continue

        # ── Numbered list item  N. text ──────────────────────────────────
        m = _RE_NUMBERED.match(line)
        if m:
            prefix, num, text_part = m.groups()
            if fmt == 'markdown':
                if pending_pp:
                    out.append('')
                out.append('{}{}. {}'.format(prefix, num, md_inline(text_part)))
            elif fmt == 'man':
                out.append('.TP\n.B {}.\n{}'.format(
                    num, man_escape(strip_rst_inline(text_part))))
            else:
                if out and out[-1] and not in_list:
                    out.append('')  # blank before a new numbered list
                out.append('{}{}. {}'.format(prefix, num, text_part))
            pending_pp = False
            pending_rst_blank = False
            in_list_item = True
            in_list = True
            i += 1
            continue

        # ── Bullet list item  - text  or  * text ────────────────────────
        m = _RE_BULLET.match(line)
        if m:
            prefix, _marker, text_part = m.groups()
            if fmt == 'markdown':
                if pending_pp:
                    out.append('')
                out.append('{}- {}'.format(prefix, md_inline(text_part)))
            elif fmt == 'man':
                out.append('.IP \\(bu\n{}'.format(
                    man_escape(strip_rst_inline(text_part))))
            else:
                if out and out[-1] and not in_list:
                    out.append('')  # blank before a new bullet list
                # Escape trailing * used as glob wildcards (e.g. dnszone-*)
                # so RST does not mistake them for emphasis markup.
                escaped = re.sub(r'(?<=[a-zA-Z0-9_-])\*(?!\*)', r'\\*',
                                 text_part)
                out.append('{}- {}'.format(prefix, escaped))
                bullet_prefix_len = len(prefix)
                bullet_text_col = len(prefix) + 2
            pending_pp = False
            pending_rst_blank = False
            in_list_item = False
            in_list = True
            i += 1
            continue

        # ── Indented text (3+ spaces) ────────────────────────────────────
        if indent >= 3 and stripped:
            if in_list_item:
                # Continuation line of a numbered list item (prose, not code).
                if fmt == 'markdown':
                    out.append('   {}'.format(md_inline(stripped)))
                elif fmt == 'man':
                    out.append(man_escape(strip_rst_inline(stripped)))
                else:
                    out.append(line.rstrip())
                i += 1
            else:
                # Code block: collect consecutive indented-or-blank lines.
                start = i
                while i < len(lines) and (
                        not lines[i].strip()
                        or (len(lines[i]) - len(lines[i].lstrip(' ')) >= 3)):
                    i += 1
                block = lines[start:i]
                while block and not block[-1].strip():
                    block.pop()

                if fmt == 'markdown':
                    dedented = [l[3:] if len(l) >= 3 else l for l in block]
                    out.append('```\n{}\n```'.format('\n'.join(dedented)))
                elif fmt == 'man':
                    code = [man_escape(l.strip())
                            for l in block if l.strip()]
                    if code:
                        out.append(
                            '.nf\n.RS 4\n{}\n.RE\n.fi'.format('\n'.join(code)))
                else:  # rst
                    dedented = [l[3:] if len(l) >= 3 else l for l in block]
                    pfx = ' ' * context_indent
                    out.append('')  # blank line ends preceding paragraph
                    out.append('{}.. code-block:: console'.format(pfx))
                    out.append('')
                    for dl in dedented:
                        if dl.strip():
                            out.append('{}   {}'.format(pfx, dl.rstrip()))
                        else:
                            out.append('')
                    out.append('')
                    pending_rst_blank = False
                pending_pp = False
            continue

        # ── Normal text ───────────────────────────────────────────────────
        in_list_item = False
        if fmt == 'markdown':
            if pending_pp:
                out.append('')
            out.append(md_inline(line.rstrip()))
        elif fmt == 'man':
            if pending_pp:
                out.append('.PP')
            out.append(man_escape(strip_rst_inline(line.rstrip())))
        else:  # rst
            if indent == 0 and pending_rst_blank and out and out[-1]:
                # Closing a block-quote section (1-2 space indent) — add blank
                # so RST sees the block quote as properly terminated.
                out.append('')
            elif 0 < indent < 3 and not in_list and out and out[-1]:
                # Opening a block-quote right after a normal paragraph — add
                # blank so RST does not report "Unexpected indentation".
                out.append('')
            if (in_list and 0 < indent < bullet_text_col
                    and indent == bullet_prefix_len and stripped):
                # Bullet continuation indented to the prefix column rather than
                # the text column: re-indent to align with the bullet text so
                # RST sees it as a proper continuation, not an unindent.
                out.append(' ' * bullet_text_col + stripped)
            else:
                out.append(line.rstrip())
            pending_rst_blank = (0 < indent < 3)
            context_indent = indent
        pending_pp = False
        i += 1

    return '\n'.join(out)


# ---------------------------------------------------------------------------
# Cross-reference linkification
# ---------------------------------------------------------------------------

def linkify_md(text, xref_commands):
    """Wrap known hyphenated IPA command names in Markdown links.

    Only hyphenated words (e.g. ``user-add``) are considered.
    Single-word topic names are skipped to avoid false positives.
    """
    result = []
    word = []
    for ch in text:
        if ch.islower() or ch.isdigit() or ch == '-':
            word.append(ch)
        else:
            result.append(_flush_word_md(''.join(word), xref_commands))
            word = []
            result.append(ch)
    result.append(_flush_word_md(''.join(word), xref_commands))
    return ''.join(result)


def _flush_word_md(word, xref_commands):
    if '-' in word and word in xref_commands:
        topic = xref_commands[word]
        return '[{w}]({t}.md#{w})'.format(w=word, t=topic)
    return word


def linkify_rst(text, xref_commands):
    """Wrap known hyphenated IPA command names in RST inline-literal markup.

    Only hyphenated words (e.g. ``user-add``) are considered.
    Single-word topic names are skipped to avoid false positives.
    Lines with 3+ spaces of indentation (RST code blocks) are left as-is.
    """
    out = []
    for line in text.split('\n'):
        indent = len(line) - len(line.lstrip(' ')) if line else 0
        if indent >= 3:
            out.append(line)
            continue
        result = []
        word = []
        for ch in line:
            if ch.islower() or ch.isdigit() or ch == '-':
                word.append(ch)
            else:
                result.append(_flush_word_rst(''.join(word), xref_commands))
                word = []
                result.append(ch)
        result.append(_flush_word_rst(''.join(word), xref_commands))
        out.append(''.join(result))
    return '\n'.join(out)


def _flush_word_rst(word, xref_commands):
    if '-' in word and word in xref_commands:
        return '``{}``'.format(word)
    return word


# ---------------------------------------------------------------------------
# API-aware helpers
# ---------------------------------------------------------------------------

def all_canonical_commands(api):
    """Yield ``(api_name, cmd)`` for every canonical, CLI-visible command."""
    for cmd in api.Command:
        if cmd is not api.Command.get_plugin(cmd.name):
            continue
        if cmd.NO_CLI:
            continue
        yield cmd.name, cmd


def topic_commands(api, topic):
    """Return a sorted list of CLI command names that belong to *topic*."""
    return sorted(
        _to_cli(api_name)
        for api_name, cmd in all_canonical_commands(api)
        if cmd.topic == topic
    )


def get_topic_doc(api, topic):
    """Return the module docstring for *topic*, or ``''`` if not found."""
    for package in api.packages:
        module_name = '{}.{}'.format(package.__name__, topic)
        module = sys.modules.get(module_name)
        if module is None:
            try:
                module = importlib.import_module(module_name)
            except ImportError:
                continue
        if module.__doc__:
            return str(module.__doc__).strip()
    return ''


def build_xref(api):
    """Build cross-reference maps.

    Returns a pair:

    - ``commands``: ``{cli_cmd: cli_topic}``
    - ``by_topic``: ``{cli_topic: [cli_cmd, ...]}`` (each list sorted)
    """
    commands = {}
    by_topic = {}
    for api_name, cmd in all_canonical_commands(api):
        cli = _to_cli(api_name)
        topic = _to_cli(cmd.topic) if cmd.topic else ''
        commands[cli] = topic
        by_topic.setdefault(topic, []).append(cli)
    for lst in by_topic.values():
        lst.sort()
    return commands, by_topic


# ---------------------------------------------------------------------------
# RST page generators
# ---------------------------------------------------------------------------

def rst_all_topics(api, w):
    """Write an RST overview page listing topics with one-line descriptions."""
    rst_heading('IPA Command Reference', '=', w)
    rst_heading('Topics', '-', w)

    topics = {}
    for _api_name, cmd in all_canonical_commands(api):
        t = cmd.topic or ''
        if t not in topics:
            topics[t] = first_line(str(cmd.summary)) if cmd.name == t else ''

    for t in sorted(topics):
        if not topics[t]:
            topics[t] = first_line(get_topic_doc(api, t))

    # Hidden toctree so Sphinx indexes and links all topic files.
    w.write('.. toctree::\n')
    w.write('   :hidden:\n')
    w.write('\n')
    for t in sorted(topics):
        w.write('   {}\n'.format(_to_cli(t)))
    w.write('\n')

    w.write('.. list-table::\n')
    w.write('   :header-rows: 1\n')
    w.write('   :widths: 20 80\n')
    w.write('\n')
    w.write('   * - Topic\n')
    w.write('     - Description\n')
    for t in sorted(topics):
        w.write('   * - :doc:`{}`\n'.format(_to_cli(t)))
        w.write('     - {}\n'.format(rst_escape(topics[t])))
    w.write(
        '\nUse ``ipa help --format rst <TOPIC>`` or '
        '``ipa help --format rst <COMMAND>`` for details.\n'
    )


def rst_topic(api, topic, w, xref_commands):
    """Write an RST page for one topic.  Returns ``True`` if topic was found."""
    cmd_names = topic_commands(api, topic)
    if not cmd_names:
        return False

    topic_doc = get_topic_doc(api, topic)
    if topic_doc:
        heading = first_line(topic_doc)
        rest_parts = topic_doc.split('\n\n', 1)
        rest = rest_parts[1].strip() if len(rest_parts) > 1 else ''
    else:
        heading = topic.capitalize()
        rest = ''

    rst_heading(heading, '=', w)
    if rest:
        converted = convert_docstring(rest, 'rst')
        w.write('{}\n\n'.format(linkify_rst(converted, xref_commands)))

    rst_heading('Commands', '-', w)

    # Summary table.
    w.write('.. list-table::\n')
    w.write('   :header-rows: 1\n')
    w.write('   :widths: 30 70\n')
    w.write('\n')
    w.write('   * - Command\n')
    w.write('     - Description\n')
    for cli in cmd_names:
        api_name = _from_cli(cli)
        if api_name in api.Command:
            cmd = api.Command[api_name]
            w.write('   * - `{}`_\n'.format(cli))
            w.write('     - {}\n'.format(
                rst_escape(first_line(str(cmd.summary or '')))))
    w.write('\n')

    # Per-command sections.
    for cli in cmd_names:
        api_name = _from_cli(cli)
        if api_name in api.Command:
            cmd = api.Command[api_name]
            w.write('----\n\n')
            w.write('.. _{}:\n\n'.format(cli))
            rst_heading(cli, '~', w)
            rst_command_body(api, cmd, '^', w, xref_commands)

    return True


def rst_command_body(api, cmd, sub_heading_char, w, xref_commands):
    """Render the RST body sections for one command."""
    from ipalib.parameters import Flag
    cli_name = _to_cli(cmd.name)
    doc = str(cmd.doc or '')

    args_list = list(cmd.args())
    args_str = ''.join(
        '[{}] '.format(_to_cli(p.cli_name).upper())
        if not p.required or p.autofill
        else '{} '.format(_to_cli(p.cli_name).upper())
        for p in args_list
    )
    w.write(
        '**Usage:** ``ipa [global-options] {} {}[options]``\n\n'.format(
            cli_name, args_str)
    )

    if doc.strip():
        converted = convert_docstring(doc.strip(), 'rst')
        w.write('{}\n\n'.format(linkify_rst(converted, xref_commands)))

    if args_list:
        rst_heading('Arguments', sub_heading_char, w)
        w.write('.. list-table::\n')
        w.write('   :header-rows: 1\n')
        w.write('   :widths: 20 10 70\n')
        w.write('\n')
        w.write('   * - Argument\n')
        w.write('     - Required\n')
        w.write('     - Description\n')
        for p in args_list:
            req = 'yes' if p.required and not p.autofill else 'no'
            w.write('   * - ``{}``\n'.format(_to_cli(p.cli_name).upper()))
            w.write('     - {}\n'.format(req))
            w.write('     - {}\n'.format(
                rst_escape(first_line(str(p.doc or '')))))
        w.write('\n')

    opts_list = [p for p in cmd.options() if 'no_option' not in p.flags]
    if opts_list:
        rst_heading('Options', sub_heading_char, w)
        w.write('.. list-table::\n')
        w.write('   :header-rows: 1\n')
        w.write('   :widths: 30 70\n')
        w.write('\n')
        w.write('   * - Option\n')
        w.write('     - Description\n')
        for p in opts_list:
            if isinstance(p, Flag):
                flag = '--{}'.format(_to_cli(p.cli_name))
            else:
                flag = '--{} {}'.format(
                    _to_cli(p.cli_name),
                    _to_cli(p.cli_name).upper())
            w.write('   * - ``{}``\n'.format(flag))
            w.write('     - {}\n'.format(
                rst_escape(first_line(str(p.doc or '')))))
        w.write('\n')


def generate_rst(api, name, w):
    """Write RST for *name* (topic or command) to *w*, or the full index if
    *name* is ``None``."""
    xref_commands, _by_topic = build_xref(api)

    if name is None:
        rst_all_topics(api, w)
        return

    api_name = _from_cli(name)

    if api_name in api.Command:
        cmd = api.Command[api_name]
        rst_heading(_to_cli(api_name), '=', w)
        rst_command_body(api, cmd, '-', w, xref_commands)
        return

    if rst_topic(api, api_name, w, xref_commands):
        return

    print(
        "ipa: ERROR: no command or topic '{}'".format(name),
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Markdown page generators
# ---------------------------------------------------------------------------

def md_all_topics(api, w):
    """Write a Markdown overview page listing all topics."""
    w.write('# IPA Command Reference\n\n')
    w.write('## Topics\n\n')
    w.write('| Topic | Description |\n')
    w.write('|-------|-------------|\n')

    topics = {}
    for _api_name, cmd in all_canonical_commands(api):
        t = cmd.topic or ''
        if t not in topics:
            topics[t] = str(cmd.summary) if cmd.name == t else ''

    for t in sorted(topics):
        if not topics[t]:
            topics[t] = first_line(get_topic_doc(api, t))

    for t in sorted(topics):
        w.write('| [`{t}`]({t}.md) | {d} |\n'.format(
            t=_to_cli(t), d=md_escape(topics[t])))

    w.write(
        '\nUse `ipa help --format markdown <TOPIC>` or '
        '`ipa help --format markdown <COMMAND>` for details.\n'
    )


def md_topic(api, topic, w, xref_commands):
    """Write a Markdown page for one topic.  Returns ``True`` if found."""
    cmd_names = topic_commands(api, topic)
    if not cmd_names:
        return False

    topic_doc = get_topic_doc(api, topic)
    if topic_doc:
        heading = first_line(topic_doc)
        rest_parts = topic_doc.split('\n\n', 1)
        rest = rest_parts[1].strip() if len(rest_parts) > 1 else ''
    else:
        heading = topic.capitalize()
        rest = ''

    w.write('# {}\n\n'.format(heading))
    if rest:
        converted = convert_docstring(rest, 'markdown')
        w.write('{}\n\n'.format(linkify_md(converted, xref_commands)))

    w.write('## Commands\n\n')
    w.write('| Command | Description |\n')
    w.write('|---------|-------------|\n')
    for cli in cmd_names:
        api_name = _from_cli(cli)
        if api_name in api.Command:
            cmd = api.Command[api_name]
            w.write('| [`{c}`](#{c}) | {d} |\n'.format(
                c=cli, d=md_escape(str(cmd.summary or ''))))
    w.write('\n')

    for cli in cmd_names:
        api_name = _from_cli(cli)
        if api_name in api.Command:
            cmd = api.Command[api_name]
            w.write('---\n\n### {}\n\n'.format(cli))
            md_command_body(api, cmd, '####', w, xref_commands)

    return True


def md_command_body(api, cmd, sub_heading, w, xref_commands):
    """Render the Markdown body sections for one command."""
    from ipalib.parameters import Flag
    cli_name = _to_cli(cmd.name)
    doc = str(cmd.doc or '')

    args_list = list(cmd.args())
    args_str = ''.join(
        '[{}] '.format(_to_cli(p.cli_name).upper())
        if not p.required or p.autofill
        else '{} '.format(_to_cli(p.cli_name).upper())
        for p in args_list
    )
    w.write(
        '**Usage:** `ipa [global-options] {} {}[options]`\n\n'.format(
            cli_name, args_str)
    )

    if doc.strip():
        converted = convert_docstring(doc.strip(), 'markdown')
        w.write('{}\n\n'.format(linkify_md(converted, xref_commands)))

    if args_list:
        w.write('{} Arguments\n\n'.format(sub_heading))
        w.write('| Argument | Required | Description |\n')
        w.write('|----------|----------|-------------|\n')
        for p in args_list:
            req = 'yes' if p.required and not p.autofill else 'no'
            w.write('| `{}` | {} | {} |\n'.format(
                _to_cli(p.cli_name).upper(),
                req,
                md_escape(str(p.doc or ''))))
        w.write('\n')

    opts_list = [p for p in cmd.options() if 'no_option' not in p.flags]
    if opts_list:
        w.write('{} Options\n\n'.format(sub_heading))
        w.write('| Option | Description |\n')
        w.write('|--------|-------------|\n')
        for p in opts_list:
            if isinstance(p, Flag):
                flag = '--{}'.format(_to_cli(p.cli_name))
            else:
                flag = '--{} {}'.format(
                    _to_cli(p.cli_name),
                    _to_cli(p.cli_name).upper())
            w.write('| `{}` | {} |\n'.format(
                flag, md_escape(str(p.doc or ''))))
        w.write('\n')


def generate_markdown(api, name, w):
    """Write Markdown for *name* (topic or command) to *w*, or the full
    index if *name* is ``None``."""
    xref_commands, _by_topic = build_xref(api)

    if name is None:
        md_all_topics(api, w)
        return

    api_name = _from_cli(name)

    if api_name in api.Command:
        cmd = api.Command[api_name]
        w.write('# {}\n\n'.format(_to_cli(api_name)))
        md_command_body(api, cmd, '###', w, xref_commands)
        return

    if md_topic(api, api_name, w, xref_commands):
        return

    print(
        "ipa: ERROR: no command or topic '{}'".format(name),
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# man-page generators
# ---------------------------------------------------------------------------

def man_all_topics(api, w):
    """Write a top-level man page listing all topics."""
    date = current_year()
    w.write('.TH IPA 1 "{}" "FreeIPA" "IPA Manual"\n'.format(date))
    w.write('.SH NAME\n')
    w.write('ipa \\- IPA command\\-line interface\n')
    w.write('.SH DESCRIPTION\n')
    w.write(
        'The \\fBipa\\fR command provides access to the IPA '
        'directory service.\n'
    )
    w.write('.SH TOPICS\n')

    topics = {}
    for _api_name, cmd in all_canonical_commands(api):
        t = cmd.topic or ''
        if t not in topics:
            topics[t] = str(cmd.summary) if cmd.name == t else ''

    for t in sorted(topics):
        if not topics[t]:
            topics[t] = first_line(get_topic_doc(api, t))

    for t in sorted(topics):
        desc = topics[t]
        w.write('.TP\n')
        w.write('.B {}\n'.format(man_escape(_to_cli(t))))
        if desc:
            w.write('{}\n'.format(man_escape(desc)))


def man_topic(api, topic, w, xref_by_topic):
    """Write a man page for one topic.  Returns ``True`` if found."""
    cmd_names = topic_commands(api, topic)
    if not cmd_names:
        return False

    topic_doc = get_topic_doc(api, topic)
    if topic_doc:
        heading = first_line(topic_doc)
        parts = topic_doc.split('\n\n', 1)
        body = parts[1].strip() if len(parts) > 1 else ''
    else:
        heading = topic.capitalize()
        body = ''

    man_topic_name = 'ipa-{}'.format(_to_cli(topic))
    date = current_year()
    w.write('.TH {} 1 "{}" "FreeIPA" "IPA Manual"\n'.format(
        man_escape(man_topic_name.upper()), date))
    w.write('.SH NAME\n')
    w.write('{} \\- {}\n'.format(
        man_escape(man_topic_name), man_escape(heading)))

    if body:
        w.write('.SH DESCRIPTION\n')
        w.write('{}\n'.format(convert_docstring(body, 'man')))

    w.write('.SH COMMANDS\n')
    for cli in cmd_names:
        api_name = _from_cli(cli)
        if api_name in api.Command:
            cmd = api.Command[api_name]
            w.write('.SS {}\n'.format(man_escape(cli)))
            man_subsection_body(api, cmd, w)

    see = [
        '.BR ipa\\-{} (1)'.format(man_escape(c))
        for c in cmd_names
    ]
    if see:
        w.write('.SH SEE ALSO\n')
        w.write(',\n'.join(see) + '\n')

    return True


def man_subsection_body(api, cmd, w):
    """Render command content inside a ``.SS`` subsection (topic man page)."""
    from ipalib.parameters import Flag
    doc = str(cmd.doc or '')
    if doc.strip():
        w.write('{}\n'.format(convert_docstring(doc.strip(), 'man')))

    args_list = list(cmd.args())
    if args_list:
        w.write('.PP\n.B Arguments\n.RS\n')
        for p in args_list:
            w.write('.TP\n')
            upper = _to_cli(p.cli_name).upper()
            if p.required and not p.autofill:
                w.write('.B {}\n'.format(man_escape(upper)))
            else:
                w.write('.I {}\n'.format(man_escape(upper)))
            w.write('{}\n'.format(man_escape(str(p.doc or ''))))
        w.write('.RE\n')

    opts_list = [p for p in cmd.options() if 'no_option' not in p.flags]
    if opts_list:
        w.write('.PP\n.B Options\n.RS\n')
        for p in opts_list:
            if isinstance(p, Flag):
                flag = '--{}'.format(_to_cli(p.cli_name))
            else:
                flag = '--{} {}'.format(
                    _to_cli(p.cli_name),
                    _to_cli(p.cli_name).upper())
            w.write('.TP\n')
            w.write('.B {}\n'.format(man_escape(flag)))
            w.write('{}\n'.format(man_escape(str(p.doc or ''))))
        w.write('.RE\n')


def man_command_body(api, cmd, w):
    """Render ``.SH DESCRIPTION``, ``.SH ARGUMENTS``, ``.SH OPTIONS``."""
    from ipalib.parameters import Flag
    doc = str(cmd.doc or '')
    if doc.strip():
        w.write('.SH DESCRIPTION\n')
        w.write('{}\n'.format(convert_docstring(doc.strip(), 'man')))

    args_list = list(cmd.args())
    if args_list:
        w.write('.SH ARGUMENTS\n')
        for p in args_list:
            w.write('.TP\n')
            upper = _to_cli(p.cli_name).upper()
            if p.required and not p.autofill:
                w.write('.B {}\n'.format(man_escape(upper)))
            else:
                w.write('.I {}\n'.format(man_escape(upper)))
            w.write('{}\n'.format(man_escape(str(p.doc or ''))))

    opts_list = [p for p in cmd.options() if 'no_option' not in p.flags]
    if opts_list:
        w.write('.SH OPTIONS\n')
        for p in opts_list:
            if isinstance(p, Flag):
                flag = '--{}'.format(_to_cli(p.cli_name))
            else:
                flag = '--{} {}'.format(
                    _to_cli(p.cli_name),
                    _to_cli(p.cli_name).upper())
            w.write('.TP\n')
            w.write('.B {}\n'.format(man_escape(flag)))
            w.write('{}\n'.format(man_escape(str(p.doc or ''))))


def man_see_also(cli_name, xref_commands, xref_by_topic, w):
    """Write a ``.SH SEE ALSO`` section with sibling commands."""
    topic = xref_commands.get(cli_name)
    if not topic:
        return
    peers = [c for c in xref_by_topic.get(topic, []) if c != cli_name]
    if not peers:
        return
    w.write('.SH SEE ALSO\n')
    entries = [
        '.BR ipa\\-{} (1)'.format(man_escape(c))
        for c in peers
    ]
    w.write(',\n'.join(entries) + '\n')


def man_single_command(api, cmd, api_name, w, xref_commands, xref_by_topic):
    """Write a standalone man page for one command."""
    cli_name = _to_cli(api_name)
    man_name = 'ipa-{}'.format(cli_name)
    date = current_year()

    w.write('.TH {} 1 "{}" "FreeIPA" "IPA Manual"\n'.format(
        man_escape(man_name.upper()), date))
    w.write('.SH NAME\n')
    w.write('{} \\- {}\n'.format(
        man_escape(man_name), man_escape(str(cmd.summary or ''))))

    args_list = list(cmd.args())
    args_str = ''.join(
        '[{}] '.format(_to_cli(p.cli_name).upper())
        if not p.required or p.autofill
        else '{} '.format(_to_cli(p.cli_name).upper())
        for p in args_list
    )
    w.write('.SH SYNOPSIS\n')
    w.write('ipa [global\\-options] {} {}[options]\n'.format(
        man_escape(cli_name), man_escape(args_str)))

    man_command_body(api, cmd, w)
    man_see_also(cli_name, xref_commands, xref_by_topic, w)


def generate_man(api, name, w):
    """Write a man page for *name* (topic or command) to *w*, or the
    top-level topic index if *name* is ``None``."""
    xref_commands, xref_by_topic = build_xref(api)

    if name is None:
        man_all_topics(api, w)
        return

    api_name = _from_cli(name)

    if api_name in api.Command:
        cmd = api.Command[api_name]
        man_single_command(api, cmd, api_name, w, xref_commands, xref_by_topic)
        return

    if man_topic(api, api_name, w, xref_by_topic):
        return

    print(
        "ipa: ERROR: no command or topic '{}'".format(name),
        file=sys.stderr,
    )
