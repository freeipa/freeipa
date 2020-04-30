===============================
Format Python code with |Black|
===============================

.. sectionauthor:: Christian Heimes

**WORK IN PROGRESS**

This design document proposed to adopt |Black| as code style for |FreeIPA|'s
Python code and to enforce a consistent style by auto-formatting with |Black|.

Overview
========

|Black| is a code formatter for Python code. From `black project`_ page:

   black is the uncompromising Python code formatter. By using it, you agree
   to cede control over minutiae of hand-formatting. In return, Black gives
   you speed, determinism, and freedom from pycodestyle nagging about
   formatting. You will save time and mental energy for more important
   matters.

|Black|'s formatting is safe and does never change meaning of code.
Internally the tool verifies that the reformatting code produces exactly the
same AST as the original code. An internal cache speeds up subsequent runs of
|Black|.

The tool also has a check mode (``black --check``) for linting that does not
modify any code.

.. note::

   This design document is a complement of Django's `DEP 0008`_ document. It
   highlights and discusses special cases for |FreeIPA| or where |FreeIPA|
   deviates from `DEP 0008`_. Please read the document before continuing.

Used in notable open-source project
-----------------------------------

|Black| has been successfully adopted by several large and prominent
Open Source projects.

* pytest
* tox
* Pyramid
* Django
* Hypothesis
* attrs
* SQLAlchemy
* Poetry
* PyPA applications (Warehouse, Pipenv, virtualenv)
* pandas
* Pillow
* ... and many more


Benefits
========

The Django Enhancement Proposal `DEP 0008`_ explains the benefits of
automated code formatting and adoption of |Black| for open-source projects
in great detail. This proposal suggests to follow Django's example.

There are some additional benefits for |FreeIPA|, too.

* |FreeIPA|'s `Python code style`_, :pep:`8`, and style checking with
  `pycodestyle`_ don't enforce a single code style. There is some room for
  interpretation. Developers have a slightly different interpretation how to
  indent multi-line function calls or where to put the closing brace of a
  *list*.
* A considerable amount of older code does not follow |FreeIPA|'s guidelines
  for `Python code style`_. Our linting and CI system has to work around the
  problem. For example `pycodestyle`_ checks are only applied to
  ``git diff``. When a developer has to touch old code then it is often
  necessary to first fix code style violations to make ``make fastlint``
  pass.
* Every now and then a reviewer a committer about code style and formatting
  in a pull request. This delays merge of a PR and can be source of
  frustration, especially for new contributors.
* Blackend code has a consistent look that makes it easy to recognize code
  blocks by whitespace and closing braces. |Black| tries to reduce amount of
  lines when possible. If not it splits lines into one item per line to
  optimizes for minimized diffs.
* Auto-formatting plus a handful of manual changes will get rid of most
  `pycodestyle`_ violations. The 4.8.6 release has about 12,500 style
  violations according to ``python3 -m pycodestyle | wc -l``. Master branch
  on 2020-05-06 has about 6,500 violations.

Adoption of |Black| will eliminate these issues and reduce |FreeIPA|'s
`Python code style`_ to run ``make black``.

Concerns
========

Auto-formatting |FreeIPA| with |Black| will change almost all Python files of
FreIPA.

* Mass-changes of code is going to make backports harder because there will
  be a lot of merge conflicts. To reduce merge conflicts all active branches
  have to be auto-formatted with |Black| at once.
* Pull requests will also be affected by merge conflicts. Therefore we should
  try to merge or close as many pull requests as possible before the code is
  formatted.
* Auto formatting is going to interfere with git history and make it harder
  to find  issues. Git has an option to ignore revisions with
  ``git blame --ignore-revs-file`` or ``blame.ignoreRevsFile`` option [1]_.
  Once the formatting changes have landed in git, IPA can provide a
  ``.gitignorerevs`` file that lists the formatting commits from all branches.
* |Black| sometimes creates less readable code. It's possible to disable
  reformatting with ``# fmt: off`` / ``# fmt: on``. This document proposes a
  short list of :ref:`exceptions <black-disable-formatting>`.
* Reformatting does never change the meaning of code. |Black| does not
  perform modifications that affect the AST (abstract syntax tree). By
  default the tool compares the AST before and after reformatting to ensure
  correctness. This is also the reason why black cannot perform string
  concatenation and sometimes creates line like
  ``text = "multiline " "string"``.
* In general |Black| spreads out long expression over multiple lines and
  therefore can increases lines of code. The slightly larger line length
  reduces lines of code in other cases. Reformatting increases the total
  lines of code of all ``.py`` files by about 1% (765k before, 773k after).

  When I first used |Black| in personal projects I was slightly annoyed by
  this formatting style. Shortly later I started to appreciate the style.
  It makes it easier to recognize begin and end of a list block, reduces
  diffs when adding/removing an item, and encourages use of keyword arguments
  in function calls.

Open questions
==============

ipa-4-6 branch
--------------

The |FreeIPA| team still maintains ipa-4-6 branch for RHEL 7. The branch
simplifies backports and fixes of IPA in RHEL.

According to the `RHEL Life Cycle`_ document, RHEL 7 is slowly winding down.
RHEL 7.8 was released March 31, 2020. RHEL 7.9 will be the last RHEL 7
y-stream release. RHEL 7 has reached end of full support in August 2019 and
is going to reach end of *Maintenance Support 1* in August 2020. During the
*Maintenance Support 2* phase critical and import security fixes and select
urgent bug fixes are provided until June 2024.

I expect that the amount of backports to 4.6 will soon diminish to a few
commits a year.

Q: When can we start to limit backports to urgent CVEs only?

|Black| target version
----------------------

|Black| creates slightly different output depending on the target version
option. With Python 2.7 as minimum target version, |Black| retains Python 2
features like ``u""`` string prefix. With target version Python 3.6, |Black|
removes the redundant ``u""`` and can make use of 3.6 features.

Q: Should we use a ``target-version`` 3.6 to automate the next step in
|FreeIPA|'s Python 3 migration?

New code style
==============

The new code style is *whatever black does*.

The rules for i18n strings and unused variables from the |FreeIPA|
`Python code style`_ still apply, though.

|Black| increases the permitted maximum line length from 79/80 characters to
88 characters. According to `black project`_'s documentation

   This number was found to produce significantly shorter files than
   sticking with 80 (the most popular), or even 79 (used by the standard
   library).

.. _black-disable-formatting:

Disable formatting
------------------

While reformatting can be disable with ``# fmt: off`` / ``# fmt: on``, this
feature should **only** be used when it arguably increases readability of
code. To paraphrase `DEP 0008`_:

   The escape hatch ``# fmt: off`` is allowed only in extreme cases where
   Black produces unreadable code, not whenever someone disagrees with the
   style choices of Black.

.. note::

   Any use of ``# fmt: off`` besides argument pairs in ``subprocess.run()`` /
   ``ipautil.run()`` should be treated as code smell and maintenance problem.

Argument pairs
~~~~~~~~~~~~~~

Argument pairs of subprocess arguments may be rearrange in such a way that
argument pairs are on the same line. The argument list must still follow
black formatting rules (double quotes, trailing commas).

.. code-block:: python

   # fmt: off
   args = [
       paths.CERTUTIL,
       "-d", dbdir,
       "-N",
       "-f", self.pwd_file,
       "-@", self.pwd_file,
   ]
   # fmt: on

Function calls with 8 or more arguments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In case a function call

* spans more 10 or more lines (including opening and closing braces)
* all arguments are simple expressions
* and there is no simple way to refactor function call

then it's acceptable to disable auto-formatting.

.. code-block:: python

   # fmt: off
   function(
       argument_a, argument_b, argument_c, argument_d, argument_e,
       argument_f, argument_g, argument_h,
   )
   # fmt: on

.. _black-pycodestyle:

pycodestyle
===========

With |Black| auto-formatting and a handful of minor patches it is finally
possible to run `pycodestyle`_ successfully on the entire code base.
Remaining style issues were already addressed in upstream `PR 4638`_.

Fixed Style issues
------------------

* *E266* too many leading '#' for block comment
* *E302* expected 2 blank lines, found 1
* *W601* .has_key() is deprecated, use 'in'
* *E711* comparison to None should be 'if cond is None:'
* *E712* comparison to True should be 'if cond is True:' or 'if cond:'
* *E712* comparison to False should be 'if cond is False:' or 'if not cond:'
* *E713* test for membership should be 'not in'
* *E714* test for object identity should be 'is not'
* *E721* do not compare types, use 'isinstance()'
* *E722* do not use bare 'except'

New ignores
-----------

*E203* whitespace before ':'
   *E203* is not :pep:`8` conform. |Black| treats slice ``:`` as binary
   operator and enforces whitespace in slices, for example ``ham[1 + 1 :]``.
*E231* missing whitespace after ','
   |Black| always adds a comma after all arguments, e.g. ``func(a,)``.
*W503* line break before binary operator
   *W503* is not :pep:`8` conform.
*W504* line break after binary operator
   In rare cases |Black| adds a binary operator on its own line when an
   expression contains inline comments.
*E731* do not assign a lambda expression
   IPA creates callable from lambdas a lot. It doesn't make sense to change
   all places.
*E741* ambiguous variable name 'l'
   In several places IPA uses ``l`` as variable name. In some fonts it can
   be confused with number ``1``.

Implementation
==============

1. Create infrastructure for |Black|

   * Add ``BuildRequires: black`` (|Black| is available in Fedora)
   * Add ``make`` targets ``black`` and ``blacklint``
   * Create ``pyproject.toml`` to configure |Black| and include Python code
     that does not have a ``.py`` file extension.
   * Exclude auto-generated plugin code in ``ipaclient/remote_plugins/2_???``
     from black. It's legacy code and no developer is going to touch the code
     any more.

2. Address remaining :ref:`pycodestyle issues <black-pycodestyle>` by either
   fixing the issue or ignoring the warning locally or globally.
   ``python3 -m pycodestyle .`` should pass without any error.
3. Backport changes from (1) and (2) to ipa-4-8 branch.
4. Run ``make black`` in master + ipa-4-8 branch and merge the changes.
5. Create ``.gitignorerevs`` file with commit hashes of |Black| run from all
   active branches``.
6. Enable ``blacklint`` for ``fastlint`` and ``lint`` targets so
   local linting and linting on Azure check for black violations.
7. Update |FreeIPA|'s `Python code style`_ to mention ``make black``.


.. |Black| replace:: *Black*
.. _black project: https://pypi.org/project/black/
.. _DEP 0008: https://github.com/django/deps/blob/master/accepted/0008-black.rst
.. _Python code style: https://www.freeipa.org/page/Python_Coding_Style
.. _pycodestyle: https://pycodestyle.pycqa.org
.. _PR 4638: https://github.com/freeipa/freeipa/pull/4638
.. _RHEL Life Cycle: https://access.redhat.com/support/policy/updates/errata
.. [1] https://git-scm.com/docs/git-blame#Documentation/git-blame.txt---ignore-revs-fileltfilegt
