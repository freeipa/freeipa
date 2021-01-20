import time
import logging

import pexpect
from pexpect.exceptions import ExceptionPexpect, TIMEOUT


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class IpaTestExpect(pexpect.spawn):
    """A wrapper class around pexpect.spawn for easier usage in automated tests

    Please see pexpect documentation at
    https://pexpect.readthedocs.io/en/stable/api/index.html for general usage
    instructions. Note that usage of "+", "*" and '?' at the end of regular
    expressions arguments to .expect() is meaningless.

    This wrapper adds ability to use the class as a context manager, which
    will take care of verifying process return status and terminating
    the process if it did not do it normally. The context manager is the
    recommended way of using the class in tests.
    Basic usage example:

    ```
        with IpaTestExpect('some_command') as e:
            e.expect_exact('yes or no?')
            e.sendline('yes')
    ```

    At exit from context manager the following checks are performed by default:
    1. there is nothing in output since last call to .expect()
    2. the process has terminated
    3. return code is 0

    If any check fails, an exceptio is raised. If you want to override checks
    1 and 3 you can call .expect_exit() explicitly:

    ```
    with IpaTestExpect('some_command') as e:
        ...
        e.expect_exit(ok_returncode=1, ignore_remaining_output=True)
    ```

    All .expect* methods are strict, meaning that if they do not find the
    pattern in the output during given amount of time, the exception is raised.
    So they can directly be used to verify output for presence of specific
    strings.

    Another addition is .get_last_output() method which can be used get process
    output from penultimate up to the last call to .expect(). The result can
    be used for more complex checks which can not be expressed as simple
    regexes, for example we can check for absence of string in output:

    ```
    with IpaTestExpect('some_command') as e:
        ...
        e.expect('All done')
        output = e.get_last_output()
    assert 'WARNING' not in output
    ```
    """
    def __init__(self, argv, default_timeout=10, encoding='utf-8'):
        if isinstance(argv, str):
            command = argv
            args = []
        else:
            command = argv[0]
            args = argv[1:]
        super().__init__(
            command, args, timeout=default_timeout, encoding=encoding,
            echo=False
        )

    def expect_exit(self, timeout=-1, ok_returncode=0, raiseonerr=True,
                    ignore_remaining_output=False):
        if timeout == -1:
            timeout = self.timeout
        wait_to_exit_until = time.time() + timeout
        if not self.eof():
            self.expect(pexpect.EOF, timeout)
        errors = []
        if not ignore_remaining_output and self.before.strip():
            errors.append('Unexpected output at program exit: {!r}'
                          .format(self.before))

        while time.time() < wait_to_exit_until:
            if not self.isalive():
                break
            time.sleep(0.1)
        else:
            errors.append('Program did not exit after waiting for {} seconds'
                          .format(self.timeout))
        if (not self.isalive() and raiseonerr
                and self.exitstatus != ok_returncode):
            errors.append('Program exited with unexpected status {}'
                          .format(self.exitstatus))
        self.exit_checked = True
        if errors:
            raise ExceptionPexpect(
                'Program exited with an unexpected state:\n'
                + '\n'.join(errors))

    def send(self, s):
        """Wrapper to provide logging input string"""
        logger.debug('Sending %r', s)
        return super().send(s)

    def expect_list(self, pattern_list, *args, **kwargs):
        """Wrapper to provide logging output string and expected patterns"""
        try:
            result = super().expect_list(pattern_list, *args, **kwargs)
        finally:
            self._log_output(pattern_list)
        return result

    def expect_exact(self, pattern_list, *args, **kwargs):
        """Wrapper to provide logging output string and expected patterns"""
        try:
            result = super().expect_exact(pattern_list, *args, **kwargs)
        finally:
            self._log_output(pattern_list)
        return result

    def get_last_output(self):
        """Return output consumed by last call to .expect*()"""
        output = self.before
        if isinstance(self.after, str):
            output += self.after
        return output

    def _log_output(self, expected):
        logger.debug('Output received: %r, expected: "%s", ',
                     self.get_last_output(), expected)

    def __enter__(self):
        self.exit_checked = False
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        exception_occurred = bool(exc_type)
        try:
            if not self.exit_checked:
                self.expect_exit(raiseonerr=not exception_occurred,
                                 ignore_remaining_output=exception_occurred)
        except TIMEOUT:
            if not exception_occurred:
                raise
        finally:
            if self.isalive():
                logger.error('Command still active, terminating.')
                self.terminate(True)
