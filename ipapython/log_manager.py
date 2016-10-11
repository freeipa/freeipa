# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2011  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''

Quick Start Guide For Using This Module
=======================================

This module implements a Log Manager class which wraps the Python
logging module and provides some utility functions for use with
logging. All logging operations should be done through the
`LogManager` where available. *DO NOT create objects using the
Python logging module, the log manager will be unaware of them.*

This module was designed for ease of use while preserving advanced
functionality and performance. You must perform the following steps.

1. Import the log_manger module and instantiate *one* `LogManager`
   instance for your application or library. The `LogManager` is
   configured via `LogManager.configure()` whose values are
   easily populated from command line options or a config file. You
   can modify the configuration again at any point.

2. Create one or more output handlers via
   `LogManager.create_log_handlers()` an easy to use yet powerful
   interface.

3. In your code create loggers via `LogManager.get_logger()`. Since
   loggers are normally bound to a class this method is optimized for
   that case, all you need to do in the call ``__init__()`` is::

     log_mgr.get_logger(self, True)

   Then emitting messages is as simple as ``self.debug()`` or ``self.error()``

Example:
--------

::

  # Step 1, Create log manager and configure it
  prog_name = 'my_app'
  log_mgr = LogManager(prog_name)
  log_mgr.configure(dict(verbose=True))

  # Step 2, Create handlers
  log_mgr.create_log_handlers([dict(name='my_app stdout',
                                    stream=sys.stdout,
                                    level=logging.INFO),
                               dict(name='my_app file',
                                    filename='my_app.log',
                                    level=logging.DEBUG)])

  # Step 3, Create and use a logger in your code
  class FooBar:
      def __init__(self, name):
          log_mgr.get_logger(self, True)
          self.info("I'm alive! %s", name)

  foobar = FooBar('Dr. Frankenstein')

  # Dump the log manager state for illustration
  print
  print log_mgr


Running the above code would produce::

  <INFO>: I'm alive! Dr. Frankenstein

  root_logger_name: my_app
  configure_state: None
  default_level: INFO
  debug: False
  verbose: True
  number of loggers: 2
      "my_app" [level=INFO]
      "my_app.__main__.FooBar" [level=INFO]
  number of handlers: 2
      "my_app file" [level=DEBUG]
      "my_app stdout" [level=INFO]
  number of logger regexps: 0

*Note, Steps 1 & 2 were broken out for expository purposes.* You can
pass your handler configuration into `LogManager.configure()`. The above
could have been simpler and more compact.::

  # Step 1 & 2, Create log manager, and configure it and handlers
  prog_name = 'my_app'
  log_mgr = LogManager(prog_name)
  log_mgr.configure(dict(verbose=True,
                         handlers = [dict(name='my_app stdout',
                                          stream=sys.stdout,
                                          level=logging.INFO),
                                     dict(name='my_app file',
                                          filename='my_app.log',
                                          level=logging.DEBUG)])


FAQ (Frequently Asked Questions)
================================

#. **Why is this better than logging.basicConfig? The short example
   for the LogManager doesn't seem much different in complexity from
   basicConfig?**

   * You get independent logging namespaces. You can instantiate
     multiple logging namespaces. If you use this module you'll be
     isolated from other users of the Python logging module avoiding
     conflicts.

   * Creating and initializing loggers for classes is trivial. One
     simple call creates the logger, configures it, and sets logging
     methods on the class instance.

   * You can easily configure individual loggers to different
     levels. For example turn on debuging for just the part of the
     code you're working on.

   * The configuration is both simple and powerful. You get many more
     options than with basicConfig.

   * You can dynamically reset the logging configuration during
     execution, you're not forced to live with the config established
     during program initialization.

   * The manager optimizes the use of the logging objects, you'll
     spend less time executing pointless logging code for messages
     that won't be emitted.

   * You can see the state of all the logging objects in your
     namespace from one centrally managed location.

   * You can configure a LogManager to use the standard logging root
     logger and get all the benefits of this API.

#. **How do I turn on debug logging for a specific class without
   affecting the rest of the logging configuration?**

   Use a logger regular expression to bind a custom level to loggers
   whose name matches the regexp. See `LogManager.configure()`
   for details.

   Lets say you want to set your Foo.Bar class to debug, then do
   this::

     log_mgr.configure(dict(logger_regexps=[(r'Foo\.Bar', 'debug')]))

#. **I set the default_level but all my loggers are configured
   with a higher level, what happened?**

   You probably don't have any handlers defined at or below the
   default_level. The level set on a logger will never be
   lower than the lowest level handler available to that logger.

#. **My logger's all have their level set to a huge integer, why?**

   See above. Logger's will never have a level less than the level of
   the handlers visible to the logger. If there are no handlers then
   loggers can't output anything so their level is set to maxsize.

#. **I set the default_level but all the loggers are configured
   at INFO or DEBUG, what happened?**

   The verbose and debug config flags set the default_level to
   INFO and DEBUG respectively as a convenience.

#. **I'm not seeing messages output when I expect them to be, what's
   wrong?**

   For a message to be emitted the following 3 conditions must hold:

   * Message level >= logger's level
   * Message level >= handler's level
   * The message was not elided by a filter

   To verify the above conditions hold print out the log manager state
   (e.g. print log_mgr). Locate your logger, what level is at? Locate
   the handler you expected to see the message appear on, what level
   is it?

A General Discussion of Python Logging
======================================

The design of this module is driven by how the Python logging module
works. The following discussion complements the Python Logging Howto,
fills in some missing information and covers strategies for
implementing different functionality along with the trade-offs
involved.

Understanding when & how log messages are emitted:
--------------------------------------------------

Loggers provide the application interface for logging. Every logger
object has the following methods debug(), info(), warning(), error(),
critical(), exception() and log() all of which can accept a format
string and arguments. Applications generate logging messages by
calling one of these methods to produce a formatted message.

A logger's effective level is the first explicitly set level found
when searching from the logger through it's ancestors terminating at
the root logger. The root logger always has an explicit level
(defaults to WARNING).

For a message to be emitted by a handler the following must be true:

The logger's effective level must >= message level and it must not
be filtered by a filter attached to the logger, otherwise the
message is discarded.

If the message survives the logger check it is passed to a list of
handlers. A handler will emit the message if the handler's level >=
message level and its not filtered by a filter attached to the
handler.

The list of handlers is determined thusly: Each logger has a list of
handlers (which may be empty). Starting with the logger the message
was bound to the message is passed to each of it's handlers. Then
the process repeats itself by traversing the chain of loggers
through all of it's ancestors until it reaches the root logger. The
logger traversal will be terminated if the propagate flag on a logger
is False (by default propagate is True).

Let's look at a hypothetical logger hierarchy (tree)::

                            A
                           / \\
                          B   D
                         /
                        C


There are 4 loggers and 3 handlers

Loggers:

+-------+---------+---------+-----------+----------+
|Logger | Level   | Filters | Propagate | Handlers |
+=======+=========+=========+===========+==========+
| A     | WARNING | []      | False     | [h1,h2]  |
+-------+---------+---------+-----------+----------+
| A.B   | ERROR   | []      | False     | [h3]     |
+-------+---------+---------+-----------+----------+
| A.B.C | DEBUG   | []      | True      |          |
+-------+---------+---------+-----------+----------+
| A.D   |         | []      | True      |          |
+-------+---------+---------+-----------+----------+

Handlers:

+---------+---------+---------+
| Handler | Level   | Filters |
+=========+=========+=========+
| h1      | ERROR   | []      |
+---------+---------+---------+
| h2      | WARNING | []      |
+---------+---------+---------+
| h3      | DEBUG   | []      |
+---------+---------+---------+

Each of the loggers and handlers have empty filter lists in this
example thus the filter checks will always pass.

If a debug message is posted logger A.B.C the following would
happen. The effective level is determined. Since it does not have a
level set it's parent (A.B) is examined which has ERROR set,
therefore the effective level of A.B.C is ERROR. Processing
immediately stops because the logger's level of ERROR does not
permit debug messages.

If an error message is posted on logger A.B.C it passes the logger
level check and filter check therefore the message is passed along
to the handlers. The list of handlers on A.B.C is empty so no
handlers are called at this position in the logging hierarchy. Logger
A.B.C's propagate flag is True so parent logger A.B handlers are
invoked. Handler h3's level is DEBUG, it passes both the level and
filter check thus h3 emits the message. Processing now stops because
logger A.B's propagate flag is False.

Now let's see what would happen if a warning message was posted on
logger A.D. It's effective level is WARNING because logger A.D does
not have a level set, it's only ancestor is logger A, the root
logger which has a level of WARNING, thus logger's A.D effective
level is WARNING. Logger A.D has no handlers, it's propagate flag is
True so the message is passed to it's parent logger A, the root
logger. Logger A has two handlers h1 and h2. The level of h1 is
ERROR so the warning message is discarded by h1, nothing is emitted
by h1. Next handler h2 is invoked, it's level is WARNING so it
passes both the level check and the filter check, thus h2 emits the
warning message.

How to configure independent logging spaces:
--------------------------------------------

A common idiom is to hang all handlers off the root logger and set
the root loggers level to the desired verbosity. But this simplistic
approach runs afoul of several problems, in particular who controls
logging (accomplished by configuring the root logger). The usual
advice is to check and see if the root logger has any handlers set,
if so someone before you has configured logging and you should
inherit their configuration, all you do is add your own loggers
without any explicitly set level. If the root logger doesn't have
handlers set then you go ahead and configure the root logger to your
preference. The idea here is if your code is being loaded by another
application you want to defer to that applications logging
configuration but if your code is running stand-alone you need to
set up logging yourself.

But sometimes your code really wants it's own logging configuration
managed only by yourself completely independent of any logging
configuration by someone who may have loaded your code. Even if you
code is not designed to be loaded as a package or module you may be
faced with this problem. A trivial example of this is running your
code under a unit test framework which itself uses the logging
facility (remember there is only ever one root logger in any Python
process).

Fortunately there is a simple way to accommodate this. All you need
to do is create a "fake" root in the logging hierarchy which belongs
to you. You set your fake root's propagate flag to False, set a
level on it and you'll hang your handlers off this fake root. Then
when you create your loggers each should be a descendant of this
fake root. Now you've completely isolated yourself in the logging
hierarchy and won't be influenced by any other logging
configuration. As an example let's say your your code is called
'foo' and so you name your fake root logger 'foo'.::

  my_root = logging.getLogger('foo') # child of the root logger
  my_root.propagate = False
  my_root.setLevel(logging.DEBUG)
  my_root.addHandler(my_handler)

Then every logger you create should have 'foo.' prepended to it's
name. If you're logging my module your module's logger would be
created like this::

  module_logger = logging.getLogger('foo.%s' % __module__)

If you're logging by class then your class logger would be::

  class_logger = logging.getLogger('foo.%s.%s' % (self.__module__,  self.__class__.__name__))

How to set levels:
------------------

An instinctive or simplistic assumption is to set the root logger to a
high logging level, for example ERROR. After all you don't want to be
spamming users with debug and info messages. Let's also assume you've
got two handlers, one for a file and one for the console, both
attached to the root logger (a common configuration) and you haven't
set the level on either handler (in which case the handler will emit
all levels).

But now let's say you want to turn on debugging, but just to the file,
the console should continue to only emit error messages.

You set the root logger's level to DEBUG. The first thing you notice is
that you're getting debug message both in the file and on the console
because the console's handler does not have a level set. Not what you
want.

So you go back restore the root loggers level back to it's original
ERROR level and set the file handler's level to DEBUG and the console
handler's level to ERROR. Now you don't get any debug messages because
the root logger is blocking all messages below the level of ERROR and
doesn't invoke any handlers. The file handler attached to the root
logger even though it's level is set to DEBUG never gets a chance to
process the message.

*IMPORTANT:* You have to set the logger's level to the minimum of all
the attached handler's levels, otherwise the logger may block the
message from ever reaching any handler.

In this example the root logger's level must be set to DEBUG, the file
handler's level to DEBUG, and the console handler's level set to
ERROR.

Now let's take a more real world example which is a bit more
complicated. It's typical to assign loggers to every major class. In
fact this is the design strategy of Java logging from which the Python
logging is modeled. In a large complex application or library that
means dozens or possibly hundreds of loggers. Now lets say you need to
trace what is happening with one class. If you use the simplistic
configuration outlined above you'll set the log level of the root
logger and one of the handlers to debug. Now you're flooded with debug
message from every logger in the system when all you wanted was the
debug messages from just one class.

How can you get fine grained control over which loggers emit debug
messages? Here are some possibilities:

(1) Set a filter.
.................

When a message is propagated to a logger in the hierarchy first the
loggers level is checked. If logger level passes then the logger
iterates over every handler attached to the logger first checking the
handler level. If the handler level check passes then the filters
attached to the handler are run.

Filters are passed the record (i.e. the message), it does not have
access to either the logger or handler it's executing within. You
can't just set the filter to only pass the records of the classes you
want to debug because that would block other important info, warning,
error and critical messages from other classes. The filter would have
to know about the "global" log level which is in effect and also pass
any messages at that level or higher. It's unfortunate the filter
cannot know the level of the logger or handler it's executing inside
of.

Also logger filters only are applied to the logger they are attached
to, i.e. the logger the message was generated on. They do not get
applied to any ancestor loggers. That means you can't just set a
filter on the root logger. You have to either set the filters on the
handlers or on every logger created.

The filter first checks the level of the message record. If it's
greater than debug it passes it. For debug messages it checks the set
of loggers which have debug messages enabled, if the message record
was generated on one of those loggers it passes the record, otherwise
it blocks it.

The only question is whether you attach the filter to every logger or
to a handful of handlers. The advantage of attaching the filter to
every logger is efficiency, the time spent handling the message can be
short circuited much sooner if the message is filtered earlier in the
process. The advantage of attaching the filter to a handler is
simplicity, you only have to do that when a handler is created, not
every place in the code where a logger is created.

(2) Conditionally set the level of each logger.
...............................................

When loggers are created a check is performed to see if the logger is
in the set of loggers for which debug information is desired, if so
it's level is set to DEBUG, otherwise it's set to the global
level. One has to recall there really isn't a single global level if
you want some handlers to emit info and above, some handlers error and
above, etc. In this case if the logger is not in the set of logger's
emitting debug the logger level should be set to the next increment
above debug level.

A good question to ask would be why not just leave the logger's level
unset if it's not in the set of loggers to be debugged? After all it
will just inherit the root level right? There are two problems with
that. 1) It wold actually inherit the level any ancestor logger and if
an ancestor was set to debug you've effectively turned on debugging
for all children of that ancestor logger. There are times you might
want that behavior, where all your children inherit your level, but
there are many cases where that's not the behavior you want. 2) A more
pernicious problem exists. The logger your handlers are attached to
MUST be set to debug level, otherwise your debug messages will never
reach the handlers for output. Thus if you leave a loggers level unset
and let it inherit it's effective level from an ancestor it might very
well inherit the debug level from the root logger. That means you've
completely negated your attempt to selectively set debug logging on
specific loggers. Bottom line, you really have to set the level on
every logger created if you want fine grained control.

Approach 2 has some distinct performance advantages. First of all
filters are not used, this avoids a whole processing step and extra
filter function calls on every message. Secondly a logger level check
is a simple integer compare which is very efficient. Thirdly the
processing of a message can be short circuited very early in the
processing pipeline, no ancestor loggers will be invoked and no
handlers will be invoked.

The downside is some added complexity at logger creation time. But
this is easily mitigated by using a utility function or method to
create the logger instead of just calling logger.getLogger().

Like every thing else in computer science which approach you take boils
down to a series of trade offs, most around how your code is
organized. You might find it easier to set a filter on just one or two
handlers. It might be easier to modify the configuration during
execution if the logic is centralized in just a filter function, but
don't let that sway you too much because it's trivial to iterate over
every logger and dynamically reset it's log level.

Now at least you've got a basic understanding of how this stuff hangs
together and what your options are. That's not insignificant, when I
was first introduced to logging in Java and Python I found it
bewildering difficult to get it do what I wanted.

John Dennis <jdennis@redhat.com>

'''
from __future__ import print_function

#-------------------------------------------------------------------------------
import sys
import os
import pwd
import logging
import re
import time

import six

#-------------------------------------------------------------------------------
# Default format
LOGGING_DEFAULT_FORMAT = '%(levelname)s %(message)s'

# Maps a logging level name to it's numeric value
log_level_name_map = {
    'notset'   : logging.NOTSET,
    'debug'    : logging.DEBUG,
    'info'     : logging.INFO,
    'warn'     : logging.WARNING,
    'warning'  : logging.WARNING,
    'error'    : logging.ERROR,
    'critical' : logging.CRITICAL
}

log_levels = (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL)

logger_method_names = ('debug', 'info', 'warning', 'error', 'exception', 'critical')

#-------------------------------------------------------------------------------

def get_unique_levels(iterable):
    '''
    Given a iterable of objects containing a logging level return a
    ordered list (min to max) of unique levels.

    :parameters:
      iterable
        Iterable yielding objects with a logging level attribute.
    :returns:
      Ordered list (min to max) of unique levels.
    '''
    levels = set()

    for obj in iterable:
        level = getattr(obj, 'level', sys.maxsize)
        if level != logging.NOTSET:
            levels.add(level)
    levels = list(levels)
    levels.sort()
    return levels

def get_minimum_level(iterable):
    '''
    Given a iterable of objects containing a logging level return the
    minimum level. If no levels are defined return maxsize.
    set of unique levels.

    :parameters:
      iterable
        Iterable yielding objects with a logging level attribute.
    :returns:
      Ordered list (min to max) of unique levels.
    '''
    min_level = sys.maxsize

    for obj in iterable:
        level = getattr(obj, 'level', sys.maxsize)
        if level != logging.NOTSET:
            if level < min_level:
                min_level = level
    return min_level

def parse_log_level(level):
    '''
    Given a log level either as a string or integer
    return a numeric logging level. The following case insensitive
    names are recognized::

    * notset
    * debug
    * info
    * warn
    * warning
    * error
    * critical

    A string containing an integer is also recognized, for example
    ``"10"`` would map to ``logging.DEBUG``

    The integer value must be the range [``logging.NOTSET``,
    ``logging.CRITICAL``] otherwise a value exception will be raised.

    :parameters:
      level
        basestring or integer, level value to convert
    :returns:
      integer level value
    '''
    # Is it a string representation of an integer?
    # If so convert to an int.
    if isinstance(level, six.string_types):
        try:
            level = int(level)
        except ValueError:
            pass

    # If it's a string lookup it's name and map to logging level
    # otherwise validate the integer value is in range.
    if isinstance(level, six.string_types):
        result = log_level_name_map.get(level.lower()) #pylint: disable=E1103
        if result is None:
            raise ValueError('unknown log level (%s)' % level)
        return result
    elif isinstance(level, int):
        if level < logging.NOTSET or level > logging.CRITICAL:
            raise ValueError('log level (%d) out of range' % level)
        return level
    else:
        raise TypeError('log level must be basestring or int, got (%s)' % type(level))

#-------------------------------------------------------------------------------
def logging_obj_str(obj):
    '''
    Unfortunately the logging Logger and Handler classes do not have a
    custom __str__() function which converts the object into a human
    readable string representation. This function takes any object
    with a level attribute and outputs the objects name with it's
    associated level. If a name was never set for the object then it's
    repr is used instead.

    :parameters:
      obj
        Object with a logging level attribute
    :returns:
      string describing the object
    '''
    name = getattr(obj, 'name', repr(obj))
    text = '"%s" [level=%s]' % (name, logging.getLevelName(obj.level))
    if isinstance(obj, logging.FileHandler):
        text += ' filename="%s"' % obj.baseFilename
    return text
#-------------------------------------------------------------------------------
class LogManager(object):
    '''
    This class wraps the functionality in the logging module to
    provide an easier to use API for logging while providing advanced
    features including a independent namespace. Each application or
    library wishing to have it's own logging namespace should instantiate
    exactly one instance of this class and use it to manage all it's
    logging.

    Traditionally (or simplistically) logging was set up with a single
    global root logger with output handlers bound to it. The global
    root logger (whose name is the empty string) was shared by all
    code in a loaded process. The only the global unamed root logger
    had a level set on it, all other loggers created inherited this
    global level. This can cause conflicts in more complex scenarios
    where loaded code wants to maintain it's own logging configuration
    independent of whomever loaded it's code. By using only a single
    logger level set on the global root logger it was not possible to
    have fine grained control over individual logger output. The
    pattern seen with this simplistic setup has been frequently copied
    despite being clumsy and awkward. The logging module has the tools
    available to support a more sophisitcated and useful model, but it
    requires an overarching framework to manage. This class provides
    such a framework.

    The features of this logging manager are:

    * Independent logging namespace.

    * Simplifed method to create handlers.

    * Simple setup for applications with command line args.

    * Sophisitcated handler configuration
      (e.g. file ownership & permissions)

    * Easy fine grained control of logger output
      (e.g. turning on debug for just 1 or 2 loggers)

    * Holistic management of the interrelationships between
      logging components.

    * Ability to dynamically adjust logging configuration in
      a running process.

    An independent namespace is established by creating a independent
    root logger for this manager (root_logger_name). This root logger
    is a direct child of the global unamed root logger. All loggers
    created by this manager will be descendants of this managers root
    logger. The managers root logger has it's propagate flag set
    to False which means all loggers and handlers created by this
    manager will be isolated in the global logging tree.

    Log level management:
    ---------------------

    Traditionally loggers inherited their logging level from the root
    logger. This was simple but made it impossible to independently
    control logging output from different loggers. If you set the root
    level to DEBUG you got DEBUG output from every logger in the
    system, often overwhelming in it's voluminous output. Many times
    you want to turn on debug for just one class (a common idom is to
    have one logger per class). To achieve the fine grained control
    you can either use filters or set a logging level on every logger
    (see the module documentation for the pros and cons). This manager
    sets a log level on every logger instead of using level
    inheritence because it's more efficient at run time.

    Global levels are supported via the verbose and debug flags
    setting every logger level to INFO and DEBUG respectively. Fine
    grained level control is provided via regular expression matching
    on logger names (see `configure()` for the details. For
    example if you want to set a debug level for the foo.bar logger
    set a regular expression to match it and bind it to the debug
    level. Note, the global verbose and debug flags always override
    the regular expression level configuration. Do not set these
    global flags if you want fine grained control.

    The manager maintains the minimum level for all loggers under it's
    control and the minimum level for all handlers under it's
    control. The reason it does this is because there is no point in
    generating debug messages on a logger if there is no handler
    defined which will output a debug message. Thus when the level is
    set on a logger it takes into consideration the set of handlers
    that logger can emit to.

    IMPORTANT: Because the manager maintains knowledge about all the
    loggers and handlers under it's control it is essential you use
    only the managers interface to modify a logger or handler and not
    set levels on the objects directly, otherwise the manger will not
    know to visit every object under it's control when a configuraiton
    changes (see '`LogManager.apply_configuration()`).

    Example Usage::

      # Create a log managers for use by 'my_app'
      log_mgr = LogManager('my_app')

       # Create a handler to send error messages to stderr
      log_mgr.create_log_handlers([dict(stream=sys.stdout,
                                        level=logging.ERROR)])

       # Create logger for a class
      class Foo(object):
          def __init__(self):
              self.log = log_mgr.get_logger(self)

    '''
    def __init__(self, root_logger_name='', configure_state=None):
        '''
        Create a new LogManager instance using root_logger_name as the
        parent of all loggers maintained by the manager.

        Only one log manger should be created for each logging namespace.

        :parameters:
          root_logger_name
            The name of the root logger. All loggers will be prefixed
            by this name.
          configure_state
            Used by clients of the log manager to track the
            configuration state, may be any object.

        :return:
          LogManager instance

        '''
        self.loggers = {}       # dict, key is logger name, value is logger object
        self.handlers = {}      # dict, key is handler name, value is handler object

        self.configure_state = configure_state
        self.root_logger_name = root_logger_name
        self.default_level = 'error'
        self.debug = False
        self.verbose = False
        self.logger_regexps = []

        self.root_logger = self.get_logger(self.root_logger_name)
        # Stop loggers and handlers from searching above our root
        self.root_logger.propagate = False


    def _get_default_level(self):
        return self._default_level

    def _set_default_level(self, value):
        level = parse_log_level(value)
        self._default_level = level
        self.apply_configuration()

    default_level = property(_get_default_level, _set_default_level,
                             doc='see log_manager.parse_log_level()` for details on how the level can be specified during assignement.')

    def set_default_level(self, level, configure_state=None):
        '''
        Reset the default logger level, updates all loggers.
        Note, the default_level may also be set by assigning to the
        default_level attribute but that does not update the configure_state,
        this method is provided as a convenience to simultaneously set the
        configure_state if so desired.

        :parameters:
          level
            The new default level for the log manager.  See
            `log_manager.parse_log_level()` for details on how the
            level can be specified.
          configure_state
            If other than None update the log manger's configure_state
            variable to this object. Clients of the log manager can
            use configure_state to track the state of the log manager.

        '''
        level = parse_log_level(level)
        self._default_level = level
        self.apply_configuration(configure_state)


    def __str__(self):
        '''
        When str() is called on the LogManager output it's state.
        '''
        text = ''
        text += 'root_logger_name: %s\n' % (self.root_logger_name)
        text += 'configure_state: %s\n' % (self.configure_state)
        text += 'default_level: %s\n' % (logging.getLevelName(self.default_level))
        text += 'debug: %s\n' % (self.debug)
        text += 'verbose: %s\n' % (self.verbose)

        text += 'number of loggers: %d\n' % (len(self.loggers))
        loggers = [logging_obj_str(x) for x in self.loggers.values()]
        loggers.sort()
        for logger in loggers:
            text += '    %s\n' % (logger)

        text += 'number of handlers: %d\n' % (len(self.handlers))
        handlers = [logging_obj_str(x) for x in self.handlers.values()]
        handlers.sort()
        for handler in handlers:
            text += '    %s\n' % (handler)

        text += 'number of logger regexps: %d\n' % (len(self.logger_regexps))
        for regexp, level in self.logger_regexps:
            text += '    "%s" => %s\n' % (regexp, logging.getLevelName(level))

        return text

    def configure(self, config, configure_state=None):
        '''
        The log manager is initialized from key,value pairs in the
        config dict.  This may be called any time to modify the
        logging configuration at run time.

        The supported entries in the config dict are:

        default_level
          The default level applied to a logger when not indivdually
          configured. The verbose and debug config items override
          the default level. See `log_manager.parse_log_level()` for
          details on how the level can be specified.
        verbose
          Boolean, if True sets default_level to INFO.
        debug
          Boolean, if True sets default_level to DEBUG.
        logger_regexps
          List of (regexp, level) tuples. This is a an ordered list
          regular expressions used to match against a logger name to
          configure the logger's level. The first regexp in the
          sequence which matches the logger name will use the
          level bound to that regexp to set the logger's level. If
          no regexp matches the logger name then the logger will be
          assigned the default_level.

          The regular expression comparision is performed with the
          re.search() function which means the match can be located
          anywhere in the name string (as opposed to the start of
          the string). Do not forget to escape regular
          expression metacharacters when appropriate. For example
          dot ('.') is used to seperate loggers in a logging
          hierarchy path (e.g. a.b.c)

          Examples::

            # To match exactly the logger a.b.c and set it to DEBUG:
                logger_regexps = [(r'^a\.b\.c$', 'debug')]

            # To match any child of a.b and set it to INFO:
                logger_regexps = [(r'^a\.b\..*', 'info')]

            # To match any leaf logger with the name c and set it to level 5:
                logger_regexps = [(r'\.c$', 5)]
        handlers
          List of handler config dicts or (config, logger)
          tuples. See `create_log_handlers()` for details
          of a hanlder config.

          The simple form where handlers is a list of dicts each
          handler is bound to the log mangers root logger (see
          `create_log_handlers()` optional ``logger``
          parameter). If you want to bind each handler to a specific
          logger other then root handler then group the handler config
          with a logger in a (config, logger) tuple. The logger may be
          either a logger name or a logger instance. The following are
          all valid methods of passing handler configuration.::

            # List of 2 config dicts; both handlers bound to root logger
            [{}, {}]

            # List of 2 tuples; first handler bound to logger_name1
            # by name, second bound to logger2 by object.
            [({}, 'logger_name1'), ({}, logger2']

            # List of 1 dict, 1 tuple; first bound to root logger,
            # second bound to logger_name by name
            [{}, ({}, 'logger_name']

        :parameters:
          config
            Dict of <key,value> pairs describing the configuration.
          configure_state
            If other than None update the log manger's configure_state
            variable to this object. Clients of the log manager can
            use configure_state to track the state of the log manager.

        '''
        for attr in ('debug', 'verbose', 'logger_regexps'):
            value = config.get(attr)
            if value is not None:
                setattr(self, attr, value)

        attr = 'default_level'
        value = config.get(attr)
        if value is not None:
            try:
                level = parse_log_level(value)
            except Exception as e:
                raise ValueError("could not set %s (%s)" % (attr, e))
            setattr(self, attr, level)

        attr = 'handlers'
        handlers = config.get(attr)
        if handlers is not None:
            for item in handlers:
                logger = self.root_logger
                config = None
                if isinstance(item, dict):
                    config = item
                elif isinstance(item, tuple):
                    if len(item) != 2:
                        raise ValueError('handler tuple must have exactly 2 items, got "%s"' % item)
                    config = item[0]
                    logger = item[1]
                else:
                    raise TypeError('expected dict or tuple for handler item, got "%s", handlers=%s' % \
                                    type(item), value)

                if not isinstance(config, dict):
                    raise TypeError('expected dict for handler config, got "%s"', type(config))
                if isinstance(logger, six.string_types):
                    logger = self.get_logger(logger)
                else:
                    if not isinstance(logger, logging.Logger):
                        raise TypeError('expected logger name or logger object in  %s' % item)

                self.create_log_handlers([config], logger, configure_state)

        if self.verbose:
            self.default_level = logging.INFO

        if self.debug:
            self.default_level = logging.DEBUG

        self.apply_configuration(configure_state)

    def create_log_handlers(self, configs, logger=None, configure_state=None):
        '''
        Create new handlers and attach them to a logger (log mangers
        root logger by default).

        *Note, you may also pass the handler configs to `LogManager.configure()`.*

        configs is an iterable yielding a dict. Each dict configures a
        handler. Currently two types of handlers are supported:

        * stream
        * file

        Which type of handler is created is determined by the presence of
        the ``stream`` or ``filename`` in the dict.

        Configuration keys:
        ===================

        Handler type keys:
        ------------------

        Exactly of the following must present in the config dict:

        stream
            Use the specified stream to initialize the StreamHandler.

        filename
            Specifies that a FileHandler be created, using the specified
            filename.

        log_handler
            Specifies a custom logging.Handler to use

        Common keys:
        ------------

        name
            Set the name of the handler. This is optional but can be
            useful when examining the logging configuration.
            For files defaults to ``'file:absolute_path'`` and for streams
            it defaults to ``'stream:stream_name'``

        format
            Use the specified format string for the handler.

        time_zone_converter
            Log record timestamps are seconds since the epoch in the UTC
            time zone stored as floating point values. When the formatter
            inserts a timestamp via the %(asctime)s format substitution it
            calls a time zone converter on the timestamp which returns a
            time.struct_time value to pass to the time.strftime function
            along with the datefmt format conversion string. The time
            module provides two functions with this signature,
            time.localtime and time.gmtime which performs a conversion to
            local time and UTC respectively. time.localtime is the default
            converter. Setting the time zone converter to time.gmtime is
            appropriate for date/time strings in UTC. The
            time_zone_converter attribute may be any function with the
            correct signature. Or as a convenience you may also pass a
            string which will select either the time.localtime or the
            time.gmtime converter. The case insenstive string mappings
            are::

              'local'     => time.localtime
              'localtime' => time.localtime
              'gmt'       => time.gmtime
              'gmtime'    => time.gmtime
              'utc'       => time.gmtime

        datefmt
            Use the specified time.strftime date/time format when
            formatting a timestamp via the %(asctime)s format
            substitution. The timestamp is first converted using the
            time_zone_converter to either local or UTC

        level
            Set the handler logger level to the specified level.  May be
            one of the following strings: 'debug', 'info', 'warn',
            'warning', 'error', 'critical' or any of the logging level
            constants. Thus level='debug' is equivalent to
            level=logging.DEBUG. Defaults to self.default_level.


        File handler keys:
        ------------------

        filemode
            Specifies the mode to open the file. Defaults to 'a' for
            append, use 'w' for write.

        permission
            Set the permission bits on the file (i.e. chmod).
            Must be a valid integer (e.g. 0660 for rw-rw----)

        user
            Set the user owning the file. May be either a numeric uid or a
            basestring with a user name in the passwd file.

        group
            Set the group associated with the file, May be either a
            numeric gid or a basestring with a group name in the groups
            file.

        Examples:
        ---------

        The following shows how to set two handlers, one for a file
        (ipa.log) at the debug log level and a second handler set to
        stdout (e.g. console) at the info log level. (One handler sets it
        level with a simple name, the other with a logging constant just
        to illustrate the flexibility) ::

          # Get a root logger
          log_mgr = LogManger('my_app')

          # Create the handlers
          log_mgr.create_log_handlers([dict(filename='my_app.log',
                                            level='info',
                                            user='root',
                                            group='root',
                                            permission=0600,
                                            time_zone_converter='utc',
                                            datefmt='%Y-%m-%dT%H:%M:%SZ', # ISO 8601
                                            format='<%(levelname)s> [%(asctime)s] module=%(name)s "%(message)s"'),
                                       dict(stream=sys.stdout,
                                            level=logging.ERROR,
                                            format='%(levelname)s: %(message)s')])

          # Create a logger for my_app.foo.bar
          foo_bar_log = log_mgr.get_logger('foo.bar')

          root_logger.info("Ready to process requests")
          foo_bar_log.error("something went boom")

        In the file my_app.log you would see::

            <INFO> [2011-10-26T01:39:00Z] module=my_app "Ready to process requests"
            <ERROR> [2011-10-26T01:39:00Z] module=may_app.foo.bar "something went boom"

        On the console you would see::

            ERROR: something went boom

        :parameters:
          configs
            Sequence of dicts (any iterable yielding a dict). Each
            dict creates one handler and contains the configuration
            parameters used to create that handler.
          logger
            If unspecified the handlers will be attached to the
            LogManager.root_logger, otherwise the handlers will be
            attached to the specified logger.
          configure_state
            If other than None update the log manger's configure_state
            variable to this object. Clients of the log manager can
            use configure_state to track the state of the log manager.

        :return:
          The list of created handers.
        '''
        if logger is None:
            logger = self.root_logger

        handlers = []

        # Iterate over handler configurations.
        for cfg in configs:
            # Type of handler?
            filename = cfg.get('filename')
            stream = cfg.get("stream")
            log_handler = cfg.get("log_handler")
            if filename:
                if "stream" in cfg:
                    raise ValueError("both filename and stream are specified, must be one or the other, config: %s" % cfg)
                path = os.path.abspath(filename)
                filemode = cfg.get('filemode', 'a')
                handler = logging.FileHandler(path, filemode)

                # Set the handler name
                name = cfg.get("name")
                if name is None:
                    name = 'file:%s' % (path)
                handler.name = name

                # Path should now exist, set ownership and permissions if requested.

                # Set uid, gid (e.g. chmod)
                uid = gid = None
                user = cfg.get('user')
                group = cfg.get('group')
                if user is not None:
                    if isinstance(user, six.string_types):
                        pw = pwd.getpwnam(user)
                        uid = pw.pw_uid
                    elif isinstance(user, int):
                        uid = user
                    else:
                        raise TypeError("user (%s) is not int or basestring" % user)
                if group is not None:
                    if isinstance(group, six.string_types):
                        pw = pwd.getpwnam(group)
                        gid = pw.pw_gid
                    elif isinstance(group, int):
                        gid = group
                    else:
                        raise TypeError("group (%s) is not int or basestring" % group)
                if uid is not None or gid is not None:
                    if uid is None:
                        uid = -1
                    if gid is None:
                        gid = -1
                    os.chown(path, uid, gid)

                # Set file permissions (e.g. mode)
                permission = cfg.get('permission')
                if permission is not None:
                    os.chmod(path, permission)
            elif stream:
                handler = logging.StreamHandler(stream)

                # Set the handler name
                name = cfg.get("name")
                if name is None:
                    name = 'stream:%s' % (stream)
                handler.name = name
            elif log_handler:
                handler = log_handler
            else:
                raise ValueError(
                    "neither file nor stream nor log_handler specified in "
                    "config: %s" % cfg)

            # Add the handler
            handlers.append(handler)

            # Configure message formatting on the handler
            format = cfg.get("format", LOGGING_DEFAULT_FORMAT)
            datefmt = cfg.get("datefmt", None)
            formatter = logging.Formatter(format, datefmt)
            time_zone_converter = cfg.get('time_zone_converter', time.localtime)
            if isinstance(time_zone_converter, six.string_types):
                converter = {'local'     : time.localtime,
                             'localtime' : time.localtime,
                             'gmt'       : time.gmtime,
                             'gmtime'    : time.gmtime,
                             'utc'       : time.gmtime}.get(time_zone_converter.lower())
                if converter is None:
                    raise ValueError("invalid time_zone_converter name (%s)" % \
                                     time_zone_converter)
            elif callable(time_zone_converter):
                converter = time_zone_converter
            else:
                raise ValueError("time_zone_converter must be basestring or callable, not %s" % \
                                 type(time_zone_converter))

            formatter.converter = converter
            handler.setFormatter(formatter)

            # Set the logging level
            level = cfg.get('level')
            if level is not None:
                try:
                    level = parse_log_level(level)
                except Exception as e:
                    print('could not set handler log level "%s" (%s)' % (level, e), file=sys.stderr)
                    level = None
            if level is None:
                level = self.default_level
            handler.setLevel(level)

        for handler in handlers:
            if handler.name in self.handlers:
                raise ValueError('handler "%s" already exists' % handler.name)
            logger.addHandler(handler)
            self.handlers[handler.name] = handler
        self.apply_configuration(configure_state)
        return handlers

    def get_handler(self, handler_name):
        '''
        Given a handler name return the handler object associated with
        it.

        :parameters:
          handler_name
            Name of the handler to look-up.

        :returns:
          The handler object associated with the handler name.
        '''
        handler = self.handlers.get(handler_name)
        if handler is None:
            raise KeyError('handler "%s" is not defined' % handler_name)
        return handler

    def set_handler_level(self, handler_name, level, configure_state=None):
        '''
        Given a handler name, set the handler's level, return previous level.

        :parameters:
          handler_name
            Name of the handler to look-up.
          level
            The new level for the handler.  See
            `log_manager.parse_log_level()` for details on how the
            level can be specified.
          configure_state
            If other than None update the log manger's configure_state
            variable to this object. Clients of the log manager can
            use configure_state to track the state of the log manager.

        :returns:
          The handler's previous level
        '''
        handler = self.get_handler(handler_name)
        level = parse_log_level(level)
        prev_level = handler.level
        handler.setLevel(level)
        self.apply_configuration(configure_state)
        return prev_level

    def get_loggers_with_handler(self, handler):
        '''
        Given a handler return a list of loggers that hander is bound to.


        :parameters:
          handler
            The name of a handler or a handler object.

        :returns:
          List of loggers with the handler is bound to.
        '''

        if isinstance(handler, six.string_types):
            handler = self.get_handler(handler)
        elif isinstance(handler, logging.Handler):
            if not handler in self.handlers.values():
                raise ValueError('handler "%s" is not managed by this log manager' % \
                                 logging_obj_str(handler))
        else:
            raise TypeError('handler must be basestring or Handler object, got %s' % type(handler))

        loggers = []
        for logger in self.loggers.values():
            if handler in  logger.handlers:
                loggers.append(logger)

        return loggers

    def remove_handler(self, handler, logger=None, configure_state=None):
        '''
        Remove the named handler. If logger is unspecified the handler
        will be removed from all managed loggers, otherwise it will be
        removed from only the specified logger.

        :parameters:
          handler
            The name of the handler to be removed or the handler object.
          logger
            If unspecified the handler is removed from all loggers,
            otherwise the handler is removed from only this logger.
          configure_state
            If other than None update the log manger's configure_state
            variable to this object. Clients of the log manager can
            use configure_state to track the state of the log manager.
        '''

        if isinstance(handler, six.string_types):
            handler = self.get_handler(handler)
        elif not isinstance(handler, logging.Handler):
            raise TypeError('handler must be basestring or Handler object, got %s' % type(handler))

        handler_name = handler.name
        if handler_name is None:
            raise ValueError('handler "%s" does not have a name' % logging_obj_str(handler))

        loggers = self.get_loggers_with_handler(handler)

        if logger is None:
            for logger in loggers:
                logger.removeHandler(handler)
            del self.handlers[handler_name]
        else:
            if not logger in loggers:
                raise ValueError('handler "%s" is not bound to logger "%s"' % \
                                 (handler_name, logging_obj_str(logger)))
            logger.removeHandler(handler)
            if len(loggers) == 1:
                del self.handlers[handler_name]

        self.apply_configuration(configure_state)

    def apply_configuration(self, configure_state=None):
        '''
        Using the log manager's internal configuration state apply the
        configuration to all the objects managed by the log manager.

        :parameters:
          configure_state
            If other than None update the log manger's configure_state
            variable to this object. Clients of the log manager can
            use configure_state to track the state of the log manager.

        '''
        if configure_state is not None:
            self.configure_state = configure_state
        for logger in self.loggers.values():
            self._set_configured_logger_level(logger)

    def get_configured_logger_level(self, name):
        '''
        Given a logger name return it's level as defined by the
        `LogManager` configuration.

        :parameters:
          name
            logger name
        :returns:
          log level
        '''
        level = self.default_level
        for regexp, config_level in self.logger_regexps:
            if re.search(regexp, name):
                level = config_level
                break

        level = parse_log_level(level)
        return level

    def get_logger_handlers(self, logger):
        '''
        Return the set of unique handlers visible to this logger.

        :parameters:
          logger
            The logger whose visible and enabled handlers will be returned.

        :return:
          Set of handlers
        '''
        handlers = set()

        while logger:
            for handler in logger.handlers:
                handlers.add(handler)
            if logger.propagate:
                logger = logger.parent
            else:
                logger = None
        return handlers

    def get_minimum_handler_level_for_logger(self, logger):
        '''
        Return the minimum handler level of all the handlers the
        logger is exposed to.

        :parameters:
          logger
            The logger whose handlers will be examined.

        :return:
          The minimum of all the handler's levels. If no
          handlers are defined sys.maxsize will be returned.
        '''

        handlers = self.get_logger_handlers(logger)
        min_level = get_minimum_level(handlers)
        return min_level

    def _set_configured_logger_level(self, logger):
        '''
        Based on the current configuration maintained by the log
        manager set this logger's level.

        If the level specified for this logger by the configuration is
        less than the minimum level supported by the output handlers
        the logger is exposed to then adjust the logger's level higher
        to the minimum handler level. This is a performance
        optimization, no point in emitting a log message if no
        handlers will ever output it.

        :parameters:
          logger
            The logger whose level is being configured.

        :return:
          The level actually set on the logger.
        '''
        level = self.get_configured_logger_level(logger.name)
        minimum_handler_level = self.get_minimum_handler_level_for_logger(logger)
        if level < minimum_handler_level:
            level = minimum_handler_level
        logger.setLevel(level)
        return level

    def get_logger(self, who, bind_logger_names=False):
        '''
        Return the logger for an object or a name. If the logger
        already exists return the existing instance otherwise create
        the logger.

        The who parameter may be either a name or an object.
        Loggers are identified by a name but because loggers are
        usually bound to a class this method is optimized to handle
        that case. If who is an object:

        * The name object's module name (dot seperated) and the
          object's class name.

        * Optionally the logging output methods can be bound to the
          object if bind_logger_names is True.

        Otherwise if who is a basestring it is used as the logger
        name.

        In all instances the root_logger_name is prefixed to every
        logger created by the manager.

        :parameters:
          who
            If a basestring then use this as the logger name,
            prefixed with the root_logger_name. Otherwise who is treated
            as a class instance. The logger name is formed by prepending
            the root_logger_name to the module name and then appending the
            class name. All name components are dot seperated. Thus if the
            root_logger_name is 'my_app', the class is ParseFileConfig
            living in the config.parsers module the logger name will be:
            ``my_app.config.parsers.ParseFileConfig``.
          bind_logger_names
            If true the class instance will have the following bound
            to it: ``log``, ``debug()``, ``info()``, ``warning()``,
            ``error()``, ``exception()``, ``critical()``. Where log is
            the logger object and the others are the loggers output
            methods. This is a convenience which allows you emit
            logging messages directly, for example::

              self.debug('%d names defined', self.num_names).

        :return:
          The logger matching the name indicated by who. If the
          logger pre-existed return that instance otherwise create the
          named logger return it.
        '''

        is_object = False
        if isinstance(who, six.string_types):
            obj_name = who
        else:
            is_object = True
            obj_name = '%s.%s' % (who.__module__, who.__class__.__name__)

        if obj_name == self.root_logger_name:
            logger_name = obj_name
        else:
            logger_name = self.root_logger_name + '.' + obj_name

        # If logger not in our cache then create and initialize the logger.
        logger = self.loggers.get(logger_name)
        if logger is None:
            logger = logging.getLogger(logger_name)
            self.loggers[logger_name] = logger
            self._set_configured_logger_level(logger)

        if bind_logger_names and is_object and getattr(who, '__log_manager', None) is None:
            setattr(who, '__log_manager', self)
            method = 'log'
            if hasattr(who, method):
                raise ValueError('%s is already bound to %s' % (method, repr(who)))
            setattr(who, method, logger)

            for method in logger_method_names:
                if hasattr(who, method):
                    raise ValueError('%s is already bound to %s' % (method, repr(who)))
                setattr(who, method, getattr(logger, method))

        return logger
