# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import string
import tempfile
import logging
import subprocess
import os

def select_user(counter, users):
    """counter is the number of User objects in users
       users is a list of User objects

       This purposely doesn't catch KeyboardInterrupt
    """
    i = 1
    print "%s entries were found. Which one would you like to display?" % counter
    for ent in users:
        print "%s: %s (%s)" % (i, ent.getValues('cn'), ent.getValues('uid'))
        i += 1
    while True:
        resp = raw_input("Choose one: (1 - %s), 0 for all, q to quit: " % counter)
        if resp == "q":
            return "q"
        if resp == "0":
            userindex = -1
            break
        try:
            userindex = int(resp) - 1
            if (userindex >= 0 and userindex < counter):
                break
        except:
            # fall through to the error msg
            pass
 
        print "Please enter a number between 1 and %s" % counter

    return userindex

def select_group(counter, groups):
    """counter is the number of Group objects in users
       users is a list of Group objects

       This purposely doesn't catch KeyboardInterrupt
    """
    i = 1
    print "%s entries were found. Which one would you like to display?" % counter
    for ent in groups:
        print "%s: %s" % (i, ent.getValues('cn'))
        i += 1
    while True:
        resp = raw_input("Choose one: (1 - %s), 0 for all, q to quit: " % counter)
        if resp == "q":
            return "q"
        if resp == "0":
            groupindex = -1
            break
        try:
            groupindex = int(resp) - 1
            if (groupindex >= 0 and groupindex < counter):
                break
        except:
            # fall through to the error msg
            pass

        print "Please enter a number between 1 and %s" % counter

    return groupindex
