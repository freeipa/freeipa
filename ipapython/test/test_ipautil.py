#! /usr/bin/python -E
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
sys.path.insert(0, ".")

import unittest
import datetime

from ipapython import ipautil


class TestCIDict(unittest.TestCase):
    def setUp(self):
        self.cidict = ipautil.CIDict()
        self.cidict["Key1"] = "val1"
        self.cidict["key2"] = "val2"
        self.cidict["KEY3"] = "VAL3"

    def tearDown(self):
        pass

    def testLen(self):
        self.assertEqual(3, len(self.cidict))

    def test__GetItem(self):
        self.assertEqual("val1", self.cidict["Key1"])
        self.assertEqual("val1", self.cidict["key1"])
        self.assertEqual("val2", self.cidict["KEY2"])
        self.assertEqual("VAL3", self.cidict["key3"])
        self.assertEqual("VAL3", self.cidict["KEY3"])
        try:
            self.cidict["key4"]
            fail("should have raised KeyError")
        except KeyError:
            pass

    def testGet(self):
        self.assertEqual("val1", self.cidict.get("Key1"))
        self.assertEqual("val1", self.cidict.get("key1"))
        self.assertEqual("val2", self.cidict.get("KEY2"))
        self.assertEqual("VAL3", self.cidict.get("key3"))
        self.assertEqual("VAL3", self.cidict.get("KEY3"))
        self.assertEqual("default", self.cidict.get("key4", "default"))

    def test__SetItem(self):
        self.cidict["key4"] = "val4"
        self.assertEqual("val4", self.cidict["key4"])
        self.cidict["KEY4"] = "newval4"
        self.assertEqual("newval4", self.cidict["key4"])

    def testDel(self):
        self.assert_(self.cidict.has_key("Key1"))
        del(self.cidict["Key1"])
        self.failIf(self.cidict.has_key("Key1"))

        self.assert_(self.cidict.has_key("key2"))
        del(self.cidict["KEY2"])
        self.failIf(self.cidict.has_key("key2"))

    def testClear(self):
        self.assertEqual(3, len(self.cidict))
        self.cidict.clear()
        self.assertEqual(0, len(self.cidict))

    def testCopy(self):
        """A copy is no longer a CIDict, but should preserve the case of
           the keys as they were inserted."""
        copy = self.cidict.copy()
        self.assertEqual(3, len(copy))
        self.assert_(copy.has_key("Key1"))
        self.assertEqual("val1", copy["Key1"])
        self.failIf(copy.has_key("key1"))

    def testHasKey(self):
        self.assert_(self.cidict.has_key("KEY1"))
        self.assert_(self.cidict.has_key("key2"))
        self.assert_(self.cidict.has_key("key3"))

    def testItems(self):
        items = self.cidict.items()
        self.assertEqual(3, len(items))
        items_set = set(items)
        self.assert_(("Key1", "val1") in items_set)
        self.assert_(("key2", "val2") in items_set)
        self.assert_(("KEY3", "VAL3") in items_set)

    def testIterItems(self):
        items = []
        for (k,v) in self.cidict.iteritems():
            items.append((k,v))
        self.assertEqual(3, len(items))
        items_set = set(items)
        self.assert_(("Key1", "val1") in items_set)
        self.assert_(("key2", "val2") in items_set)
        self.assert_(("KEY3", "VAL3") in items_set)

    def testIterKeys(self):
        keys = []
        for k in self.cidict.iterkeys():
            keys.append(k)
        self.assertEqual(3, len(keys))
        keys_set = set(keys)
        self.assert_("Key1" in keys_set)
        self.assert_("key2" in keys_set)
        self.assert_("KEY3" in keys_set)

    def testIterValues(self):
        values = []
        for k in self.cidict.itervalues():
            values.append(k)
        self.assertEqual(3, len(values))
        values_set = set(values)
        self.assert_("val1" in values_set)
        self.assert_("val2" in values_set)
        self.assert_("VAL3" in values_set)

    def testKeys(self):
        keys = self.cidict.keys()
        self.assertEqual(3, len(keys))
        keys_set = set(keys)
        self.assert_("Key1" in keys_set)
        self.assert_("key2" in keys_set)
        self.assert_("KEY3" in keys_set)

    def testValues(self):
        values = self.cidict.values()
        self.assertEqual(3, len(values))
        values_set = set(values)
        self.assert_("val1" in values_set)
        self.assert_("val2" in values_set)
        self.assert_("VAL3" in values_set)

    def testUpdate(self):
        newdict = { "KEY2": "newval2",
                    "key4": "val4" }
        self.cidict.update(newdict)
        self.assertEqual(4, len(self.cidict))

        items = self.cidict.items()
        self.assertEqual(4, len(items))
        items_set = set(items)
        self.assert_(("Key1", "val1") in items_set)
        # note the update "overwrites" the case of the key2
        self.assert_(("KEY2", "newval2") in items_set)
        self.assert_(("KEY3", "VAL3") in items_set)
        self.assert_(("key4", "val4") in items_set)

    def testSetDefault(self):
        self.assertEqual("val1", self.cidict.setdefault("KEY1", "default"))

        self.failIf(self.cidict.has_key("KEY4"))
        self.assertEqual("default", self.cidict.setdefault("KEY4", "default"))
        self.assert_(self.cidict.has_key("KEY4"))
        self.assertEqual("default", self.cidict["key4"])

        self.failIf(self.cidict.has_key("KEY5"))
        self.assertEqual(None, self.cidict.setdefault("KEY5"))
        self.assert_(self.cidict.has_key("KEY5"))
        self.assertEqual(None, self.cidict["key5"])

    def testPop(self):
        self.assertEqual("val1", self.cidict.pop("KEY1", "default"))
        self.failIf(self.cidict.has_key("key1"))

        self.assertEqual("val2", self.cidict.pop("KEY2"))
        self.failIf(self.cidict.has_key("key2"))

        self.assertEqual("default", self.cidict.pop("key4", "default"))
        try:
            self.cidict.pop("key4")
            fail("should have raised KeyError")
        except KeyError:
            pass

    def testPopItem(self):
        items = set(self.cidict.items())
        self.assertEqual(3, len(self.cidict))

        item = self.cidict.popitem()
        self.assertEqual(2, len(self.cidict))
        self.assert_(item in items)
        items.discard(item)

        item = self.cidict.popitem()
        self.assertEqual(1, len(self.cidict))
        self.assert_(item in items)
        items.discard(item)

        item = self.cidict.popitem()
        self.assertEqual(0, len(self.cidict))
        self.assert_(item in items)
        items.discard(item)

class TestTimeParser(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testSimple(self):
        timestr = "20070803"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(2007, time.year)
        self.assertEqual(8, time.month)
        self.assertEqual(3, time.day)
        self.assertEqual(0, time.hour)
        self.assertEqual(0, time.minute)
        self.assertEqual(0, time.second)

    def testHourMinSec(self):
        timestr = "20051213141205"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(2005, time.year)
        self.assertEqual(12, time.month)
        self.assertEqual(13, time.day)
        self.assertEqual(14, time.hour)
        self.assertEqual(12, time.minute)
        self.assertEqual(5, time.second)

    def testFractions(self):
        timestr = "2003092208.5"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(2003, time.year)
        self.assertEqual(9, time.month)
        self.assertEqual(22, time.day)
        self.assertEqual(8, time.hour)
        self.assertEqual(30, time.minute)
        self.assertEqual(0, time.second)

        timestr = "199203301544,25"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(1992, time.year)
        self.assertEqual(3, time.month)
        self.assertEqual(30, time.day)
        self.assertEqual(15, time.hour)
        self.assertEqual(44, time.minute)
        self.assertEqual(15, time.second)

        timestr = "20060401185912,8"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(2006, time.year)
        self.assertEqual(4, time.month)
        self.assertEqual(1, time.day)
        self.assertEqual(18, time.hour)
        self.assertEqual(59, time.minute)
        self.assertEqual(12, time.second)
        self.assertEqual(800000, time.microsecond)

    def testTimeZones(self):
        timestr = "20051213141205Z"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(0, time.tzinfo.houroffset)
        self.assertEqual(0, time.tzinfo.minoffset)
        offset = time.tzinfo.utcoffset(time.tzinfo.dst())
        self.assertEqual(0, offset.seconds)

        timestr = "20051213141205+0500"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(5, time.tzinfo.houroffset)
        self.assertEqual(0, time.tzinfo.minoffset)
        offset = time.tzinfo.utcoffset(time.tzinfo.dst())
        self.assertEqual(5 * 60 * 60, offset.seconds)

        timestr = "20051213141205-0500"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(-5, time.tzinfo.houroffset)
        self.assertEqual(0, time.tzinfo.minoffset)
        # NOTE - the offset is always positive - it's minutes
        #        _east_ of UTC
        offset = time.tzinfo.utcoffset(time.tzinfo.dst())
        self.assertEqual((24 - 5) * 60 * 60, offset.seconds)

        timestr = "20051213141205-0930"

        time = ipautil.parse_generalized_time(timestr)
        self.assertEqual(-9, time.tzinfo.houroffset)
        self.assertEqual(-30, time.tzinfo.minoffset)
        offset = time.tzinfo.utcoffset(time.tzinfo.dst())
        self.assertEqual(((24 - 9) * 60 * 60) - (30 * 60), offset.seconds)


if __name__ == '__main__':
    unittest.main()
