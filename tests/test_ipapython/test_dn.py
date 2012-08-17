#!/usr/bin/python

import unittest
from ipapython.dn import *

def default_rdn_attr_arg(i):
    return 'a%d' % i

def default_rdn_value_arg(i):
    return str(i)

def alt_rdn_attr_arg(i):
    return 'b%d' % i

def alt_rdn_value_arg(i):
    return str(i*10)

def make_rdn_args(low, high, kind, attr=None, value=None):
    result=[]
    for i in range(low, high):
        if attr is None:
            new_attr = default_rdn_attr_arg(i)
        elif callable(attr):
            new_attr = attr(i)
        else:
            new_attr = attr

        if value is None:
            new_value = default_rdn_value_arg(i)
        elif callable(value):
            new_value = value(i)
        else:
            new_value = value

        if kind == 'tuple':
            result.append((new_attr, new_value))
        elif kind == 'list':
            result.append([new_attr, new_value])
        elif kind == 'RDN':
            result.append(RDN((new_attr, new_value)))
        else:
            raise ValueError("Unknown kind = %s" % kind)

    return result

def expected_class(klass, component):
    if klass is AVA:
        if component == 'self':
            return AVA

    elif klass is EditableAVA:
        if component == 'self':
            return EditableAVA

    elif klass is RDN:
        if component == 'self':
            return RDN
        elif component == 'AVA':
            return AVA

    elif klass is EditableRDN:
        if component == 'self':
            return EditableRDN
        elif component == 'AVA':
            return EditableAVA

    elif klass is DN:
        if component == 'self':
            return DN
        elif component == 'AVA':
            return AVA
        elif component == 'RDN':
            return RDN

    elif klass is EditableDN:
        if component == 'self':
            return EditableDN
        elif component == 'AVA':
            return EditableAVA
        elif component == 'RDN':
            return EditableRDN

    raise ValueError("class %s with component '%s' unknown" % (klass.__name__, component))


class TestAVA(unittest.TestCase):
    def setUp(self):
        self.attr1    = 'cn'
        self.value1   = 'Bob'
        self.str_ava1 = '%s=%s' % (self.attr1, self.value1)
        self.ava1     = AVA(self.attr1, self.value1)

        self.attr2    = 'ou'
        self.value2   = 'People'
        self.str_ava2 = '%s=%s' % (self.attr2, self.value2)
        self.ava2     = AVA(self.attr2, self.value2)

        self.attr3    = 'c'
        self.value3   = 'US'
        self.str_ava3 = '%s=%s' % (self.attr3, self.value3)
        self.ava3     = AVA(self.attr3, self.value3)

    def assertExpectedClass(self, klass, obj, component):
        self.assertIs(obj.__class__, expected_class(klass, component))

    def test_create(self):
        for AVA_class in (AVA, EditableAVA):
            # Create with attr,value pair
            ava1 = AVA_class(self.attr1, self.value1)
            self.assertExpectedClass(AVA_class, ava1, 'self')
            self.assertEqual(ava1, self.ava1)

            # Create with "attr=value" string
            ava1 = AVA_class(self.str_ava1)
            self.assertExpectedClass(AVA_class, ava1, 'self')
            self.assertEqual(ava1, self.ava1)

            # Create with tuple (attr, value)
            ava1 = AVA_class((self.attr1, self.value1))
            self.assertExpectedClass(AVA_class, ava1, 'self')
            self.assertEqual(ava1, self.ava1)

            # Create with list [attr, value]
            ava1 = AVA_class([self.attr1, self.value1])
            self.assertExpectedClass(AVA_class, ava1, 'self')
            self.assertEqual(ava1, self.ava1)

            # Create with no args should fail
            with self.assertRaises(TypeError):
                AVA_class()

            # Create with more than 2 args should fail
            with self.assertRaises(TypeError):
                AVA_class(self.attr1, self.value1, self.attr1)

            # Create with 1 arg which is not string should fail
            with self.assertRaises(TypeError):
                AVA_class(1)

            # Create with malformed AVA_class string should fail
            with self.assertRaises(ValueError):
                AVA_class("cn")

            # Create with non-string parameters, should convert
            ava1 = AVA_class(1, self.value1)
            self.assertExpectedClass(AVA_class, ava1, 'self')
            self.assertEqual(ava1.attr, u'1')

            ava1 = AVA_class((1, self.value1))
            self.assertExpectedClass(AVA_class, ava1, 'self')
            self.assertEqual(ava1.attr, u'1')

            ava1 = AVA_class(self.attr1, 1)
            self.assertExpectedClass(AVA_class, ava1, 'self')
            self.assertEqual(ava1.value, u'1')

            ava1 = AVA_class((self.attr1, 1))
            self.assertExpectedClass(AVA_class, ava1, 'self')
            self.assertEqual(ava1.value, u'1')

    def test_indexing(self):
        for AVA_class in (AVA, EditableAVA):
            ava1 = AVA_class(self.ava1)

            self.assertEqual(ava1[self.attr1], self.value1)

            with self.assertRaises(KeyError):
                ava1['foo']

            with self.assertRaises(TypeError):
                ava1[0]

    def test_properties(self):
        for AVA_class in (AVA, EditableAVA):
            ava1 = AVA_class(self.ava1)

            self.assertEqual(ava1.attr, self.attr1)
            self.assertIsInstance(ava1.attr, unicode)

            self.assertEqual(ava1.value, self.value1)
            self.assertIsInstance(ava1.value, unicode)

    def test_str(self):
        for AVA_class in (AVA, EditableAVA):
            ava1 = AVA_class(self.ava1)

            self.assertEqual(str(ava1), self.str_ava1)
            self.assertIsInstance(str(ava1), str)

    def test_cmp(self):
        for AVA_class in (AVA, EditableAVA):
            # Equality
            ava1 = AVA_class(self.attr1, self.value1)

            self.assertTrue(ava1 == self.ava1)
            self.assertFalse(ava1 != self.ava1)

            self.assertTrue(ava1 == self.str_ava1)
            self.assertFalse(ava1 != self.str_ava1)

            result = cmp(ava1, self.ava1)
            self.assertEqual(result, 0)

            # Upper case attr should still be equal
            ava1 = AVA_class(self.attr1.upper(), self.value1)

            self.assertFalse(ava1.attr == self.attr1)
            self.assertTrue(ava1.value == self.value1)
            self.assertTrue(ava1 == self.ava1)
            self.assertFalse(ava1 != self.ava1)

            result = cmp(ava1, self.ava1)
            self.assertEqual(result, 0)

            # Upper case value should still be equal
            ava1 = AVA_class(self.attr1, self.value1.upper())

            self.assertTrue(ava1.attr == self.attr1)
            self.assertFalse(ava1.value == self.value1)
            self.assertTrue(ava1 == self.ava1)
            self.assertFalse(ava1 != self.ava1)

            result = cmp(ava1, self.ava1)
            self.assertEqual(result, 0)

            # Make ava1's attr greater
            if AVA_class.is_mutable:
                ava1.attr = self.attr1 + "1"
            else:
                with self.assertRaises(AttributeError):
                    ava1.attr = self.attr1 + "1"
                ava1 = AVA_class(self.attr1 + "1", self.value1.upper())

            self.assertFalse(ava1 == self.ava1)
            self.assertTrue(ava1 != self.ava1)

            result = cmp(ava1, self.ava1)
            self.assertEqual(result, 1)

            result = cmp(self.ava1, ava1)
            self.assertEqual(result, -1)

            # Reset ava1's attr, should be equal again
            if AVA_class.is_mutable:
                ava1.attr = self.attr1
            else:
                with self.assertRaises(AttributeError):
                    ava1.attr = self.attr1
                ava1 = AVA_class(self.attr1, self.value1.upper())

            result = cmp(ava1, self.ava1)
            self.assertEqual(result, 0)

            # Make ava1's value greater
            # attr will be equal, this tests secondary comparision component
            if AVA_class.is_mutable:
                ava1.value = self.value1 + "1"
            else:
                with self.assertRaises(AttributeError):
                    ava1.value = self.value1 + "1"
                ava1 = AVA_class(self.attr1, self.value1 + "1")

            result = cmp(ava1, self.ava1)
            self.assertEqual(result, 1)

            result = cmp(self.ava1, ava1)
            self.assertEqual(result, -1)

    def test_hashing(self):
        # create AVA's that are equal but differ in case
        immutable_ava1 = AVA((self.attr1.lower(), self.value1.upper()))
        immutable_ava2 = AVA((self.attr1.upper(), self.value1.lower()))

        mutable_ava1   = EditableAVA((self.attr1.lower(), self.value1.upper()))
        mutable_ava2   = EditableAVA((self.attr1.upper(), self.value1.lower()))

        # Immutable AVA's that are equal should hash to the same value.
        # Mutable AVA's should not be hashable.

        self.assertEqual(immutable_ava1, immutable_ava2)
        self.assertEqual(immutable_ava1, mutable_ava1)
        self.assertEqual(immutable_ava1, mutable_ava2)
        self.assertEqual(mutable_ava1, immutable_ava2)

        # Good, everyone's equal, now verify their hash values

        self.assertEqual(hash(immutable_ava1), hash(immutable_ava2))
        with self.assertRaises(TypeError):
            hash(mutable_ava1)
        with self.assertRaises(TypeError):
            hash(mutable_ava2)

        # Different immutable AVA objects with the same value should
        # map to 1 common key and 1 member in a set. The key and
        # member are based on the object's value.
        #
        # Mutable AVA objects should be unhashable.

        for AVA_class in (AVA, EditableAVA):
            ava1_a = AVA_class(self.ava1)
            ava1_b = AVA_class(self.ava1)

            ava2_a = AVA_class(self.ava2)
            ava2_b = AVA_class(self.ava2)

            ava3_a = AVA_class(self.ava3)
            ava3_b = AVA_class(self.ava3)

            self.assertEqual(ava1_a, ava1_b)
            self.assertEqual(ava2_a, ava2_b)
            self.assertEqual(ava3_a, ava3_b)

            d = dict()
            s = set()

            if AVA_class.is_mutable:
                with self.assertRaises(TypeError):
                    d[ava1_a] = str(ava1_a)
                with self.assertRaises(TypeError):
                    d[ava1_b] = str(ava1_b)
                with self.assertRaises(TypeError):
                    d[ava2_a] = str(ava2_a)
                with self.assertRaises(TypeError):
                    d[ava2_b] = str(ava2_b)

                with self.assertRaises(TypeError):
                    s.add(ava1_a)
                with self.assertRaises(TypeError):
                    s.add(ava1_b)
                with self.assertRaises(TypeError):
                    s.add(ava2_a)
                with self.assertRaises(TypeError):
                    s.add(ava2_b)
            else:
                d[ava1_a] = str(ava1_a)
                d[ava1_b] = str(ava1_b)
                d[ava2_a] = str(ava2_a)
                d[ava2_b] = str(ava2_b)

                s.add(ava1_a)
                s.add(ava1_b)
                s.add(ava2_a)
                s.add(ava2_b)

                self.assertEqual(len(d), 2)
                self.assertEqual(len(s), 2)
                self.assertEqual(sorted(d.keys()), sorted([ava1_a, ava2_a]))
                self.assertEqual(sorted(s), sorted([ava1_a, ava2_a]))

                self.assertTrue(ava1_a in d)
                self.assertTrue(ava1_b in d)
                self.assertTrue(ava2_a in d)
                self.assertTrue(ava2_b in d)
                self.assertFalse(ava3_a in d)
                self.assertFalse(ava3_b in d)

                self.assertTrue(d.has_key(ava1_a))
                self.assertTrue(d.has_key(ava1_b))
                self.assertTrue(d.has_key(ava2_a))
                self.assertTrue(d.has_key(ava2_b))
                self.assertFalse(d.has_key(ava3_a))
                self.assertFalse(d.has_key(ava3_b))

                self.assertTrue(ava1_a in s)
                self.assertTrue(ava1_b in s)
                self.assertTrue(ava2_a in s)
                self.assertTrue(ava2_b in s)
                self.assertFalse(ava3_a in s)
                self.assertFalse(ava3_b in s)

    def test_coerce(self):
        # Coerce an immutable to a mutable
        immutable_ava1 = AVA(self.ava1)
        mutable_ava1 = EditableAVA(immutable_ava1)
        self.assertEqual(mutable_ava1, self.ava1)
        self.assertEqual(mutable_ava1, immutable_ava1)

        # Coerce a mutable to an immutable
        mutable_ava1 = EditableAVA(self.ava1)
        immutable_ava1 = AVA(mutable_ava1)
        self.assertEqual(immutable_ava1, self.ava1)
        self.assertEqual(immutable_ava1, mutable_ava1)

class TestRDN(unittest.TestCase):
    def setUp(self):
        # ava1 must sort before ava2
        self.attr1    = 'cn'
        self.value1   = 'Bob'
        self.str_ava1 = '%s=%s' % (self.attr1, self.value1)
        self.ava1     = AVA(self.attr1, self.value1)

        self.str_rdn1 = '%s=%s' % (self.attr1, self.value1)
        self.rdn1 = RDN((self.attr1, self.value1))

        self.attr2    = 'ou'
        self.value2   = 'people'
        self.str_ava2 = '%s=%s' % (self.attr2, self.value2)
        self.ava2     = AVA(self.attr2, self.value2)

        self.str_rdn2 = '%s=%s' % (self.attr2, self.value2)
        self.rdn2     = RDN((self.attr2, self.value2))

        self.str_ava3 = '%s=%s+%s=%s' % (self.attr1, self.value1, self.attr2, self.value2)

        self.str_rdn3 = '%s=%s+%s=%s' % (self.attr1, self.value1, self.attr2, self.value2)
        self.rdn3 = RDN(self.ava1, self.ava2)

    def assertExpectedClass(self, klass, obj, component):
        self.assertIs(obj.__class__, expected_class(klass, component))

    def test_create(self):
        for RDN_class in (RDN, EditableRDN):
            # Create with single attr,value pair
            rdn1 = RDN_class((self.attr1, self.value1))


            self.assertEqual(len(rdn1), 1)
            self.assertEqual(rdn1, self.rdn1)
            self.assertExpectedClass(RDN_class, rdn1, 'self')
            for i in range(0, len(rdn1)):
                self.assertExpectedClass(RDN_class, rdn1[i], 'AVA')
            self.assertEqual(rdn1[0], self.ava1)

            # Create with multiple attr,value pairs
            rdn3 = RDN_class((self.attr1, self.value1), (self.attr2, self.value2))
            self.assertEqual(len(rdn3), 2)
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')
            self.assertEqual(rdn3[0], self.ava1)
            self.assertEqual(rdn3[1], self.ava2)

            # Create with multiple attr,value pairs passed as lists
            rdn3 = RDN_class([self.attr1, self.value1], [self.attr2, self.value2])
            self.assertEqual(len(rdn3), 2)
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')
            self.assertEqual(rdn3[0], self.ava1)
            self.assertEqual(rdn3[1], self.ava2)

            # Create with multiple attr,value pairs but reverse
            # constructor parameter ordering. RDN canonical ordering
            # should remain the same
            rdn3 = RDN_class((self.attr2, self.value2), (self.attr1, self.value1))
            self.assertEqual(len(rdn3), 2)
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')
            self.assertEqual(rdn3[0], self.ava1)
            self.assertEqual(rdn3[1], self.ava2)

            # Create with single AVA object
            rdn1 = RDN_class(self.ava1)
            self.assertEqual(len(rdn1), 1)
            self.assertEqual(rdn1, self.rdn1)
            self.assertExpectedClass(RDN_class, rdn1, 'self')
            for i in range(0, len(rdn1)):
                self.assertExpectedClass(RDN_class, rdn1[i], 'AVA')
            self.assertEqual(rdn1[0], self.ava1)

            # Create with multiple AVA objects
            rdn3 = RDN_class(self.ava1, self.ava2)
            self.assertEqual(len(rdn3), 2)
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')
            self.assertEqual(rdn3[0], self.ava1)
            self.assertEqual(rdn3[1], self.ava2)


            # Create with multiple AVA objects but reverse constructor
            # parameter ordering.  RDN canonical ordering should remain
            # the same
            rdn3 = RDN_class(self.ava2, self.ava1)
            self.assertEqual(len(rdn3), 2)
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')
            self.assertEqual(rdn3[0], self.ava1)
            self.assertEqual(rdn3[1], self.ava2)

            # Create with single string with 1 AVA
            rdn1 = RDN_class(self.str_rdn1)
            self.assertEqual(len(rdn1), 1)
            self.assertEqual(rdn1, self.rdn1)
            self.assertExpectedClass(RDN_class, rdn1, 'self')
            for i in range(0, len(rdn1)):
                self.assertExpectedClass(RDN_class, rdn1[i], 'AVA')
            self.assertEqual(rdn1[0], self.ava1)

            # Create with single string with 2 AVA's
            rdn3 = RDN_class(self.str_rdn3)
            self.assertEqual(len(rdn3), 2)
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')
            self.assertEqual(rdn3[0], self.ava1)
            self.assertEqual(rdn3[1], self.ava2)

    def test_properties(self):
        for RDN_class in (RDN, EditableRDN):
            rdn1 = RDN_class(self.rdn1)
            rdn2 = RDN_class(self.rdn2)
            rdn3 = RDN_class(self.rdn3)

            self.assertEqual(rdn1.attr, self.attr1)
            self.assertIsInstance(rdn1.attr, unicode)

            self.assertEqual(rdn1.value, self.value1)
            self.assertIsInstance(rdn1.value, unicode)

            self.assertEqual(rdn2.attr, self.attr2)
            self.assertIsInstance(rdn2.attr, unicode)

            self.assertEqual(rdn2.value, self.value2)
            self.assertIsInstance(rdn2.value, unicode)

            self.assertEqual(rdn3.attr, self.attr1)
            self.assertIsInstance(rdn3.attr, unicode)

            self.assertEqual(rdn3.value, self.value1)
            self.assertIsInstance(rdn3.value, unicode)

    def test_str(self):
        for RDN_class in (RDN, EditableRDN):
            rdn1 = RDN_class(self.rdn1)
            rdn2 = RDN_class(self.rdn2)
            rdn3 = RDN_class(self.rdn3)

            self.assertEqual(str(rdn1), self.str_rdn1)
            self.assertIsInstance(str(rdn1), str)

            self.assertEqual(str(rdn2), self.str_rdn2)
            self.assertIsInstance(str(rdn2), str)

            self.assertEqual(str(rdn3), self.str_rdn3)
            self.assertIsInstance(str(rdn3), str)

    def test_cmp(self):
        for RDN_class in (RDN, EditableRDN):
            # Equality
            rdn1 = RDN_class((self.attr1, self.value1))

            self.assertTrue(rdn1 == self.rdn1)
            self.assertFalse(rdn1 != self.rdn1)

            self.assertTrue(rdn1 == self.str_rdn1)
            self.assertFalse(rdn1 != self.str_rdn1)

            result = cmp(rdn1, self.rdn1)
            self.assertEqual(result, 0)

            # Make rdn1's attr greater
            if RDN_class.is_mutable:
                rdn1.attr = self.attr1 + "1"
            else:
                rdn1 = RDN_class((self.attr1 + "1", self.value1))

            self.assertFalse(rdn1 == self.rdn1)
            self.assertTrue(rdn1 != self.rdn1)

            result = cmp(rdn1, self.rdn1)
            self.assertEqual(result, 1)

            result = cmp(self.rdn1, rdn1)
            self.assertEqual(result, -1)

            # Reset rdn1's attr, should be equal again
            if RDN_class.is_mutable:
                rdn1.attr = self.attr1
            else:
                rdn1 = RDN_class((self.attr1, self.value1))

            result = cmp(rdn1, self.rdn1)
            self.assertEqual(result, 0)

            # Make rdn1's value greater
            # attr will be equal, this tests secondary comparision component
            if RDN_class.is_mutable:
                rdn1.value = self.value1 + "1"
            else:
                rdn1 = RDN_class((self.attr1, self.value1 + "1"))

            result = cmp(rdn1, self.rdn1)
            self.assertEqual(result, 1)

            result = cmp(self.rdn1, rdn1)
            self.assertEqual(result, -1)

            # Make sure rdn's with more ava's are greater
            result = cmp(self.rdn1, self.rdn3)
            self.assertEqual(result, -1)
            result = cmp(self.rdn3, self.rdn1)
            self.assertEqual(result, 1)

    def test_indexing(self):
        for RDN_class in (RDN, EditableRDN):
            rdn1 = RDN_class(self.rdn1)
            rdn2 = RDN_class(self.rdn2)
            rdn3 = RDN_class(self.rdn3)

            self.assertEqual(rdn1[0], self.ava1)
            self.assertEqual(rdn1[self.ava1.attr], self.ava1.value)
            with self.assertRaises(KeyError):
                rdn1['foo']

            self.assertEqual(rdn2[0], self.ava2)
            self.assertEqual(rdn2[self.ava2.attr], self.ava2.value)
            with self.assertRaises(KeyError):
                rdn2['foo']

            self.assertEqual(rdn3[0], self.ava1)
            self.assertEqual(rdn3[self.ava1.attr], self.ava1.value)
            self.assertEqual(rdn3[1], self.ava2)
            self.assertEqual(rdn3[self.ava2.attr], self.ava2.value)
            with self.assertRaises(KeyError):
                rdn3['foo']

            self.assertEqual(rdn1.attr, self.attr1)
            self.assertEqual(rdn1.value, self.value1)

            with self.assertRaises(TypeError):
                rdn3[1.0]

            # Slices
            self.assertEqual(rdn3[0:1], [self.ava1])
            self.assertEqual(rdn3[:],   [self.ava1, self.ava2])

    def test_assignments(self):
        for RDN_class in (RDN, EditableRDN):
            rdn = RDN_class((self.attr1, self.value1))
            if RDN_class.is_mutable:
                rdn[0] = self.ava2
                self.assertEqual(rdn, self.rdn2)
            else:
                with self.assertRaises(TypeError):
                    rdn[0] = self.ava2
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            rdn = RDN_class((self.attr1, self.value1))
            if RDN_class.is_mutable:
                rdn[0] = (self.attr2, self.value2)
                self.assertEqual(rdn, self.rdn2)
            else:
                with self.assertRaises(TypeError):
                    rdn[0] = (self.attr2, self.value2)
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            rdn  = RDN_class((self.attr1, self.value1))
            if RDN_class.is_mutable:
                rdn[self.attr1] = self.str_ava2
                self.assertEqual(rdn[0], self.ava2)
            else:
                with self.assertRaises(TypeError):
                    rdn[self.attr1] = self.str_ava2
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            # Can't assign multiples to single entry
            rdn  = RDN_class((self.attr1, self.value1))
            with self.assertRaises(TypeError):
                rdn[self.attr1] = self.str_ava3
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            rdn  = RDN_class((self.attr1, self.value1))
            with self.assertRaises(TypeError):
                rdn[self.attr1] = (self.attr1, self.value1, self.attr2, self.value2)
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            rdn  = RDN_class((self.attr1, self.value1))
            with self.assertRaises(TypeError):
                rdn[self.attr1] = [(self.attr1, self.value1), (self.attr2, self.value2)]
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            # Slices
            rdn  = RDN_class((self.attr1, self.value1))
            self.assertEqual(rdn, self.rdn1)
            if RDN_class.is_mutable:
                rdn[0:1] = [self.ava2]
                self.assertEqual(rdn, self.rdn2)
            else:
                with self.assertRaises(TypeError):
                    rdn[0:1] = [self.ava2]
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            rdn  = RDN_class((self.attr1, self.value1))
            self.assertEqual(rdn, self.rdn1)
            if RDN_class.is_mutable:
                rdn[:] = [(self.attr2, self.value2)]
                self.assertEqual(rdn, self.rdn2)
            else:
                with self.assertRaises(TypeError):
                    rdn[:] = [(self.attr2, self.value2)]
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            rdn  = RDN_class((self.attr1, self.value1))
            self.assertEqual(rdn, self.rdn1)
            if RDN_class.is_mutable:
                rdn[:] = [(self.attr1, self.value1),(self.attr2, self.value2)]
                self.assertEqual(rdn, self.rdn3)
            else:
                with self.assertRaises(TypeError):
                    rdn[:] = [(self.attr1, self.value1),(self.attr2, self.value2)]
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')

            rdn  = RDN_class((self.attr1, self.value1))
            self.assertEqual(rdn, self.rdn1)
            if RDN_class.is_mutable:
                rdn[0:1] = [(self.attr1, self.value1), (self.attr2, self.value2)]
                self.assertEqual(rdn, self.rdn3)
            else:
                with self.assertRaises(TypeError):
                    rdn[0:1] = [(self.attr1, self.value1), (self.attr2, self.value2)]
            self.assertExpectedClass(RDN_class, rdn, 'self')
            for i in range(0, len(rdn)):
                self.assertExpectedClass(RDN_class, rdn[i], 'AVA')


    def test_iter(self):
        for RDN_class in (RDN, EditableRDN):
            rdn1 = RDN_class(self.rdn1)
            rdn2 = RDN_class(self.rdn2)
            rdn3 = RDN_class(self.rdn3)

            self.assertEqual(len(rdn1), 1)
            self.assertEqual(rdn1[:], [self.ava1])
            for i, ava in enumerate(rdn1):
                if i == 0:
                    self.assertEqual(ava, self.ava1)
                else:
                    self.fail("got iteration index %d, but len=%d" % (i, len(rdn1)))

            self.assertEqual(len(rdn2), 1)
            self.assertEqual(rdn2[:], [self.ava2])
            for i, ava in enumerate(rdn2):
                if i == 0:
                    self.assertEqual(ava, self.ava2)
                else:
                    self.fail("got iteration index %d, but len=%d" % (i, len(rdn2)))

            self.assertEqual(len(rdn3), 2)
            self.assertEqual(rdn3[:], [self.ava1, self.ava2])
            for i, ava in enumerate(rdn3):
                if i == 0:
                    self.assertEqual(ava, self.ava1)
                elif i == 1:
                    self.assertEqual(ava, self.ava2)
                else:
                    self.fail("got iteration index %d, but len=%d" % (i, len(rdn3)))


    def test_concat(self):
        for RDN_class in (RDN, EditableRDN):
            rdn1 = RDN_class((self.attr1, self.value1))
            rdn2 = RDN_class((self.attr2, self.value2))

            # in-place addtion

            # Note: If __iadd__ is not available Python will emulate += by
            # replacing the lhs object with the result of __add__ (if available).
            # Thus += works for both immutable and mutable RDN,DN object, the only
            # difference is an immutable without __iadd__ will have a different object
            # on the lhs after the operator evaluates.

            rdn1 += rdn2
            self.assertEqual(rdn1, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn1, 'self')
            for i in range(0, len(rdn1)):
                self.assertExpectedClass(RDN_class, rdn1[i], 'AVA')

            rdn1 = RDN_class((self.attr1, self.value1))
            rdn1 += self.ava2
            self.assertEqual(rdn1, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn1, 'self')
            for i in range(0, len(rdn1)):
                self.assertExpectedClass(RDN_class, rdn1[i], 'AVA')

            rdn1 = RDN_class((self.attr1, self.value1))
            rdn1 += self.str_ava2
            self.assertEqual(rdn1, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn1, 'self')
            for i in range(0, len(rdn1)):
                self.assertExpectedClass(RDN_class, rdn1[i], 'AVA')

            # concatenation
            rdn1 = RDN_class((self.attr1, self.value1))
            rdn3 = rdn1 + rdn2
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')

            rdn3 = rdn1 + self.ava2
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')

            rdn3 = rdn1 + self.str_ava2
            self.assertEqual(rdn3, self.rdn3)
            self.assertExpectedClass(RDN_class, rdn3, 'self')
            for i in range(0, len(rdn3)):
                self.assertExpectedClass(RDN_class, rdn3[i], 'AVA')


    def test_hashing(self):
        # create RDN's that are equal but differ in case
        immutable_rdn1 = RDN((self.attr1.lower(), self.value1.upper()))
        immutable_rdn2 = RDN((self.attr1.upper(), self.value1.lower()))

        mutable_rdn1   = EditableRDN((self.attr1.lower(), self.value1.upper()))
        mutable_rdn2   = EditableRDN((self.attr1.upper(), self.value1.lower()))

        # Immutable RDN's that are equal should hash to the same value.
        # Mutable RDN's should not be hashable.

        self.assertEqual(immutable_rdn1, immutable_rdn2)
        self.assertEqual(immutable_rdn1, mutable_rdn1)
        self.assertEqual(immutable_rdn1, mutable_rdn2)
        self.assertEqual(mutable_rdn1, immutable_rdn2)

        # Good, everyone's equal, now verify their hash values

        self.assertEqual(hash(immutable_rdn1), hash(immutable_rdn2))
        with self.assertRaises(TypeError):
            hash(mutable_rdn1)
        with self.assertRaises(TypeError):
            hash(mutable_rdn2)

    def test_coerce(self):
        # Coerce an immutable to a mutable
        immutable_rdn3 = RDN(self.rdn3)
        mutable_rdn3 = EditableRDN(immutable_rdn3)
        self.assertEqual(mutable_rdn3, self.rdn3)
        self.assertEqual(mutable_rdn3, immutable_rdn3)

        # Coerce a mutable to an immutable
        mutable_rdn3 = EditableRDN(self.rdn3)
        immutable_rdn3 = RDN(mutable_rdn3)
        self.assertEqual(immutable_rdn3, self.rdn3)
        self.assertEqual(immutable_rdn3, mutable_rdn3)

class TestDN(unittest.TestCase):
    def setUp(self):
        # ava1 must sort before ava2
        self.attr1    = 'cn'
        self.value1   = 'Bob'
        self.str_ava1 = '%s=%s' % (self.attr1, self.value1)
        self.ava1     = AVA(self.attr1, self.value1)

        self.str_rdn1 = '%s=%s' % (self.attr1, self.value1)
        self.rdn1     = RDN((self.attr1, self.value1))

        self.attr2    = 'ou'
        self.value2   = 'people'
        self.str_ava2 = '%s=%s' % (self.attr2, self.value2)
        self.ava2     = AVA(self.attr2, self.value2)

        self.str_rdn2 = '%s=%s' % (self.attr2, self.value2)
        self.rdn2     = RDN((self.attr2, self.value2))

        self.str_dn1 = self.str_rdn1
        self.dn1 = DN(self.rdn1)

        self.str_dn2 = self.str_rdn2
        self.dn2 = DN(self.rdn2)

        self.str_dn3 = '%s,%s' % (self.str_rdn1, self.str_rdn2)
        self.dn3 = DN(self.rdn1, self.rdn2)

        self.base_rdn1 = RDN(('dc', 'redhat'))
        self.base_rdn2 = RDN(('dc', 'com'))
        self.base_dn = DN(self.base_rdn1, self.base_rdn2)

        self.container_rdn1 = RDN(('cn', 'sudorules'))
        self.container_rdn2 = RDN(('cn', 'sudo'))
        self.container_dn = DN(self.container_rdn1, self.container_rdn2)

        self.base_container_dn = DN((self.attr1, self.value1),
                                    self.container_dn, self.base_dn)


    def assertExpectedClass(self, klass, obj, component):
        self.assertIs(obj.__class__, expected_class(klass, component))

    def test_create(self):
        for DN_class in (DN, EditableDN):
            # Create with single attr,value pair
            dn1 = DN_class((self.attr1, self.value1))
            self.assertEqual(len(dn1), 1)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[0].attr, unicode)
            self.assertIsInstance(dn1[0].value, unicode)
            self.assertEqual(dn1[0], self.rdn1)

            # Create with single attr,value pair passed as a tuple
            dn1 = DN_class((self.attr1, self.value1))
            self.assertEqual(len(dn1), 1)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn1)

            # Creation with multiple attr,value string pairs should fail
            with self.assertRaises(ValueError):
                dn1 = DN_class(self.attr1, self.value1, self.attr2, self.value2)

            # Create with multiple attr,value pairs passed as tuples & lists
            dn1 = DN_class((self.attr1, self.value1), [self.attr2, self.value2])
            self.assertEqual(len(dn1), 2)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn1)
            self.assertEqual(dn1[1], self.rdn2)

            # Create with multiple attr,value pairs passed as tuple and RDN
            dn1 = DN_class((self.attr1, self.value1), RDN((self.attr2, self.value2)))
            self.assertEqual(len(dn1), 2)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn1)
            self.assertEqual(dn1[1], self.rdn2)

            # Create with multiple attr,value pairs but reverse
            # constructor parameter ordering. RDN ordering should also be
            # reversed because DN's are a ordered sequence of RDN's
            dn1 = DN_class((self.attr2, self.value2), (self.attr1, self.value1))
            self.assertEqual(len(dn1), 2)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn2)
            self.assertEqual(dn1[1], self.rdn1)

            # Create with single RDN object
            dn1 = DN_class(self.rdn1)
            self.assertEqual(len(dn1), 1)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn1)

            # Create with multiple RDN objects, assure ordering is preserved.
            dn1 = DN_class(self.rdn1, self.rdn2)
            self.assertEqual(len(dn1), 2)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn1)
            self.assertEqual(dn1[1], self.rdn2)

            # Create with multiple RDN objects in different order, assure
            # ordering is preserved.
            dn1 = DN_class(self.rdn2, self.rdn1)
            self.assertEqual(len(dn1), 2)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn2)
            self.assertEqual(dn1[1], self.rdn1)

            # Create with single string with 1 RDN
            dn1 = DN_class(self.str_rdn1)
            self.assertEqual(len(dn1), 1)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn1)

            # Create with single string with 2 RDN's
            dn1 = DN_class(self.str_dn3)
            self.assertEqual(len(dn1), 2)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')
                self.assertIsInstance(dn1[i].attr, unicode)
                self.assertIsInstance(dn1[i].value, unicode)
            self.assertEqual(dn1[0], self.rdn1)
            self.assertEqual(dn1[1], self.rdn2)

            # Create with RDN, and 2 DN's (e.g. attr + container + base)
            dn1 = DN_class((self.attr1, self.value1), self.container_dn, self.base_dn)
            self.assertEqual(len(dn1), 5)
            dn_str = ','.join([str(self.rdn1),
                               str(self.container_rdn1), str(self.container_rdn2),
                               str(self.base_rdn1), str(self.base_rdn2)])
            self.assertEqual(str(dn1), dn_str)

    def test_str(self):
        for DN_class in (DN, EditableDN):
            dn1 = DN_class(self.dn1)
            dn2 = DN_class(self.dn2)
            dn3 = DN_class(self.dn3)

            self.assertEqual(str(dn1), self.str_dn1)
            self.assertIsInstance(str(dn1), str)

            self.assertEqual(str(dn2), self.str_dn2)
            self.assertIsInstance(str(dn2), str)

            self.assertEqual(str(dn3), self.str_dn3)
            self.assertIsInstance(str(dn3), str)

    def test_cmp(self):
        for DN_class in (DN, EditableDN):
            # Equality
            dn1 = DN_class((self.attr1, self.value1))

            self.assertTrue(dn1 == self.dn1)
            self.assertFalse(dn1 != self.dn1)

            self.assertTrue(dn1 == self.str_dn1)
            self.assertFalse(dn1 != self.str_dn1)

            result = cmp(dn1, self.dn1)
            self.assertEqual(result, 0)

            # Make dn1's attr greater
            if DN_class.is_mutable:
                dn1[0].attr = self.attr1 + "1"
            else:
                with self.assertRaises(AttributeError):
                    dn1[0].attr = self.attr1 + "1"
                dn1 = DN_class((self.attr1 + "1", self.value1))

            self.assertFalse(dn1 == self.dn1)
            self.assertTrue(dn1 != self.dn1)

            result = cmp(dn1, self.dn1)
            self.assertEqual(result, 1)

            result = cmp(self.dn1, dn1)
            self.assertEqual(result, -1)

            # Reset dn1's attr, should be equal again
            if DN_class.is_mutable:
                dn1[0].attr = self.attr1
            else:
                with self.assertRaises(AttributeError):
                    dn1[0].attr = self.attr1
                dn1 = DN_class((self.attr1, self.value1))

            result = cmp(dn1, self.dn1)
            self.assertEqual(result, 0)

            # Make dn1's value greater
            # attr will be equal, this tests secondary comparision component
            if DN_class.is_mutable:
                dn1[0].value = self.value1 + "1"
            else:
                with self.assertRaises(AttributeError):
                    dn1[0].value = self.value1 + "1"
                dn1 = DN_class((self.attr1, self.value1 + "1"))

            result = cmp(dn1, self.dn1)
            self.assertEqual(result, 1)

            result = cmp(self.dn1, dn1)
            self.assertEqual(result, -1)

            # Make sure dn's with more rdn's are greater
            result = cmp(self.dn1, self.dn3)
            self.assertEqual(result, -1)
            result = cmp(self.dn3, self.dn1)
            self.assertEqual(result, 1)


            # Test startswith, endswith
            container_dn = DN_class(self.container_dn)
            base_container_dn = DN_class(self.base_container_dn)

            self.assertTrue(base_container_dn.startswith(self.rdn1))
            self.assertTrue(base_container_dn.startswith(self.dn1))
            self.assertTrue(base_container_dn.startswith(self.dn1 + container_dn))
            self.assertFalse(base_container_dn.startswith(self.dn2))
            self.assertFalse(base_container_dn.startswith(self.rdn2))
            self.assertTrue(base_container_dn.startswith((self.dn1)))
            self.assertTrue(base_container_dn.startswith((self.rdn1)))
            self.assertFalse(base_container_dn.startswith((self.rdn2)))
            self.assertTrue(base_container_dn.startswith((self.rdn2, self.rdn1)))
            self.assertTrue(base_container_dn.startswith((self.dn1, self.dn2)))

            self.assertTrue(base_container_dn.endswith(self.base_dn))
            self.assertTrue(base_container_dn.endswith(container_dn + self.base_dn))
            self.assertFalse(base_container_dn.endswith(DN(self.base_rdn1)))
            self.assertTrue(base_container_dn.endswith(DN(self.base_rdn2)))
            self.assertTrue(base_container_dn.endswith((DN(self.base_rdn1), DN(self.base_rdn2))))

            # Test "in" membership
            self.assertTrue(self.container_rdn1 in container_dn)
            self.assertTrue(container_dn in container_dn)
            self.assertFalse(self.base_rdn1 in container_dn)

            self.assertTrue(self.container_rdn1 in base_container_dn)
            self.assertTrue(container_dn in base_container_dn)
            self.assertTrue(container_dn + self.base_dn in
                            base_container_dn)
            self.assertTrue(self.dn1 + container_dn + self.base_dn in
                            base_container_dn)
            self.assertTrue(self.dn1 + container_dn + self.base_dn ==
                            base_container_dn)

            self.assertFalse(self.container_rdn1 in self.base_dn)

    def test_indexing(self):
        for DN_class in (DN, EditableDN):
            dn1 = DN_class(self.dn1)
            dn2 = DN_class(self.dn2)
            dn3 = DN_class(self.dn3)

            self.assertEqual(dn1[0], self.rdn1)
            self.assertEqual(dn1[self.rdn1.attr], self.rdn1.value)
            with self.assertRaises(KeyError):
                dn1['foo']

            self.assertEqual(dn2[0], self.rdn2)
            self.assertEqual(dn2[self.rdn2.attr], self.rdn2.value)
            with self.assertRaises(KeyError):
                dn2['foo']

            self.assertEqual(dn3[0], self.rdn1)
            self.assertEqual(dn3[self.rdn1.attr], self.rdn1.value)
            self.assertEqual(dn3[1], self.rdn2)
            self.assertEqual(dn3[self.rdn2.attr], self.rdn2.value)
            with self.assertRaises(KeyError):
                dn3['foo']

            with self.assertRaises(TypeError):
                dn3[1.0]

    def test_assignments(self):
        for DN_class in (DN, EditableDN):
            dn_low = 0
            dn_high = 6

            rdn_args = make_rdn_args(dn_low, dn_high, 'tuple',
                                     default_rdn_attr_arg, default_rdn_value_arg)
            dn1 = DN_class(*rdn_args)

            rdn_args = make_rdn_args(dn_low, dn_high, 'list',
                                     default_rdn_attr_arg, default_rdn_value_arg)
            dn2 = DN_class(*rdn_args)

            rdn_args = make_rdn_args(dn_low, dn_high, 'RDN',
                                     default_rdn_attr_arg, default_rdn_value_arg)
            dn3 = DN_class(*rdn_args)

            self.assertEqual(dn1, dn2)
            self.assertEqual(dn1, dn3)

            for i in range(dn_low, dn_high):
                attr = default_rdn_attr_arg(i)
                value = default_rdn_value_arg(i)

                self.assertEqual(dn1[i].attr, attr)
                self.assertEqual(dn1[i].value, value)
                self.assertEqual(dn1[attr], value)
                self.assertExpectedClass(DN_class, dn1, 'self')
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')

                self.assertEqual(dn2[i].attr, attr)
                self.assertEqual(dn2[i].value, value)
                self.assertEqual(dn2[attr], value)
                self.assertExpectedClass(DN_class, dn2, 'self')
                self.assertExpectedClass(DN_class, dn2[i], 'RDN')
                for j in range(0, len(dn2[i])):
                    self.assertExpectedClass(DN_class, dn2[i][j], 'AVA')

                self.assertEqual(dn3[i].attr, attr)
                self.assertEqual(dn3[i].value, value)
                self.assertEqual(dn3[attr], value)
                self.assertExpectedClass(DN_class, dn3, 'self')
                self.assertExpectedClass(DN_class, dn3[i], 'RDN')
                for j in range(0, len(dn3[i])):
                    self.assertExpectedClass(DN_class, dn3[i][j], 'AVA')


            for i in range(dn_low, dn_high):
                if i % 2:
                    orig_attr = default_rdn_attr_arg(i)
                    attr = alt_rdn_attr_arg(i)
                    value = alt_rdn_value_arg(i)

                    if DN_class.is_mutable:
                        dn1[i] = attr, value
                    else:
                        with self.assertRaises(TypeError):
                            dn1[i] = attr, value

                    if DN_class.is_mutable:
                        dn2[orig_attr] = (attr, value)
                    else:
                        with self.assertRaises(TypeError):
                            dn2[orig_attr] = (attr, value)

                    if DN_class.is_mutable:
                        dn3[i] = RDN((attr, value))
                    else:
                        with self.assertRaises(TypeError):
                            dn3[i] = RDN((attr, value))

            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')

            self.assertExpectedClass(DN_class, dn2, 'self')
            for i in range(0, len(dn2)):
                self.assertExpectedClass(DN_class, dn2[i], 'RDN')
                for j in range(0, len(dn2[i])):
                    self.assertExpectedClass(DN_class, dn2[i][j], 'AVA')

            self.assertExpectedClass(DN_class, dn3, 'self')
            for i in range(0, len(dn3)):
                self.assertExpectedClass(DN_class, dn3[i], 'RDN')
                for j in range(0, len(dn3[i])):
                    self.assertExpectedClass(DN_class, dn3[i][j], 'AVA')


            if DN_class.is_mutable:
                self.assertEqual(dn1, dn2)
                self.assertEqual(dn1, dn3)

                for i in range(dn_low, dn_high):
                    if i % 2:
                        attr = alt_rdn_attr_arg(i)
                        value = alt_rdn_value_arg(i)
                    else:
                        attr = default_rdn_attr_arg(i)
                        value = default_rdn_value_arg(i)
                    self.assertEqual(dn1[i].attr, attr)
                    self.assertEqual(dn1[i].value, value)
                    self.assertEqual(dn1[attr], value)

            # Slices
            slice_low = 2
            slice_high = 4
            slice_interval = range(slice_low, slice_high)

            # Slices
            # Assign via tuple
            rdn_args = make_rdn_args(dn_low, dn_high, 'tuple',
                                     default_rdn_attr_arg, default_rdn_value_arg)
            dn = DN_class(*rdn_args)

            dn_slice = make_rdn_args(slice_low, slice_high, 'tuple',
                                     alt_rdn_attr_arg, alt_rdn_value_arg)

            if DN_class.is_mutable:
                dn[slice_low:slice_high] = dn_slice
                for i in range(dn_low, dn_high):
                    if i in slice_interval:
                        attr = alt_rdn_attr_arg(i)
                        value = alt_rdn_value_arg(i)
                    else:
                        attr = default_rdn_attr_arg(i)
                        value = default_rdn_value_arg(i)
                    self.assertEqual(dn[i].attr, attr)
                    self.assertEqual(dn[i].value, value)
                    self.assertEqual(dn[attr], value)

                query_slice = dn[slice_low:slice_high]
                for i, query_rdn in enumerate(query_slice):
                    slice_rdn = RDN(dn_slice[i])
                    self.assertEqual(slice_rdn, query_rdn)
            else:
                with self.assertRaises(TypeError):
                    dn[slice_low:slice_high] = dn_slice


            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            # insert
            dn = DN_class(self.rdn2)

            if DN_class.is_mutable:
                dn.insert(0, self.rdn1)
                self.assertEqual(dn, self.dn3)
            else:
                with self.assertRaises(AttributeError):
                    dn.insert(0, self.rdn1)

            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')
            dn = DN_class(self.rdn1)

            if DN_class.is_mutable:
                dn.insert(1, (self.attr2, self.value2))
                self.assertEqual(dn, self.dn3)
            else:
                with self.assertRaises(AttributeError):
                    dn.insert(1, (self.attr2, self.value2))

            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            # Slices
            # Assign via RDN
            rdn_args = make_rdn_args(dn_low, dn_high, 'tuple',
                                     default_rdn_attr_arg, default_rdn_value_arg)
            dn = DN_class(*rdn_args)

            dn_slice = make_rdn_args(slice_low, slice_high, 'RDN',
                                     alt_rdn_attr_arg, alt_rdn_value_arg)

            if DN_class.is_mutable:
                dn[slice_low:slice_high] = dn_slice
                for i in range(dn_low, dn_high):
                    if i in slice_interval:
                        attr = alt_rdn_attr_arg(i)
                        value = alt_rdn_value_arg(i)
                    else:
                        attr = default_rdn_attr_arg(i)
                        value = default_rdn_value_arg(i)
                    self.assertEqual(dn[i].value, value)
                    self.assertEqual(dn[attr], value)

                query_slice = dn[slice_low:slice_high]
                for i, query_rdn in enumerate(query_slice):
                    slice_rdn = dn_slice[i]
                    self.assertEqual(slice_rdn, query_rdn)
            else:
                with self.assertRaises(TypeError):
                    dn[slice_low:slice_high] = dn_slice

            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

    def test_iter(self):
        for DN_class in (DN, EditableDN):
            dn1 = DN_class(self.dn1)
            dn2 = DN_class(self.dn2)
            dn3 = DN_class(self.dn3)

            self.assertEqual(len(dn1), 1)
            self.assertEqual(dn1[:], [self.rdn1])
            for i, ava in enumerate(dn1):
                if i == 0:
                    self.assertEqual(ava, self.rdn1)
                else:
                    self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn1)))

            self.assertEqual(len(dn2), 1)
            self.assertEqual(dn2[:], [self.rdn2])
            for i, ava in enumerate(dn2):
                if i == 0:
                    self.assertEqual(ava, self.rdn2)
                else:
                    self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn2)))

            self.assertEqual(len(dn3), 2)
            self.assertEqual(dn3[:], [self.rdn1, self.rdn2])
            for i, ava in enumerate(dn3):
                if i == 0:
                    self.assertEqual(ava, self.rdn1)
                elif i == 1:
                    self.assertEqual(ava, self.rdn2)
                else:
                    self.fail("got iteration index %d, but len=%d" % (i, len(dn3)))


    def test_concat(self):
        for DN_class in (DN, EditableDN):
            dn1 = DN_class((self.attr1, self.value1))
            dn2 = DN_class([self.attr2, self.value2])

            # in-place addtion

            # Note: If __iadd__ is not available Python will emulate += by
            # replacing the lhs object with the result of __add__ (if available).
            # Thus += works for both immutable and mutable RDN,DN object, the only
            # difference is an immutable without __iadd__ will have a different object
            # on the lhs after the operator evaluates.

            dn1 += dn2
            self.assertEqual(dn1, self.dn3)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')


            dn1 = DN_class((self.attr1, self.value1))
            dn1 += self.rdn2
            self.assertEqual(dn1, self.dn3)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')


            dn1 = DN_class((self.attr1, self.value1))
            dn1 += self.dn2
            self.assertEqual(dn1, self.dn3)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')


            dn1 = DN_class((self.attr1, self.value1))
            dn1 += self.str_dn2
            self.assertEqual(dn1, self.dn3)
            self.assertExpectedClass(DN_class, dn1, 'self')
            for i in range(0, len(dn1)):
                self.assertExpectedClass(DN_class, dn1[i], 'RDN')
                for j in range(0, len(dn1[i])):
                    self.assertExpectedClass(DN_class, dn1[i][j], 'AVA')


            # concatenation
            dn1 = DN_class((self.attr1, self.value1))
            dn3 = dn1 + dn2
            self.assertEqual(dn3, self.dn3)
            self.assertExpectedClass(DN_class, dn3, 'self')
            for i in range(0, len(dn3)):
                self.assertExpectedClass(DN_class, dn3[i], 'RDN')
                for j in range(0, len(dn3[i])):
                    self.assertExpectedClass(DN_class, dn3[i][j], 'AVA')


            dn1 = DN_class((self.attr1, self.value1))
            dn3 = dn1 + self.rdn2
            self.assertEqual(dn3, self.dn3)
            self.assertExpectedClass(DN_class, dn3, 'self')
            for i in range(0, len(dn3)):
                self.assertExpectedClass(DN_class, dn3[i], 'RDN')
                for j in range(0, len(dn3[i])):
                    self.assertExpectedClass(DN_class, dn3[i][j], 'AVA')

            dn3 = dn1 + self.str_rdn2
            self.assertEqual(dn3, self.dn3)
            self.assertExpectedClass(DN_class, dn3, 'self')
            for i in range(0, len(dn3)):
                self.assertExpectedClass(DN_class, dn3[i], 'RDN')
                self.assertExpectedClass(DN_class, dn3[i][0], 'AVA')

            dn3 = dn1 + self.str_dn2
            self.assertEqual(dn3, self.dn3)
            self.assertExpectedClass(DN_class, dn3, 'self')
            self.assertExpectedClass(DN_class, dn3, 'self')
            for i in range(0, len(dn3)):
                self.assertExpectedClass(DN_class, dn3[i], 'RDN')
                for j in range(0, len(dn3[i])):
                    self.assertExpectedClass(DN_class, dn3[i][j], 'AVA')

            dn3 = dn1 + self.dn2
            self.assertEqual(dn3, self.dn3)
            self.assertExpectedClass(DN_class, dn3, 'self')
            self.assertExpectedClass(DN_class, dn3, 'self')
            for i in range(0, len(dn3)):
                self.assertExpectedClass(DN_class, dn3[i], 'RDN')
                for j in range(0, len(dn3[i])):
                    self.assertExpectedClass(DN_class, dn3[i][j], 'AVA')

    def test_find(self):
        for DN_class in (DN, EditableDN):
            #        -10 -9  -8     -7  -6  -5  -4     -3  -2  -1
            dn = DN_class('t=0,t=1,cn=bob,t=3,t=4,t=5,cn=bob,t=7,t=8,t=9')
            pat = DN_class('cn=bob')

            # forward
            self.assertEqual(dn.find(pat),          2)
            self.assertEqual(dn.find(pat,  1),      2)
            self.assertEqual(dn.find(pat,  1,  3),  2)
            self.assertEqual(dn.find(pat,  2,  3),  2)
            self.assertEqual(dn.find(pat,  6),      6)

            self.assertEqual(dn.find(pat,  7),     -1)
            self.assertEqual(dn.find(pat,  1,  2), -1)

            with self.assertRaises(ValueError):
                self.assertEqual(dn.index(pat,  7),     -1)
            with self.assertRaises(ValueError):
                self.assertEqual(dn.index(pat,  1,  2), -1)

            # reverse
            self.assertEqual(dn.rfind(pat),          6)
            self.assertEqual(dn.rfind(pat, -4),      6)
            self.assertEqual(dn.rfind(pat,  6),      6)
            self.assertEqual(dn.rfind(pat,  6,  8),  6)
            self.assertEqual(dn.rfind(pat,  6,  8),  6)
            self.assertEqual(dn.rfind(pat, -8),      6)
            self.assertEqual(dn.rfind(pat, -8, -4),  6)
            self.assertEqual(dn.rfind(pat, -8, -5),  2)

            self.assertEqual(dn.rfind(pat,  7),     -1)
            self.assertEqual(dn.rfind(pat, -3),     -1)

            with self.assertRaises(ValueError):
                self.assertEqual(dn.rindex(pat,  7),     -1)
            with self.assertRaises(ValueError):
                self.assertEqual(dn.rindex(pat, -3),     -1)


    def test_replace(self):
        for DN_class in (DN, EditableDN):
            dn = DN_class('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=8,t=9')
            pat = DN('cn=bob')
            replacement = DN('cn=bob')

            if DN_class.is_mutable:
                n_replaced = dn.replace(pat, replacement)
                self.assertEqual(n_replaced, 0)
            else:
                with self.assertRaises(AttributeError):
                    n_replaced = dn.replace(pat, replacement)
            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            pat = DN('t=2')
            if DN_class.is_mutable:
                expected_dn = DN('t=0,t=1,cn=bob,t=3,t=4,t=5,t=6,t=7,t=8,t=9')
                n_replaced = dn.replace(pat, replacement)
                self.assertEqual(n_replaced, 1)
                self.assertEqual(dn, expected_dn)
            else:
                with self.assertRaises(AttributeError):
                    n_replaced = dn.replace(pat, replacement)
            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            dn = DN_class('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=2,t=9')
            if DN_class.is_mutable:
                expected_dn = DN('t=0,t=1,cn=bob,t=3,t=4,t=5,t=6,t=7,t=2,t=9')
                n_replaced = dn.replace(pat, replacement, 1)
                self.assertEqual(n_replaced, 1)
                self.assertEqual(dn, expected_dn)
            else:
                with self.assertRaises(AttributeError):
                    n_replaced = dn.replace(pat, replacement, 1)
            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            dn = DN_class('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=2,t=9')
            if DN_class.is_mutable:
                expected_dn = DN('t=0,t=1,cn=bob,t=3,t=4,t=5,t=6,t=7,t=2,t=9')
                n_replaced = dn.replace(pat, replacement, 1)
                self.assertEqual(n_replaced, 1)
                self.assertEqual(dn, expected_dn)
            else:
                with self.assertRaises(AttributeError):
                    n_replaced = dn.replace(pat, replacement, 1)
            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            replacement = DN('cn=bob,ou=people')

            dn = DN_class('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=2,t=9')
            if DN_class.is_mutable:
                expected_dn = DN('t=0,t=1,cn=bob,ou=people,t=3,t=4,t=5,t=6,t=7,t=2,t=9')
                n_replaced = dn.replace(pat, replacement, 1)
                self.assertEqual(n_replaced, 1)
                self.assertEqual(dn, expected_dn)
            else:
                with self.assertRaises(AttributeError):
                    n_replaced = dn.replace(pat, replacement, 1)
            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            dn = DN_class('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=2,t=9')
            if DN_class.is_mutable:
                expected_dn = DN('t=0,t=1,cn=bob,ou=people,t=3,t=4,t=5,t=6,t=7,cn=bob,ou=people,t=9')
                n_replaced = dn.replace(pat, replacement)
                self.assertEqual(n_replaced, 2)
                self.assertEqual(dn, expected_dn)
            else:
                with self.assertRaises(AttributeError):
                    n_replaced = dn.replace(pat, replacement)
            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            pat = DN('t=3,t=4')
            replacement = DN('cn=bob')
            dn = DN_class('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=8,t=9')
            if DN_class.is_mutable:
                expected_dn = DN('t=0,t=1,t=2,cn=bob,t=5,t=6,t=7,t=8,t=9')
                n_replaced = dn.replace(pat, replacement)
                self.assertEqual(n_replaced, 1)
                self.assertEqual(dn, expected_dn)
            else:
                with self.assertRaises(AttributeError):
                    n_replaced = dn.replace(pat, replacement)
            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

            pat = DN('t=3,t=4')
            replacement = DN('cn=bob,ou=people')
            dn = DN_class('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=8,t=9')
            if DN_class.is_mutable:
                expected_dn = DN('t=0,t=1,t=2,cn=bob,ou=people,t=5,t=6,t=7,t=8,t=9')
                n_replaced = dn.replace(pat, replacement)
                self.assertEqual(n_replaced, 1)
                self.assertEqual(dn, expected_dn)
            else:
                with self.assertRaises(AttributeError):
                    n_replaced = dn.replace(pat, replacement)
            self.assertExpectedClass(DN_class, dn, 'self')
            for i in range(0, len(dn)):
                self.assertExpectedClass(DN_class, dn[i], 'RDN')
                for j in range(0, len(dn[i])):
                    self.assertExpectedClass(DN_class, dn[i][j], 'AVA')

    def test_hashing(self):
        # create DN's that are equal but differ in case
        immutable_dn1 = DN((self.attr1.lower(), self.value1.upper()))
        immutable_dn2 = DN((self.attr1.upper(), self.value1.lower()))

        mutable_dn1   = EditableDN((self.attr1.lower(), self.value1.upper()))
        mutable_dn2   = EditableDN((self.attr1.upper(), self.value1.lower()))

        # Immutable DN's that are equal should hash to the same value.
        # Mutable DN's should not be hashable.

        self.assertEqual(immutable_dn1, immutable_dn2)
        self.assertEqual(immutable_dn1, mutable_dn1)
        self.assertEqual(immutable_dn1, mutable_dn2)
        self.assertEqual(mutable_dn1, immutable_dn2)

        # Good, everyone's equal, now verify their hash values

        self.assertEqual(hash(immutable_dn1), hash(immutable_dn2))
        with self.assertRaises(TypeError):
            hash(mutable_dn1)
        with self.assertRaises(TypeError):
            hash(mutable_dn2)

        # Different immutable DN objects with the same value should
        # map to 1 common key and 1 member in a set. The key and
        # member are based on the object's value.
        #
        # Mutable DN objects should be unhashable.

        for DN_class in (DN, EditableDN):
            dn1_a = DN_class(self.dn1)
            dn1_b = DN_class(self.dn1)

            dn2_a = DN_class(self.dn2)
            dn2_b = DN_class(self.dn2)

            dn3_a = DN_class(self.dn3)
            dn3_b = DN_class(self.dn3)

            self.assertEqual(dn1_a, dn1_b)
            self.assertEqual(dn2_a, dn2_b)
            self.assertEqual(dn3_a, dn3_b)

            d = dict()
            s = set()

            if DN_class.is_mutable:
                with self.assertRaises(TypeError):
                    d[dn1_a] = str(dn1_a)
                with self.assertRaises(TypeError):
                    d[dn1_b] = str(dn1_b)
                with self.assertRaises(TypeError):
                    d[dn2_a] = str(dn2_a)
                with self.assertRaises(TypeError):
                    d[dn2_b] = str(dn2_b)

                with self.assertRaises(TypeError):
                    s.add(dn1_a)
                with self.assertRaises(TypeError):
                    s.add(dn1_b)
                with self.assertRaises(TypeError):
                    s.add(dn2_a)
                with self.assertRaises(TypeError):
                    s.add(dn2_b)
            else:
                d[dn1_a] = str(dn1_a)
                d[dn1_b] = str(dn1_b)
                d[dn2_a] = str(dn2_a)
                d[dn2_b] = str(dn2_b)

                s.add(dn1_a)
                s.add(dn1_b)
                s.add(dn2_a)
                s.add(dn2_b)

                self.assertEqual(len(d), 2)
                self.assertEqual(len(s), 2)
                self.assertEqual(sorted(d.keys()), sorted([dn1_a, dn2_a]))
                self.assertEqual(sorted(s), sorted([dn1_a, dn2_a]))

                self.assertTrue(dn1_a in d)
                self.assertTrue(dn1_b in d)
                self.assertTrue(dn2_a in d)
                self.assertTrue(dn2_b in d)
                self.assertFalse(dn3_a in d)
                self.assertFalse(dn3_b in d)

                self.assertTrue(d.has_key(dn1_a))
                self.assertTrue(d.has_key(dn1_b))
                self.assertTrue(d.has_key(dn2_a))
                self.assertTrue(d.has_key(dn2_b))
                self.assertFalse(d.has_key(dn3_a))
                self.assertFalse(d.has_key(dn3_b))

                self.assertTrue(dn1_a in s)
                self.assertTrue(dn1_b in s)
                self.assertTrue(dn2_a in s)
                self.assertTrue(dn2_b in s)
                self.assertFalse(dn3_a in s)
                self.assertFalse(dn3_b in s)

    def test_coerce(self):
        # Coerce an immutable to a mutable
        immutable_dn3 = DN(self.dn3)
        mutable_dn3 = EditableDN(immutable_dn3)
        self.assertEqual(mutable_dn3, self.dn3)
        self.assertEqual(mutable_dn3, immutable_dn3)

        # Coerce a mutable to an immutable
        mutable_dn3 = EditableDN(self.dn3)
        immutable_dn3 = DN(mutable_dn3)
        self.assertEqual(immutable_dn3, self.dn3)
        self.assertEqual(immutable_dn3, mutable_dn3)

class TestEscapes(unittest.TestCase):
    def setUp(self):
        self.privilege = 'R,W privilege'
        self.dn_str_hex_escape = 'cn=R\\2cW privilege,cn=privileges,cn=pbac,dc=idm,dc=lab,dc=bos,dc=redhat,dc=com'
        self.dn_str_backslash_escape = 'cn=R\\,W privilege,cn=privileges,cn=pbac,dc=idm,dc=lab,dc=bos,dc=redhat,dc=com'

    def test_escape(self):
        for DN_class in (DN, EditableDN):
            dn = DN_class(self.dn_str_hex_escape)
            self.assertEqual(dn['cn'], self.privilege)
            self.assertEqual(dn[0].value, self.privilege)

            dn = DN_class(self.dn_str_backslash_escape)
            self.assertEqual(dn['cn'], self.privilege)
            self.assertEqual(dn[0].value, self.privilege)

class TestInternationalization(unittest.TestCase):
    def setUp(self):
        # Hello in Arabic
        self.arabic_hello_utf8 = '\xd9\x85\xd9\x83\xd9\x8a\xd9\x84' + \
                                 '\xd8\xb9\x20\xd9\x85\xd8\xa7\xd9' + \
                                 '\x84\xd9\x91\xd8\xb3\xd9\x84\xd8\xa7'

        self.arabic_hello_unicode = self.arabic_hello_utf8.decode('utf-8')

    def test_i18n(self):
        self.assertEqual(self.arabic_hello_utf8,
                         self.arabic_hello_unicode.encode('utf-8'))

        # AVA's
        # test attr i18n
        for AVA_class in (AVA, EditableAVA):
            ava1 = AVA_class(self.arabic_hello_unicode, 'foo')
            self.assertIsInstance(ava1.attr,  unicode)
            self.assertIsInstance(ava1.value, unicode)
            self.assertEqual(ava1.attr, self.arabic_hello_unicode)
            self.assertEqual(str(ava1), self.arabic_hello_utf8+'=foo')

            ava1 = AVA_class(self.arabic_hello_utf8, 'foo')
            self.assertIsInstance(ava1.attr,  unicode)
            self.assertIsInstance(ava1.value, unicode)
            self.assertEqual(ava1.attr, self.arabic_hello_unicode)
            self.assertEqual(str(ava1), self.arabic_hello_utf8+'=foo')

            # test value i18n
            ava1 = AVA_class('cn', self.arabic_hello_unicode)
            self.assertIsInstance(ava1.attr,  unicode)
            self.assertIsInstance(ava1.value, unicode)
            self.assertEqual(ava1.value, self.arabic_hello_unicode)
            self.assertEqual(str(ava1), 'cn='+self.arabic_hello_utf8)

            ava1 = AVA_class('cn', self.arabic_hello_utf8)
            self.assertIsInstance(ava1.attr,  unicode)
            self.assertIsInstance(ava1.value, unicode)
            self.assertEqual(ava1.value, self.arabic_hello_unicode)
            self.assertEqual(str(ava1), 'cn='+self.arabic_hello_utf8)

        # RDN's
        # test attr i18n
        for RDN_class in (RDN, EditableRDN):
            rdn1 = RDN_class((self.arabic_hello_unicode, 'foo'))
            self.assertIsInstance(rdn1.attr,  unicode)
            self.assertIsInstance(rdn1.value, unicode)
            self.assertEqual(rdn1.attr, self.arabic_hello_unicode)
            self.assertEqual(str(rdn1), self.arabic_hello_utf8+'=foo')

            rdn1 = RDN_class((self.arabic_hello_utf8, 'foo'))
            self.assertIsInstance(rdn1.attr,  unicode)
            self.assertIsInstance(rdn1.value, unicode)
            self.assertEqual(rdn1.attr, self.arabic_hello_unicode)
            self.assertEqual(str(rdn1), self.arabic_hello_utf8+'=foo')

            # test value i18n
            rdn1 = RDN_class(('cn', self.arabic_hello_unicode))
            self.assertIsInstance(rdn1.attr,  unicode)
            self.assertIsInstance(rdn1.value, unicode)
            self.assertEqual(rdn1.value, self.arabic_hello_unicode)
            self.assertEqual(str(rdn1), 'cn='+self.arabic_hello_utf8)

            rdn1 = RDN_class(('cn', self.arabic_hello_utf8))
            self.assertIsInstance(rdn1.attr,  unicode)
            self.assertIsInstance(rdn1.value, unicode)
            self.assertEqual(rdn1.value, self.arabic_hello_unicode)
            self.assertEqual(str(rdn1), 'cn='+self.arabic_hello_utf8)

        # DN's
        # test attr i18n
        for DN_class in (DN, EditableDN):
            dn1 = DN_class((self.arabic_hello_unicode, 'foo'))
            self.assertIsInstance(dn1[0].attr,  unicode)
            self.assertIsInstance(dn1[0].value, unicode)
            self.assertEqual(dn1[0].attr, self.arabic_hello_unicode)
            self.assertEqual(str(dn1), self.arabic_hello_utf8+'=foo')

            dn1 = DN_class((self.arabic_hello_utf8, 'foo'))
            self.assertIsInstance(dn1[0].attr,  unicode)
            self.assertIsInstance(dn1[0].value, unicode)
            self.assertEqual(dn1[0].attr, self.arabic_hello_unicode)
            self.assertEqual(str(dn1), self.arabic_hello_utf8+'=foo')

            # test value i18n
            dn1 = DN_class(('cn', self.arabic_hello_unicode))
            self.assertIsInstance(dn1[0].attr,  unicode)
            self.assertIsInstance(dn1[0].value, unicode)
            self.assertEqual(dn1[0].value, self.arabic_hello_unicode)
            self.assertEqual(str(dn1), 'cn='+self.arabic_hello_utf8)

            dn1 = DN_class(('cn', self.arabic_hello_utf8))
            self.assertIsInstance(dn1[0].attr,  unicode)
            self.assertIsInstance(dn1[0].value, unicode)
            self.assertEqual(dn1[0].value, self.arabic_hello_unicode)
            self.assertEqual(str(dn1), 'cn='+self.arabic_hello_utf8)

if __name__ == '__main__':
    unittest.main()
