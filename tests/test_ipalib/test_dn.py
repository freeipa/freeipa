#!/usr/bin/python

import unittest
from ipalib.dn import AVA, RDN, DN

def make_rdn_args(low, high, kind, attr=None, value=None):
    result=[]
    for i in range(low, high):
        if attr is None:
            new_attr = 'a%d' % i
        elif callable(attr):
            new_attr = attr(i)
        else:
            new_attr = attr

        if value is None:
            new_value = str(i)
        elif callable(value):
            new_value = value(i)
        else:
            new_value = value

        if kind == 'sequence':
            result.append(new_attr)
            result.append(new_value)
        elif kind == 'tuple':
            result.append((new_attr, new_value))
        elif kind == 'list':
            result.append([new_attr, new_value])
        elif kind == 'RDN':
            result.append(RDN(new_attr, new_value))
        else:
            raise ValueError("Unknown kind = %s" % kind)

    return result

class TestAVA(unittest.TestCase):
    def setUp(self):
        self.attr1    = 'cn'
        self.value1   = 'Bob'
        self.str_ava1 = '%s=%s' % (self.attr1, self.value1)
        self.ava1     = AVA(self.attr1, self.value1)

    def test_create(self):
        # Create with attr,value pair
        ava1 = AVA(self.attr1, self.value1)
        self.assertEqual(ava1, self.ava1)

        # Create with "attr=value" string
        ava1 = AVA(self.str_ava1)
        self.assertEqual(ava1, self.ava1)

        # Create with tuple (attr, value)
        ava1 = AVA((self.attr1, self.value1))
        self.assertEqual(ava1, self.ava1)

        # Create with list [attr, value]
        ava1 = AVA([self.attr1, self.value1])
        self.assertEqual(ava1, self.ava1)

        # Create with no args should fail
        with self.assertRaises(TypeError):
            AVA()

        # Create with more than 2 args should fail
        with self.assertRaises(TypeError):
            AVA(self.attr1, self.value1, self.attr1)

        # Create with 1 arg which is not string should fail
        with self.assertRaises(TypeError):
            AVA(1)

        # Create with malformed AVA string should fail
        with self.assertRaises(ValueError):
            AVA("cn")

        # Create with non-string parameters, should fail
        with self.assertRaises(TypeError):
            AVA(1, self.value1)

        with self.assertRaises(TypeError):
            AVA(self.attr1, 1)

        with self.assertRaises(TypeError):
            AVA((1, self.value1))

        with self.assertRaises(TypeError):
            AVA((self.attr1, 1))

    def test_encoding(self):
        # Create with attr,value pair
        ava1 = AVA(self.attr1, self.value1)
        self.assertEqual(ava1, self.ava1)
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)

        ava1 = AVA(unicode(self.attr1), self.value1)
        self.assertEqual(ava1, self.ava1)
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)

        ava1 = AVA(self.attr1, unicode(self.value1))
        self.assertEqual(ava1, self.ava1)
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)

        # Create with "attr=value" string
        ava1 = AVA(self.str_ava1)
        self.assertEqual(ava1, self.ava1)
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)

        ava1 = AVA(unicode(self.ava1))
        self.assertEqual(ava1, self.ava1)
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)

        # Create with tuple (attr, value)
        ava1 = AVA((unicode(self.attr1), self.value1))
        self.assertEqual(ava1, self.ava1)
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)

        ava1 = AVA((self.attr1, unicode(self.value1)))
        self.assertEqual(ava1, self.ava1)
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)

    def test_indexing(self):
        self.assertEqual(self.ava1[self.attr1], self.value1)

        with self.assertRaises(KeyError):
            self.ava1['foo']

        with self.assertRaises(TypeError):
            self.ava1[0]

    def test_properties(self):
        self.assertEqual(self.ava1.attr, self.attr1)
        self.assertEqual(self.ava1.value, self.value1)

    def test_str(self):
        self.assertEqual(str(self.ava1), self.str_ava1)
        self.assertIsInstance(str(self.ava1), str)

    def test_cmp(self):
        # Equality
        ava1 = AVA(self.attr1, self.value1)

        self.assertTrue(ava1 == self.ava1)
        self.assertFalse(ava1 != self.ava1)

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 0)

        # Make ava1's attr greater
        ava1.attr = self.attr1 + "1"

        self.assertFalse(ava1 == self.ava1)
        self.assertTrue(ava1 != self.ava1)

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 1)

        result = cmp(self.ava1, ava1)
        self.assertEqual(result, -1)

        # Reset ava1's attr, should be equal again
        ava1.attr = self.attr1

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 0)

        # Make ava1's value greater
        # attr will be equal, this tests secondary comparision component
        ava1.value = self.value1 + "1"

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 1)

        result = cmp(self.ava1, ava1)
        self.assertEqual(result, -1)

class TestRDN(unittest.TestCase):
    def setUp(self):
        # ava1 must sort before ava2
        self.attr1    = 'cn'
        self.value1   = 'Bob'
        self.str_ava1 = '%s=%s' % (self.attr1, self.value1)
        self.ava1     = AVA(self.attr1, self.value1)

        self.str_rdn1 = '%s=%s' % (self.attr1, self.value1)
        self.rdn1 = RDN(self.attr1, self.value1)

        self.attr2    = 'ou'
        self.value2   = 'people'
        self.str_ava2 = '%s=%s' % (self.attr2, self.value2)
        self.ava2     = AVA(self.attr2, self.value2)

        self.str_rdn2 = '%s=%s' % (self.attr2, self.value2)
        self.rdn2     = RDN(self.attr2, self.value2)

        self.str_ava3 = '%s=%s+%s=%s' % (self.attr1, self.value1, self.attr2, self.value2)

        self.str_rdn3 = '%s=%s+%s=%s' % (self.attr1, self.value1, self.attr2, self.value2)
        self.rdn3 = RDN(self.ava1, self.ava2)

    def test_create(self):
        # Create with single attr,value pair
        rdn1 = RDN(self.attr1, self.value1)
        self.assertEqual(len(rdn1), 1)
        self.assertEqual(rdn1, self.rdn1)
        self.assertIsInstance(rdn1[0], AVA)
        self.assertEqual(rdn1[0], self.ava1)

        # Create with single attr,value pair passed as a tuple
        rdn1 = RDN((self.attr1, self.value1))
        self.assertEqual(len(rdn1), 1)
        self.assertEqual(rdn1, self.rdn1)
        self.assertIsInstance(rdn1[0], AVA)
        self.assertEqual(rdn1[0], self.ava1)

        # Create with multiple attr,value pairs
        rdn3 = RDN(self.attr1, self.value1, self.attr2, self.value2)
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertIsInstance(rdn3[0], AVA)
        self.assertEqual(rdn3[0], self.ava1)
        self.assertIsInstance(rdn3[1], AVA)
        self.assertEqual(rdn3[1], self.ava2)

        # Create with multiple attr,value pairs passed as lists
        rdn3 = RDN([self.attr1, self.value1], [self.attr2, self.value2])
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertIsInstance(rdn3[0], AVA)
        self.assertEqual(rdn3[0], self.ava1)
        self.assertIsInstance(rdn3[1], AVA)
        self.assertEqual(rdn3[1], self.ava2)

        # Create with multiple attr,value pairs but reverse
        # constructor parameter ordering. RDN canonical ordering
        # should remain the same
        rdn3 = RDN(self.attr2, self.value2, self.attr1, self.value1)
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertIsInstance(rdn3[0], AVA)
        self.assertEqual(rdn3[0], self.ava1)
        self.assertIsInstance(rdn3[1], AVA)
        self.assertEqual(rdn3[1], self.ava2)

        # Create with single AVA object
        rdn1 = RDN(self.ava1)
        self.assertEqual(len(rdn1), 1)
        self.assertEqual(rdn1, self.rdn1)
        self.assertIsInstance(rdn1[0], AVA)
        self.assertEqual(rdn1[0], self.ava1)

        # Create with multiple AVA objects
        rdn3 = RDN(self.ava1, self.ava2)
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertIsInstance(rdn3[0], AVA)
        self.assertEqual(rdn3[0], self.ava1)
        self.assertIsInstance(rdn3[1], AVA)
        self.assertEqual(rdn3[1], self.ava2)


        # Create with multiple AVA objects but reverse constructor
        # parameter ordering.  RDN canonical ordering should remain
        # the same
        rdn3 = RDN(self.ava2, self.ava1)
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertIsInstance(rdn3[0], AVA)
        self.assertEqual(rdn3[0], self.ava1)
        self.assertIsInstance(rdn3[1], AVA)
        self.assertEqual(rdn3[1], self.ava2)

        # Create with single string with 1 AVA
        rdn1 = RDN(self.str_rdn1)
        self.assertEqual(len(rdn1), 1)
        self.assertEqual(rdn1, self.rdn1)
        self.assertIsInstance(rdn1[0], AVA)
        self.assertEqual(rdn1[0], self.ava1)

        # Create with single string with 2 AVA's
        rdn3 = RDN(self.str_rdn3)
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertIsInstance(rdn3[0], AVA)
        self.assertEqual(rdn3[0], self.ava1)
        self.assertIsInstance(rdn3[1], AVA)
        self.assertEqual(rdn3[1], self.ava2)

    def test_properties(self):
        self.assertEqual(self.rdn1.attr, self.attr1)
        self.assertIsInstance(self.rdn1.attr, unicode)

        self.assertEqual(self.rdn1.value, self.value1)
        self.assertIsInstance(self.rdn1.value, unicode)

        self.assertEqual(self.rdn2.attr, self.attr2)
        self.assertIsInstance(self.rdn2.attr, unicode)

        self.assertEqual(self.rdn2.value, self.value2)
        self.assertIsInstance(self.rdn2.value, unicode)

        self.assertEqual(self.rdn3.attr, self.attr1)
        self.assertIsInstance(self.rdn3.attr, unicode)

        self.assertEqual(self.rdn3.value, self.value1)
        self.assertIsInstance(self.rdn3.value, unicode)

    def test_str(self):
        self.assertEqual(str(self.rdn1), self.str_rdn1)
        self.assertIsInstance(str(self.rdn1), str)

        self.assertEqual(str(self.rdn2), self.str_rdn2)
        self.assertIsInstance(str(self.rdn2), str)

        self.assertEqual(str(self.rdn3), self.str_rdn3)
        self.assertIsInstance(str(self.rdn3), str)

    def test_cmp(self):
        # Equality
        rdn1 = RDN(self.attr1, self.value1)

        self.assertTrue(rdn1 == self.rdn1)
        self.assertFalse(rdn1 != self.rdn1)

        result = cmp(rdn1, self.rdn1)
        self.assertEqual(result, 0)

        # Make rdn1's attr greater
        rdn1.attr = self.attr1 + "1"

        self.assertFalse(rdn1 == self.rdn1)
        self.assertTrue(rdn1 != self.rdn1)

        result = cmp(rdn1, self.rdn1)
        self.assertEqual(result, 1)

        result = cmp(self.rdn1, rdn1)
        self.assertEqual(result, -1)

        # Reset rdn1's attr, should be equal again
        rdn1.attr = self.attr1

        result = cmp(rdn1, self.rdn1)
        self.assertEqual(result, 0)

        # Make rdn1's value greater
        # attr will be equal, this tests secondary comparision component
        rdn1.value = self.value1 + "1"

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
        self.assertEqual(self.rdn1[0], self.ava1)
        self.assertEqual(self.rdn1[self.ava1.attr], self.ava1.value)
        with self.assertRaises(KeyError):
            self.rdn1['foo']

        self.assertEqual(self.rdn2[0], self.ava2)
        self.assertEqual(self.rdn2[self.ava2.attr], self.ava2.value)
        with self.assertRaises(KeyError):
            self.rdn2['foo']

        self.assertEqual(self.rdn3[0], self.ava1)
        self.assertEqual(self.rdn3[self.ava1.attr], self.ava1.value)
        self.assertEqual(self.rdn3[1], self.ava2)
        self.assertEqual(self.rdn3[self.ava2.attr], self.ava2.value)
        with self.assertRaises(KeyError):
            self.rdn3['foo']

        self.assertEqual(self.rdn1.attr, self.attr1)
        self.assertEqual(self.rdn1.value, self.value1)

        with self.assertRaises(TypeError):
            self.rdn3[1.0]

        # Slices
        self.assertEqual(self.rdn3[0:1], [self.ava1])
        self.assertEqual(self.rdn3[:],   [self.ava1, self.ava2])

    def test_assignments(self):
        rdn = RDN(self.attr1, self.value1)
        rdn[0] = self.ava2
        self.assertEqual(rdn, self.rdn2)

        rdn = RDN(self.attr1, self.value1)
        rdn[0] = (self.attr2, self.value2)
        self.assertEqual(rdn, self.rdn2)

        rdn  = RDN(self.attr1, self.value1)
        rdn[self.attr1] = self.str_ava2
        self.assertEqual(rdn[0], self.ava2)

        # Can't assign multiples to single entry
        rdn  = RDN(self.attr1, self.value1)
        with self.assertRaises(TypeError):
            rdn[self.attr1] = self.str_ava3

        rdn  = RDN(self.attr1, self.value1)
        with self.assertRaises(TypeError):
            rdn[self.attr1] = (self.attr1, self.value1, self.attr2, self.value2)

        rdn  = RDN(self.attr1, self.value1)
        with self.assertRaises(TypeError):
            rdn[self.attr1] = [(self.attr1, self.value1), (self.attr2, self.value2)]

        # Slices
        rdn  = RDN(self.attr1, self.value1)
        self.assertEqual(rdn, self.rdn1)
        rdn[0:1] = [self.ava2]
        self.assertEqual(rdn, self.rdn2)

        rdn  = RDN(self.attr1, self.value1)
        self.assertEqual(rdn, self.rdn1)
        rdn[:] = [(self.attr2, self.value2)]
        self.assertEqual(rdn, self.rdn2)

        rdn  = RDN(self.attr1, self.value1)
        self.assertEqual(rdn, self.rdn1)
        rdn[:] = [(self.attr1, self.value1),(self.attr2, self.value2)]
        self.assertEqual(rdn, self.rdn3)

        rdn  = RDN(self.attr1, self.value1)
        self.assertEqual(rdn, self.rdn1)
        rdn[0:1] = [self.attr1, self.value1, self.attr2, self.value2]
        self.assertEqual(rdn, self.rdn3)


    def test_iter(self):
        self.assertEqual(len(self.rdn1), 1)
        self.assertEqual(self.rdn1[:], [self.ava1])
        for i, ava in enumerate(self.rdn1):
            if i == 0:
                self.assertEqual(ava, self.ava1)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn1)))

        self.assertEqual(len(self.rdn2), 1)
        self.assertEqual(self.rdn2[:], [self.ava2])
        for i, ava in enumerate(self.rdn2):
            if i == 0:
                self.assertEqual(ava, self.ava2)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn2)))

        self.assertEqual(len(self.rdn3), 2)
        self.assertEqual(self.rdn3[:], [self.ava1, self.ava2])
        for i, ava in enumerate(self.rdn3):
            if i == 0:
                self.assertEqual(ava, self.ava1)
            elif i == 1:
                self.assertEqual(ava, self.ava2)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn3)))


    def test_concat(self):
        rdn1 = RDN(self.attr1, self.value1)
        rdn2 = RDN(self.attr2, self.value2)

        # in-place addtion
        rdn1 += rdn2
        self.assertEqual(rdn1, self.rdn3)

        rdn1 = RDN(self.attr1, self.value1)
        rdn1 += self.ava2
        self.assertEqual(rdn1, self.rdn3)

        rdn1 = RDN(self.attr1, self.value1)
        rdn1 += self.str_ava2
        self.assertEqual(rdn1, self.rdn3)

        # concatenation
        rdn1 = RDN(self.attr1, self.value1)
        rdn3 = rdn1 + rdn2
        self.assertEqual(rdn3, self.rdn3)

        rdn3 = rdn1 + self.ava2
        self.assertEqual(rdn3, self.rdn3)

        rdn3 = rdn1 + self.str_ava2
        self.assertEqual(rdn3, self.rdn3)


class TestDN(unittest.TestCase):
    def setUp(self):
        # ava1 must sort before ava2
        self.attr1    = 'cn'
        self.value1   = 'Bob'
        self.str_ava1 = '%s=%s' % (self.attr1, self.value1)
        self.ava1     = AVA(self.attr1, self.value1)

        self.str_rdn1 = '%s=%s' % (self.attr1, self.value1)
        self.rdn1     = RDN(self.attr1, self.value1)

        self.attr2    = 'ou'
        self.value2   = 'people'
        self.str_ava2 = '%s=%s' % (self.attr2, self.value2)
        self.ava2     = AVA(self.attr2, self.value2)

        self.str_rdn2 = '%s=%s' % (self.attr2, self.value2)
        self.rdn2     = RDN(self.attr2, self.value2)

        self.str_dn1 = self.str_rdn1
        self.dn1 = DN(self.rdn1)

        self.str_dn2 = self.str_rdn2
        self.dn2 = DN(self.rdn2)

        self.str_dn3 = '%s,%s' % (self.str_rdn1, self.str_rdn2)
        self.dn3 = DN(self.rdn1, self.rdn2)

    def test_create(self):
        # Create with single attr,value pair
        dn1 = DN(self.attr1, self.value1)
        self.assertEqual(len(dn1), 1)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)

        # Create with single attr,value pair passed as a tuple
        dn1 = DN((self.attr1, self.value1))
        self.assertEqual(len(dn1), 1)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)

        # Create with multiple attr,value pairs
        dn1 = DN(self.attr1, self.value1, self.attr2, self.value2)
        self.assertEqual(len(dn1), 2)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertIsInstance(dn1[1], RDN)
        self.assertIsInstance(dn1[1].attr, unicode)
        self.assertIsInstance(dn1[1].value, unicode)
        self.assertEqual(dn1[1], self.rdn2)

        # Create with multiple attr,value pairs passed as lists
        dn1 = DN([self.attr1, self.value1], [self.attr2, self.value2])
        self.assertEqual(len(dn1), 2)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertIsInstance(dn1[1], RDN)
        self.assertIsInstance(dn1[1].attr, unicode)
        self.assertIsInstance(dn1[1].value, unicode)
        self.assertEqual(dn1[1], self.rdn2)

        # Create with multiple attr,value pairs but reverse
        # constructor parameter ordering. RDN ordering should also be
        # reversed because DN's are a ordered sequence of RDN's
        dn1 = DN(self.attr2, self.value2, self.attr1, self.value1)
        self.assertEqual(len(dn1), 2)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn2)
        self.assertIsInstance(dn1[1], RDN)
        self.assertIsInstance(dn1[1].attr, unicode)
        self.assertIsInstance(dn1[1].value, unicode)
        self.assertEqual(dn1[1], self.rdn1)

        # Create with single RDN object
        dn1 = DN(self.rdn1)
        self.assertEqual(len(dn1), 1)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)

        # Create with multiple RDN objects, assure ordering is preserved.
        dn1 = DN(self.rdn1, self.rdn2)
        self.assertEqual(len(dn1), 2)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertIsInstance(dn1[1], RDN)
        self.assertIsInstance(dn1[1].attr, unicode)
        self.assertIsInstance(dn1[1].value, unicode)
        self.assertEqual(dn1[1], self.rdn2)

        # Create with multiple RDN objects in different order, assure
        # ordering is preserved.
        dn1 = DN(self.rdn2, self.rdn1)
        self.assertEqual(len(dn1), 2)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn2)
        self.assertIsInstance(dn1[1], RDN)
        self.assertIsInstance(dn1[1].attr, unicode)
        self.assertIsInstance(dn1[1].value, unicode)
        self.assertEqual(dn1[1], self.rdn1)

        # Create with single string with 1 RDN
        dn1 = DN(self.str_rdn1)
        self.assertEqual(len(dn1), 1)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)

        # Create with single string with 2 RDN's
        dn1 = DN(self.str_dn3)
        self.assertEqual(len(dn1), 2)
        self.assertIsInstance(dn1[0], RDN)
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertIsInstance(dn1[1], RDN)
        self.assertIsInstance(dn1[1].attr, unicode)
        self.assertIsInstance(dn1[1].value, unicode)
        self.assertEqual(dn1[1], self.rdn2)

    def test_str(self):
        self.assertEqual(str(self.dn1), self.str_dn1)
        self.assertIsInstance(str(self.dn1), str)

        self.assertEqual(str(self.dn2), self.str_dn2)
        self.assertIsInstance(str(self.dn2), str)

        self.assertEqual(str(self.dn3), self.str_dn3)
        self.assertIsInstance(str(self.dn3), str)

    def test_cmp(self):
        # Equality
        dn1 = DN(self.attr1, self.value1)

        self.assertTrue(dn1 == self.dn1)
        self.assertFalse(dn1 != self.dn1)

        result = cmp(dn1, self.dn1)
        self.assertEqual(result, 0)

        # Make dn1's attr greater
        dn1[0].attr = self.attr1 + "1"

        self.assertFalse(dn1 == self.dn1)
        self.assertTrue(dn1 != self.dn1)

        result = cmp(dn1, self.dn1)
        self.assertEqual(result, 1)

        result = cmp(self.dn1, dn1)
        self.assertEqual(result, -1)

        # Reset dn1's attr, should be equal again
        dn1[0].attr = self.attr1

        result = cmp(dn1, self.dn1)
        self.assertEqual(result, 0)

        # Make dn1's value greater
        # attr will be equal, this tests secondary comparision component
        dn1[0].value = self.value1 + "1"

        result = cmp(dn1, self.dn1)
        self.assertEqual(result, 1)

        result = cmp(self.dn1, dn1)
        self.assertEqual(result, -1)

        # Make sure dn's with more rdn's are greater
        result = cmp(self.dn1, self.dn3)
        self.assertEqual(result, -1)
        result = cmp(self.dn3, self.dn1)
        self.assertEqual(result, 1)

    def test_indexing(self):
        self.assertEqual(self.dn1[0], self.rdn1)
        self.assertEqual(self.dn1[self.rdn1.attr], self.rdn1.value)
        with self.assertRaises(KeyError):
            self.dn1['foo']

        self.assertEqual(self.dn2[0], self.rdn2)
        self.assertEqual(self.dn2[self.rdn2.attr], self.rdn2.value)
        with self.assertRaises(KeyError):
            self.dn2['foo']

        self.assertEqual(self.dn3[0], self.rdn1)
        self.assertEqual(self.dn3[self.rdn1.attr], self.rdn1.value)
        self.assertEqual(self.dn3[1], self.rdn2)
        self.assertEqual(self.dn3[self.rdn2.attr], self.rdn2.value)
        with self.assertRaises(KeyError):
            self.dn3['foo']

        with self.assertRaises(TypeError):
            self.dn3[1.0]

    def test_assignments(self):
        dn_low = 0
        dn_high = 6

        rdn_args = make_rdn_args(dn_low, dn_high, 'sequence')
        dn1 = DN(*rdn_args)

        rdn_args = make_rdn_args(dn_low, dn_high, 'tuple')
        dn2 = DN(*rdn_args)

        rdn_args = make_rdn_args(dn_low, dn_high, 'RDN')
        dn3 = DN(*rdn_args)

        self.assertEqual(dn1, dn2)
        self.assertEqual(dn1, dn3)

        for i in range(dn_low, dn_high):
            attr = 'a%d' % i
            value = str(i)
            self.assertEqual(dn1[i].attr, attr)
            self.assertEqual(dn1[i].value, value)
            self.assertEqual(dn1[attr], value)

        for i in range(dn_low, dn_high):
            if i % 2:
                orig_attr = 'a%d' % i
                attr = 'b%d' % i
                value = str(i*10)
                dn1[i] = attr, value
                dn2[orig_attr] = (attr, value)
                dn3[i] = RDN(attr, value)

        self.assertEqual(dn1, dn2)
        self.assertEqual(dn1, dn3)

        for i in range(dn_low, dn_high):
            if i % 2:
                attr = 'b%d' % i
                value = str(i*10)
            else:
                attr = 'a%d' % i
                value = str(i)
            self.assertEqual(dn1[i].value, dn1[i].value)
            self.assertEqual(dn1[attr], value)

        # Slices
        slice_low = 2
        slice_high = 4
        interval = range(slice_low, slice_high)

        # Assign via sequence
        rdn_args = make_rdn_args(dn_low, dn_high, 'sequence')
        dn1 = DN(*rdn_args)

        dn_slice = make_rdn_args(slice_low, slice_high, 'sequence',
                                 lambda i: 'b%d' % i, lambda i: str(i*10))

        dn1[slice_low:slice_high] = dn_slice

        for i in range(dn_low, dn_high):
            if i in interval:
                attr = 'b%d' % i
                value = str(i*10)
            else:
                attr = 'a%d' % i
                value = str(i)
            self.assertEqual(dn1[i].value, dn1[i].value)
            self.assertEqual(dn1[attr], value)

        query_slice = dn1[slice_low:slice_high]
        for i, query_rdn in enumerate(query_slice):
            slice_rdn = RDN(dn_slice[i*2], dn_slice[i*2+1])
            self.assertEqual(slice_rdn, query_rdn)

        # Slices
        # Assign via tuple
        rdn_args = make_rdn_args(dn_low, dn_high, 'sequence')
        dn1 = DN(*rdn_args)

        dn_slice = make_rdn_args(slice_low, slice_high, 'tuple',
                                 lambda i: 'b%d' % i, lambda i: str(i*10))

        dn1[slice_low:slice_high] = dn_slice

        for i in range(dn_low, dn_high):
            if i in interval:
                attr = 'b%d' % i
                value = str(i*10)
            else:
                attr = 'a%d' % i
                value = str(i)
            self.assertEqual(dn1[i].value, dn1[i].value)
            self.assertEqual(dn1[attr], value)

        query_slice = dn1[slice_low:slice_high]
        for i, query_rdn in enumerate(query_slice):
            slice_rdn = RDN(dn_slice[i])
            self.assertEqual(slice_rdn, query_rdn)

        # Slices
        # Assign via RDN
        rdn_args = make_rdn_args(dn_low, dn_high, 'sequence')
        dn1 = DN(*rdn_args)

        dn_slice = make_rdn_args(slice_low, slice_high, 'RDN',
                                 lambda i: 'b%d' % i, lambda i: str(i*10))

        dn1[slice_low:slice_high] = dn_slice

        for i in range(dn_low, dn_high):
            if i in interval:
                attr = 'b%d' % i
                value = str(i*10)
            else:
                attr = 'a%d' % i
                value = str(i)
            self.assertEqual(dn1[i].value, dn1[i].value)
            self.assertEqual(dn1[attr], value)

        query_slice = dn1[slice_low:slice_high]
        for i, query_rdn in enumerate(query_slice):
            slice_rdn = dn_slice[i]
            self.assertEqual(slice_rdn, query_rdn)


    def test_iter(self):
        self.assertEqual(len(self.dn1), 1)
        self.assertEqual(self.dn1[:], [self.rdn1])
        for i, ava in enumerate(self.dn1):
            if i == 0:
                self.assertEqual(ava, self.rdn1)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn1)))

        self.assertEqual(len(self.dn2), 1)
        self.assertEqual(self.dn2[:], [self.rdn2])
        for i, ava in enumerate(self.dn2):
            if i == 0:
                self.assertEqual(ava, self.rdn2)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn2)))

        self.assertEqual(len(self.dn3), 2)
        self.assertEqual(self.dn3[:], [self.rdn1, self.rdn2])
        for i, ava in enumerate(self.dn3):
            if i == 0:
                self.assertEqual(ava, self.rdn1)
            elif i == 1:
                self.assertEqual(ava, self.rdn2)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(self.dn3)))


    def test_concat(self):
        dn1 = DN(self.attr1, self.value1)
        dn2 = DN(self.attr2, self.value2)

        # in-place addtion
        dn1 += dn2
        self.assertEqual(dn1, self.dn3)

        dn1 = DN(self.attr1, self.value1)
        dn1 += self.rdn2
        self.assertEqual(dn1, self.dn3)

        dn1 = DN(self.attr1, self.value1)
        dn1 += self.dn2
        self.assertEqual(dn1, self.dn3)

        dn1 = DN(self.attr1, self.value1)
        dn1 += self.str_dn2
        self.assertEqual(dn1, self.dn3)

        # concatenation
        dn1 = DN(self.attr1, self.value1)
        dn3 = dn1 + dn2
        self.assertEqual(dn3, self.dn3)

        dn1 = DN(self.attr1, self.value1)
        dn3 = dn1 + self.rdn2
        self.assertEqual(dn3, self.dn3)

        dn3 = dn1 + self.str_rdn2
        self.assertEqual(dn3, self.dn3)

        dn3 = dn1 + self.str_dn2
        self.assertEqual(dn3, self.dn3)

        dn3 = dn1 + self.dn2
        self.assertEqual(dn3, self.dn3)

class TestEscapes(unittest.TestCase):
    def setUp(self):
        self.privilege = 'R,W privilege'
        self.dn_str_hex_escape = 'cn=R\\2cW privilege,cn=privileges,cn=pbac,dc=idm,dc=lab,dc=bos,dc=redhat,dc=com'
        self.dn_str_backslash_escape = 'cn=R\\,W privilege,cn=privileges,cn=pbac,dc=idm,dc=lab,dc=bos,dc=redhat,dc=com'

    def test_escape(self):
        dn = DN(self.dn_str_hex_escape)
        self.assertEqual(dn['cn'], self.privilege)
        self.assertEqual(dn[0].value, self.privilege)

        dn = DN(self.dn_str_backslash_escape)
        self.assertEqual(dn['cn'], self.privilege)
        self.assertEqual(dn[0].value, self.privilege)

if __name__ == '__main__':
    unittest.main()
