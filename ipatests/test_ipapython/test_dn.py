import contextlib
import unittest
import pytest

from cryptography import x509
import six

from ipapython.dn import DN, RDN, AVA

if six.PY3:
    unicode = str

    def cmp(a, b):
        if a == b:
            assert not a < b
            assert not a > b
            assert not a != b
            assert a <= b
            assert a >= b
            return 0
        elif a < b:
            assert not a > b
            assert a != b
            assert a <= b
            assert not a >= b
            return -1
        else:
            assert a > b
            assert a != b
            assert not a <= b
            assert a >= b
            return 1

pytestmark = pytest.mark.tier0


def expected_class(klass, component):
    if klass is AVA:
        if component == 'self':
            return AVA

    elif klass is RDN:
        if component == 'self':
            return RDN
        elif component == 'AVA':
            return AVA

    elif klass is DN:
        if component == 'self':
            return DN
        elif component == 'AVA':
            return AVA
        elif component == 'RDN':
            return RDN

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
        # Create with attr,value pair
        ava1 = AVA(self.attr1, self.value1)
        self.assertExpectedClass(AVA, ava1, 'self')
        self.assertEqual(ava1, self.ava1)

        # Create with "attr=value" string
        ava1 = AVA(self.str_ava1)
        self.assertExpectedClass(AVA, ava1, 'self')
        self.assertEqual(ava1, self.ava1)

        # Create with tuple (attr, value)
        ava1 = AVA((self.attr1, self.value1))
        self.assertExpectedClass(AVA, ava1, 'self')
        self.assertEqual(ava1, self.ava1)

        # Create with list [attr, value]
        ava1 = AVA([self.attr1, self.value1])
        self.assertExpectedClass(AVA, ava1, 'self')
        self.assertEqual(ava1, self.ava1)

        # Create with no args should fail
        with self.assertRaises(TypeError):
            AVA()

        # Create with more than 3 args should fail
        with self.assertRaises(TypeError):
            AVA(self.attr1, self.value1, self.attr1, self.attr1)

        # Create with 1 arg which is not string should fail
        with self.assertRaises(TypeError):
            AVA(1)

        # Create with malformed AVA string should fail
        with self.assertRaises(ValueError):
            AVA("cn")

        # Create with non-string parameters, should convert
        ava1 = AVA(1, self.value1)
        self.assertExpectedClass(AVA, ava1, 'self')
        self.assertEqual(ava1.attr, u'1')

        ava1 = AVA((1, self.value1))
        self.assertExpectedClass(AVA, ava1, 'self')
        self.assertEqual(ava1.attr, u'1')

        ava1 = AVA(self.attr1, 1)
        self.assertExpectedClass(AVA, ava1, 'self')
        self.assertEqual(ava1.value, u'1')

        ava1 = AVA((self.attr1, 1))
        self.assertExpectedClass(AVA, ava1, 'self')
        self.assertEqual(ava1.value, u'1')

    def test_indexing(self):
        ava1 = AVA(self.ava1)

        self.assertEqual(ava1[self.attr1], self.value1)

        self.assertEqual(ava1[0], self.attr1)
        self.assertEqual(ava1[1], self.value1)

        with self.assertRaises(KeyError):
            ava1['foo']  # pylint: disable=pointless-statement

        with self.assertRaises(KeyError):
            ava1[3]  # pylint: disable=pointless-statement

    def test_properties(self):
        ava1 = AVA(self.ava1)

        self.assertEqual(ava1.attr, self.attr1)
        self.assertIsInstance(ava1.attr, unicode)

        self.assertEqual(ava1.value, self.value1)
        self.assertIsInstance(ava1.value, unicode)

    def test_str(self):
        ava1 = AVA(self.ava1)

        self.assertEqual(str(ava1), self.str_ava1)
        self.assertIsInstance(str(ava1), str)

    def test_cmp(self):
        # Equality
        ava1 = AVA(self.attr1, self.value1)

        self.assertTrue(ava1 == self.ava1)
        self.assertFalse(ava1 != self.ava1)

        self.assertTrue(ava1 == self.str_ava1)
        self.assertFalse(ava1 != self.str_ava1)

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 0)

        # Upper case attr should still be equal
        ava1 = AVA(self.attr1.upper(), self.value1)

        self.assertFalse(ava1.attr == self.attr1)
        self.assertTrue(ava1.value == self.value1)
        self.assertTrue(ava1 == self.ava1)
        self.assertFalse(ava1 != self.ava1)

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 0)

        # Upper case value should still be equal
        ava1 = AVA(self.attr1, self.value1.upper())

        self.assertTrue(ava1.attr == self.attr1)
        self.assertFalse(ava1.value == self.value1)
        self.assertTrue(ava1 == self.ava1)
        self.assertFalse(ava1 != self.ava1)

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 0)

        # Make ava1's attr greater
        with self.assertRaises(AttributeError):
            ava1.attr = self.attr1 + "1"
        ava1 = AVA(self.attr1 + "1", self.value1.upper())

        self.assertFalse(ava1 == self.ava1)
        self.assertTrue(ava1 != self.ava1)

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 1)

        result = cmp(self.ava1, ava1)
        self.assertEqual(result, -1)

        # Reset ava1's attr, should be equal again
        with self.assertRaises(AttributeError):
            ava1.attr = self.attr1
        ava1 = AVA(self.attr1, self.value1.upper())

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 0)

        # Make ava1's value greater
        # attr will be equal, this tests secondary comparision component
        with self.assertRaises(AttributeError):
            ava1.value = self.value1 + "1"
        ava1 = AVA(self.attr1, self.value1 + "1")

        result = cmp(ava1, self.ava1)
        self.assertEqual(result, 1)

        result = cmp(self.ava1, ava1)
        self.assertEqual(result, -1)

    def test_hashing(self):
        # create AVA's that are equal but differ in case
        ava1 = AVA((self.attr1.lower(), self.value1.upper()))
        ava2 = AVA((self.attr1.upper(), self.value1.lower()))

        # AVAs that are equal should hash to the same value.
        self.assertEqual(ava1, ava2)
        self.assertEqual(hash(ava1), hash(ava2))

        # Different AVA objects with the same value should
        # map to 1 common key and 1 member in a set. The key and
        # member are based on the object's value.

        ava1_a = AVA(self.ava1)
        ava1_b = AVA(self.ava1)

        ava2_a = AVA(self.ava2)
        ava2_b = AVA(self.ava2)

        ava3_a = AVA(self.ava3)
        ava3_b = AVA(self.ava3)

        self.assertEqual(ava1_a, ava1_b)
        self.assertEqual(ava2_a, ava2_b)
        self.assertEqual(ava3_a, ava3_b)

        d = dict()
        s = set()

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
        self.assertEqual(sorted(d), sorted([ava1_a, ava2_a]))
        self.assertEqual(sorted(s), sorted([ava1_a, ava2_a]))

        self.assertTrue(ava1_a in d)
        self.assertTrue(ava1_b in d)
        self.assertTrue(ava2_a in d)
        self.assertTrue(ava2_b in d)
        self.assertFalse(ava3_a in d)
        self.assertFalse(ava3_b in d)

        self.assertTrue(ava1_a in s)
        self.assertTrue(ava1_b in s)
        self.assertTrue(ava2_a in s)
        self.assertTrue(ava2_b in s)
        self.assertFalse(ava3_a in s)
        self.assertFalse(ava3_b in s)


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
        # Create with single attr,value pair
        rdn1 = RDN((self.attr1, self.value1))


        self.assertEqual(len(rdn1), 1)
        self.assertEqual(rdn1, self.rdn1)
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')
        self.assertEqual(rdn1[0], self.ava1)

        # Create with multiple attr,value pairs
        rdn3 = RDN((self.attr1, self.value1), (self.attr2, self.value2))
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        self.assertEqual(rdn3[0], self.ava1)
        self.assertEqual(rdn3[1], self.ava2)

        # Create with multiple attr,value pairs passed as lists
        rdn3 = RDN([self.attr1, self.value1], [self.attr2, self.value2])
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        self.assertEqual(rdn3[0], self.ava1)
        self.assertEqual(rdn3[1], self.ava2)

        # Create with multiple attr,value pairs but reverse
        # constructor parameter ordering. RDN canonical ordering
        # should remain the same
        rdn3 = RDN((self.attr2, self.value2), (self.attr1, self.value1))
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        self.assertEqual(rdn3[0], self.ava1)
        self.assertEqual(rdn3[1], self.ava2)

        # Create with single AVA object
        rdn1 = RDN(self.ava1)
        self.assertEqual(len(rdn1), 1)
        self.assertEqual(rdn1, self.rdn1)
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')
        self.assertEqual(rdn1[0], self.ava1)

        # Create with multiple AVA objects
        rdn3 = RDN(self.ava1, self.ava2)
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        self.assertEqual(rdn3[0], self.ava1)
        self.assertEqual(rdn3[1], self.ava2)


        # Create with multiple AVA objects but reverse constructor
        # parameter ordering.  RDN canonical ordering should remain
        # the same
        rdn3 = RDN(self.ava2, self.ava1)
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        self.assertEqual(rdn3[0], self.ava1)
        self.assertEqual(rdn3[1], self.ava2)

        # Create with single string with 1 AVA
        rdn1 = RDN(self.str_rdn1)
        self.assertEqual(len(rdn1), 1)
        self.assertEqual(rdn1, self.rdn1)
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')
        self.assertEqual(rdn1[0], self.ava1)

        # Create with single string with 2 AVA's
        rdn3 = RDN(self.str_rdn3)
        self.assertEqual(len(rdn3), 2)
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        self.assertEqual(rdn3[0], self.ava1)
        self.assertEqual(rdn3[1], self.ava2)

    def test_properties(self):
        rdn1 = RDN(self.rdn1)
        rdn2 = RDN(self.rdn2)
        rdn3 = RDN(self.rdn3)

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
        rdn1 = RDN(self.rdn1)
        rdn2 = RDN(self.rdn2)
        rdn3 = RDN(self.rdn3)

        self.assertEqual(str(rdn1), self.str_rdn1)
        self.assertIsInstance(str(rdn1), str)

        self.assertEqual(str(rdn2), self.str_rdn2)
        self.assertIsInstance(str(rdn2), str)

        self.assertEqual(str(rdn3), self.str_rdn3)
        self.assertIsInstance(str(rdn3), str)

    def test_cmp(self):
        # Equality
        rdn1 = RDN((self.attr1, self.value1))

        self.assertTrue(rdn1 == self.rdn1)
        self.assertFalse(rdn1 != self.rdn1)

        self.assertTrue(rdn1 == self.str_rdn1)
        self.assertFalse(rdn1 != self.str_rdn1)

        result = cmp(rdn1, self.rdn1)
        self.assertEqual(result, 0)

        # Make rdn1's attr greater
        rdn1 = RDN((self.attr1 + "1", self.value1))

        self.assertFalse(rdn1 == self.rdn1)
        self.assertTrue(rdn1 != self.rdn1)

        result = cmp(rdn1, self.rdn1)
        self.assertEqual(result, 1)

        result = cmp(self.rdn1, rdn1)
        self.assertEqual(result, -1)

        # Reset rdn1's attr, should be equal again
        rdn1 = RDN((self.attr1, self.value1))

        result = cmp(rdn1, self.rdn1)
        self.assertEqual(result, 0)

        # Make rdn1's value greater
        # attr will be equal, this tests secondary comparision component
        rdn1 = RDN((self.attr1, self.value1 + "1"))

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
        rdn1 = RDN(self.rdn1)
        rdn2 = RDN(self.rdn2)
        rdn3 = RDN(self.rdn3)

        self.assertEqual(rdn1[0], self.ava1)
        self.assertEqual(rdn1[self.ava1.attr], self.ava1.value)
        with self.assertRaises(KeyError):
            rdn1['foo']  # pylint: disable=pointless-statement

        self.assertEqual(rdn2[0], self.ava2)
        self.assertEqual(rdn2[self.ava2.attr], self.ava2.value)
        with self.assertRaises(KeyError):
            rdn2['foo']  # pylint: disable=pointless-statement

        self.assertEqual(rdn3[0], self.ava1)
        self.assertEqual(rdn3[self.ava1.attr], self.ava1.value)
        self.assertEqual(rdn3[1], self.ava2)
        self.assertEqual(rdn3[self.ava2.attr], self.ava2.value)
        with self.assertRaises(KeyError):
            rdn3['foo']  # pylint: disable=pointless-statement

        self.assertEqual(rdn1.attr, self.attr1)
        self.assertEqual(rdn1.value, self.value1)

        with self.assertRaises(TypeError):
            rdn3[1.0]  # pylint: disable=pointless-statement

        # Slices
        self.assertEqual(rdn3[0:1], [self.ava1])
        self.assertEqual(rdn3[:],   [self.ava1, self.ava2])

    def test_assignments(self):
        rdn = RDN((self.attr1, self.value1))
        with self.assertRaises(TypeError):
            # pylint: disable=unsupported-assignment-operation
            rdn[0] = self.ava2

    def test_iter(self):
        rdn1 = RDN(self.rdn1)
        rdn2 = RDN(self.rdn2)
        rdn3 = RDN(self.rdn3)

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
        rdn1 = RDN((self.attr1, self.value1))
        rdn2 = RDN((self.attr2, self.value2))

        # in-place addtion
        rdn1 += rdn2
        self.assertEqual(rdn1, self.rdn3)
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')

        rdn1 = RDN((self.attr1, self.value1))
        rdn1 += self.ava2
        self.assertEqual(rdn1, self.rdn3)
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')

        rdn1 = RDN((self.attr1, self.value1))
        rdn1 += self.str_ava2
        self.assertEqual(rdn1, self.rdn3)
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')

        # concatenation
        rdn1 = RDN((self.attr1, self.value1))
        rdn3 = rdn1 + rdn2
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')

        rdn3 = rdn1 + self.ava2
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')

        rdn3 = rdn1 + self.str_ava2
        self.assertEqual(rdn3, self.rdn3)
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')


    def test_hashing(self):
        # create RDN's that are equal but differ in case
        rdn1 = RDN((self.attr1.lower(), self.value1.upper()))
        rdn2 = RDN((self.attr1.upper(), self.value1.lower()))

        # RDNs that are equal should hash to the same value.
        self.assertEqual(rdn1, rdn2)
        self.assertEqual(hash(rdn1), hash(rdn2))


class TestDN(unittest.TestCase):
    def setUp(self):
        # ava1 must sort before ava2
        self.attr1    = 'cn'
        self.value1   = u'Bob'
        self.str_ava1 = '%s=%s' % (self.attr1, self.value1)
        self.ava1     = AVA(self.attr1, self.value1)

        self.str_rdn1 = '%s=%s' % (self.attr1, self.value1)
        self.rdn1     = RDN((self.attr1, self.value1))

        self.attr2    = 'ou'
        self.value2   = u'people'
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

        ou = x509.NameAttribute(
            x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.value2)
        cn = x509.NameAttribute(x509.NameOID.COMMON_NAME, self.value1)
        c = x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u'AU')
        st = x509.NameAttribute(
            x509.NameOID.STATE_OR_PROVINCE_NAME, u'Queensland')
        self.x500name = x509.Name([ou, cn])
        self.x500nameMultiRDN = x509.Name([
            x509.RelativeDistinguishedName([c, st]),
            x509.RelativeDistinguishedName([cn]),
        ])

    def assertExpectedClass(self, klass, obj, component):
        self.assertIs(obj.__class__, expected_class(klass, component))

    def test_create(self):
        # Create with single attr,value pair
        dn1 = DN((self.attr1, self.value1))
        self.assertEqual(len(dn1), 1)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
        self.assertIsInstance(dn1[0].attr, unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)

        # Create with single attr,value pair passed as a tuple
        dn1 = DN((self.attr1, self.value1))
        self.assertEqual(len(dn1), 1)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)

        # Creation with multiple attr,value string pairs should fail
        with self.assertRaises(ValueError):
            dn1 = DN(self.attr1, self.value1, self.attr2, self.value2)

        # Create with multiple attr,value pairs passed as tuples & lists
        dn1 = DN((self.attr1, self.value1), [self.attr2, self.value2])
        self.assertEqual(len(dn1), 2)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertEqual(dn1[1], self.rdn2)

        # Create with multiple attr,value pairs passed as tuple and RDN
        dn1 = DN((self.attr1, self.value1), RDN((self.attr2, self.value2)))
        self.assertEqual(len(dn1), 2)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertEqual(dn1[1], self.rdn2)

        # Create with multiple attr,value pairs but reverse
        # constructor parameter ordering. RDN ordering should also be
        # reversed because DN's are a ordered sequence of RDN's
        dn1 = DN((self.attr2, self.value2), (self.attr1, self.value1))
        self.assertEqual(len(dn1), 2)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn2)
        self.assertEqual(dn1[1], self.rdn1)

        # Create with single RDN object
        dn1 = DN(self.rdn1)
        self.assertEqual(len(dn1), 1)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)

        # Create with multiple RDN objects, assure ordering is preserved.
        dn1 = DN(self.rdn1, self.rdn2)
        self.assertEqual(len(dn1), 2)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertEqual(dn1[1], self.rdn2)

        # Create with multiple RDN objects in different order, assure
        # ordering is preserved.
        dn1 = DN(self.rdn2, self.rdn1)
        self.assertEqual(len(dn1), 2)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn2)
        self.assertEqual(dn1[1], self.rdn1)

        # Create with single string with 1 RDN
        dn1 = DN(self.str_rdn1)
        self.assertEqual(len(dn1), 1)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)

        # Create with single string with 2 RDN's
        dn1 = DN(self.str_dn3)
        self.assertEqual(len(dn1), 2)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertEqual(dn1[1], self.rdn2)

        # Create with a python-cryptography 'Name'
        dn1 = DN(self.x500name)
        self.assertEqual(len(dn1), 2)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            self.assertIsInstance(dn1[i].attr, unicode)
            self.assertIsInstance(dn1[i].value, unicode)
        self.assertEqual(dn1[0], self.rdn1)
        self.assertEqual(dn1[1], self.rdn2)

        # Create from 'Name' with multi-valued RDN
        dn1 = DN(self.x500nameMultiRDN)
        self.assertEqual(len(dn1), 2)
        self.assertEqual(len(dn1[1]), 2)
        self.assertIn(AVA('c', 'au'), dn1[1])
        self.assertIn(AVA('st', 'queensland'), dn1[1])
        self.assertEqual(len(dn1[0]), 1)
        self.assertIn(self.ava1, dn1[0])

        # Create with RDN, and 2 DN's (e.g. attr + container + base)
        dn1 = DN((self.attr1, self.value1), self.container_dn, self.base_dn)
        self.assertEqual(len(dn1), 5)
        dn_str = ','.join([str(self.rdn1),
                            str(self.container_rdn1), str(self.container_rdn2),
                            str(self.base_rdn1), str(self.base_rdn2)])
        self.assertEqual(str(dn1), dn_str)

    def test_str(self):
        dn1 = DN(self.dn1)
        dn2 = DN(self.dn2)
        dn3 = DN(self.dn3)

        self.assertEqual(str(dn1), self.str_dn1)
        self.assertIsInstance(str(dn1), str)

        self.assertEqual(str(dn2), self.str_dn2)
        self.assertIsInstance(str(dn2), str)

        self.assertEqual(str(dn3), self.str_dn3)
        self.assertIsInstance(str(dn3), str)

    def test_cmp(self):
        # Equality
        dn1 = DN((self.attr1, self.value1))

        self.assertTrue(dn1 == self.dn1)
        self.assertFalse(dn1 != self.dn1)

        self.assertTrue(dn1 == self.str_dn1)
        self.assertFalse(dn1 != self.str_dn1)

        result = cmp(dn1, self.dn1)
        self.assertEqual(result, 0)

        # Make dn1's attr greater
        with self.assertRaises(AttributeError):
            dn1[0].attr = self.attr1 + "1"
        dn1 = DN((self.attr1 + "1", self.value1))

        self.assertFalse(dn1 == self.dn1)
        self.assertTrue(dn1 != self.dn1)

        result = cmp(dn1, self.dn1)
        self.assertEqual(result, 1)

        result = cmp(self.dn1, dn1)
        self.assertEqual(result, -1)

        # Reset dn1's attr, should be equal again
        with self.assertRaises(AttributeError):
            dn1[0].attr = self.attr1
        dn1 = DN((self.attr1, self.value1))

        result = cmp(dn1, self.dn1)
        self.assertEqual(result, 0)

        # Make dn1's value greater
        # attr will be equal, this tests secondary comparision component
        with self.assertRaises(AttributeError):
            dn1[0].value = self.value1 + "1"
        dn1 = DN((self.attr1, self.value1 + "1"))

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
        container_dn = DN(self.container_dn)
        base_container_dn = DN(self.base_container_dn)

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
        # pylint: disable=comparison-with-itself
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
        dn1 = DN(self.dn1)
        dn2 = DN(self.dn2)
        dn3 = DN(self.dn3)

        self.assertEqual(dn1[0], self.rdn1)
        self.assertEqual(dn1[self.rdn1.attr], self.rdn1.value)
        with self.assertRaises(KeyError):
            dn1['foo']  # pylint: disable=pointless-statement

        self.assertEqual(dn2[0], self.rdn2)
        self.assertEqual(dn2[self.rdn2.attr], self.rdn2.value)
        with self.assertRaises(KeyError):
            dn2['foo']  # pylint: disable=pointless-statement

        self.assertEqual(dn3[0], self.rdn1)
        self.assertEqual(dn3[self.rdn1.attr], self.rdn1.value)
        self.assertEqual(dn3[1], self.rdn2)
        self.assertEqual(dn3[self.rdn2.attr], self.rdn2.value)
        with self.assertRaises(KeyError):
            dn3['foo']  # pylint: disable=pointless-statement

        with self.assertRaises(TypeError):
            dn3[1.0]  # pylint: disable=pointless-statement

    def test_assignments(self):
        dn = DN('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=8,t=9')
        with self.assertRaises(TypeError):
            # pylint: disable=unsupported-assignment-operation
            dn[0] = RDN('t=a')
        with self.assertRaises(TypeError):
            # pylint: disable=unsupported-assignment-operation
            dn[0:1] = [RDN('t=a'), RDN('t=b')]

    def test_iter(self):
        dn1 = DN(self.dn1)
        dn2 = DN(self.dn2)
        dn3 = DN(self.dn3)

        self.assertEqual(len(dn1), 1)
        self.assertEqual(dn1[:], self.rdn1)
        for i, ava in enumerate(dn1):
            if i == 0:
                self.assertEqual(ava, self.rdn1)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn1)))

        self.assertEqual(len(dn2), 1)
        self.assertEqual(dn2[:], self.rdn2)
        for i, ava in enumerate(dn2):
            if i == 0:
                self.assertEqual(ava, self.rdn2)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(self.rdn2)))

        self.assertEqual(len(dn3), 2)
        self.assertEqual(dn3[:], DN(self.rdn1, self.rdn2))
        for i, ava in enumerate(dn3):
            if i == 0:
                self.assertEqual(ava, self.rdn1)
            elif i == 1:
                self.assertEqual(ava, self.rdn2)
            else:
                self.fail("got iteration index %d, but len=%d" % (i, len(dn3)))

    def test_concat(self):
        dn1 = DN((self.attr1, self.value1))
        dn2 = DN([self.attr2, self.value2])

        # in-place addtion

        dn1 += dn2
        self.assertEqual(dn1, self.dn3)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')


        dn1 = DN((self.attr1, self.value1))
        dn1 += self.rdn2
        self.assertEqual(dn1, self.dn3)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')


        dn1 = DN((self.attr1, self.value1))
        dn1 += self.dn2
        self.assertEqual(dn1, self.dn3)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')


        dn1 = DN((self.attr1, self.value1))
        dn1 += self.str_dn2
        self.assertEqual(dn1, self.dn3)
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')


        # concatenation
        dn1 = DN((self.attr1, self.value1))
        dn3 = dn1 + dn2
        self.assertEqual(dn3, self.dn3)
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            for j in range(0, len(dn3[i])):
                self.assertExpectedClass(DN, dn3[i][j], 'AVA')


        dn1 = DN((self.attr1, self.value1))
        dn3 = dn1 + self.rdn2
        self.assertEqual(dn3, self.dn3)
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            for j in range(0, len(dn3[i])):
                self.assertExpectedClass(DN, dn3[i][j], 'AVA')

        dn3 = dn1 + self.str_rdn2
        self.assertEqual(dn3, self.dn3)
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            self.assertExpectedClass(DN, dn3[i][0], 'AVA')

        dn3 = dn1 + self.str_dn2
        self.assertEqual(dn3, self.dn3)
        self.assertExpectedClass(DN, dn3, 'self')
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            for j in range(0, len(dn3[i])):
                self.assertExpectedClass(DN, dn3[i][j], 'AVA')

        dn3 = dn1 + self.dn2
        self.assertEqual(dn3, self.dn3)
        self.assertExpectedClass(DN, dn3, 'self')
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            for j in range(0, len(dn3[i])):
                self.assertExpectedClass(DN, dn3[i][j], 'AVA')

    def test_find(self):
        #        -10 -9  -8     -7  -6  -5  -4     -3  -2  -1
        dn = DN('t=0,t=1,cn=bob,t=3,t=4,t=5,cn=bob,t=7,t=8,t=9')
        pat = DN('cn=bob')

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
        # pylint: disable=no-member
        dn = DN('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=8,t=9')
        with self.assertRaises(AttributeError):
            dn.replace  # pylint: disable=pointless-statement

    def test_hashing(self):
        # create DN's that are equal but differ in case
        dn1 = DN((self.attr1.lower(), self.value1.upper()))
        dn2 = DN((self.attr1.upper(), self.value1.lower()))

        # DNs that are equal should hash to the same value.
        self.assertEqual(dn1, dn2)

        # Good, everyone's equal, now verify their hash values

        self.assertEqual(hash(dn1), hash(dn2))

        # Different DN objects with the same value should
        # map to 1 common key and 1 member in a set. The key and
        # member are based on the object's value.

        dn1_a = DN(self.dn1)
        dn1_b = DN(self.dn1)

        dn2_a = DN(self.dn2)
        dn2_b = DN(self.dn2)

        dn3_a = DN(self.dn3)
        dn3_b = DN(self.dn3)

        self.assertEqual(dn1_a, dn1_b)
        self.assertEqual(dn2_a, dn2_b)
        self.assertEqual(dn3_a, dn3_b)

        d = dict()
        s = set()

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
        self.assertEqual(sorted(d), sorted([dn1_a, dn2_a]))
        self.assertEqual(sorted(s), sorted([dn1_a, dn2_a]))

        self.assertTrue(dn1_a in d)
        self.assertTrue(dn1_b in d)
        self.assertTrue(dn2_a in d)
        self.assertTrue(dn2_b in d)
        self.assertFalse(dn3_a in d)
        self.assertFalse(dn3_b in d)

        self.assertTrue(dn1_a in s)
        self.assertTrue(dn1_b in s)
        self.assertTrue(dn2_a in s)
        self.assertTrue(dn2_b in s)
        self.assertFalse(dn3_a in s)
        self.assertFalse(dn3_b in s)

    def test_x500_text(self):
        # null DN x500 ordering and LDAP ordering are the same
        nulldn = DN()
        self.assertEqual(nulldn.ldap_text(), nulldn.x500_text())

        # reverse a DN with a single RDN
        self.assertEqual(self.dn1.ldap_text(), self.dn1.x500_text())

        # reverse a DN with 2 RDNs
        dn3_x500 = self.dn3.x500_text()
        dn3_rev = DN(self.rdn2, self.rdn1)
        self.assertEqual(dn3_rev.ldap_text(), dn3_x500)

        # reverse a longer DN
        longdn_x500 = self.base_container_dn.x500_text()
        longdn_rev = DN(longdn_x500)
        l = len(self.base_container_dn)
        for i in range(l):
            self.assertEqual(longdn_rev[i], self.base_container_dn[l-1-i])


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

class TestInternationalization(unittest.TestCase):
    def setUp(self):
        # Hello in Arabic
        self.arabic_hello_utf8 = (b'\xd9\x85\xd9\x83\xd9\x8a\xd9\x84' +
                                  b'\xd8\xb9\x20\xd9\x85\xd8\xa7\xd9' +
                                  b'\x84\xd9\x91\xd8\xb3\xd9\x84\xd8\xa7')

        self.arabic_hello_unicode = self.arabic_hello_utf8.decode('utf-8')

    def assert_equal_utf8(self, obj, b):
        if six.PY2:
            self.assertEqual(str(obj), b)
        else:
            self.assertEqual(str(obj), b.decode('utf-8'))

    @contextlib.contextmanager
    def fail_py3(self, exception_type):
        try:
            yield
        except exception_type:
            if six.PY2:
                raise

    def test_i18n(self):
        self.assertEqual(self.arabic_hello_utf8,
                         self.arabic_hello_unicode.encode('utf-8'))

        # AVA's
        # test attr i18n
        ava1 = AVA(self.arabic_hello_unicode, 'foo')
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)
        self.assertEqual(ava1.attr, self.arabic_hello_unicode)
        self.assert_equal_utf8(ava1, self.arabic_hello_utf8 + b'=foo')

        with self.fail_py3(TypeError):
            ava1 = AVA(self.arabic_hello_utf8, 'foo')
        if six.PY2:
            self.assertIsInstance(ava1.attr,  unicode)
            self.assertIsInstance(ava1.value, unicode)
            self.assertEqual(ava1.attr, self.arabic_hello_unicode)
            self.assert_equal_utf8(ava1, self.arabic_hello_utf8 + b'=foo')

        # test value i18n
        ava1 = AVA('cn', self.arabic_hello_unicode)
        self.assertIsInstance(ava1.attr,  unicode)
        self.assertIsInstance(ava1.value, unicode)
        self.assertEqual(ava1.value, self.arabic_hello_unicode)
        self.assert_equal_utf8(ava1, b'cn=' + self.arabic_hello_utf8)

        with self.fail_py3(TypeError):
            ava1 = AVA('cn', self.arabic_hello_utf8)
        if six.PY2:
            self.assertIsInstance(ava1.attr,  unicode)
            self.assertIsInstance(ava1.value, unicode)
            self.assertEqual(ava1.value, self.arabic_hello_unicode)
            self.assert_equal_utf8(ava1, b'cn=' + self.arabic_hello_utf8)

        # RDN's
        # test attr i18n
        rdn1 = RDN((self.arabic_hello_unicode, 'foo'))
        self.assertIsInstance(rdn1.attr,  unicode)
        self.assertIsInstance(rdn1.value, unicode)
        self.assertEqual(rdn1.attr, self.arabic_hello_unicode)
        self.assert_equal_utf8(rdn1, self.arabic_hello_utf8 + b'=foo')

        with self.fail_py3(TypeError):
            rdn1 = RDN((self.arabic_hello_utf8, 'foo'))
        if six.PY2:
            self.assertIsInstance(rdn1.attr,  unicode)
            self.assertIsInstance(rdn1.value, unicode)
            self.assertEqual(rdn1.attr, self.arabic_hello_unicode)
            self.assertEqual(str(rdn1), self.arabic_hello_utf8 + b'=foo')

        # test value i18n
        rdn1 = RDN(('cn', self.arabic_hello_unicode))
        self.assertIsInstance(rdn1.attr,  unicode)
        self.assertIsInstance(rdn1.value, unicode)
        self.assertEqual(rdn1.value, self.arabic_hello_unicode)
        self.assert_equal_utf8(rdn1, b'cn=' + self.arabic_hello_utf8)

        with self.fail_py3(TypeError):
            rdn1 = RDN(('cn', self.arabic_hello_utf8))
        if six.PY2:
            self.assertIsInstance(rdn1.attr,  unicode)
            self.assertIsInstance(rdn1.value, unicode)
            self.assertEqual(rdn1.value, self.arabic_hello_unicode)
            self.assertEqual(str(rdn1), b'cn=' + self.arabic_hello_utf8)

        # DN's
        # test attr i18n
        dn1 = DN((self.arabic_hello_unicode, 'foo'))
        self.assertIsInstance(dn1[0].attr,  unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0].attr, self.arabic_hello_unicode)
        self.assert_equal_utf8(dn1, self.arabic_hello_utf8 + b'=foo')

        with self.fail_py3(TypeError):
            dn1 = DN((self.arabic_hello_utf8, 'foo'))
        if six.PY2:
            self.assertIsInstance(dn1[0].attr,  unicode)
            self.assertIsInstance(dn1[0].value, unicode)
            self.assertEqual(dn1[0].attr, self.arabic_hello_unicode)
            self.assertEqual(str(dn1), self.arabic_hello_utf8 + b'=foo')

        # test value i18n
        dn1 = DN(('cn', self.arabic_hello_unicode))
        self.assertIsInstance(dn1[0].attr,  unicode)
        self.assertIsInstance(dn1[0].value, unicode)
        self.assertEqual(dn1[0].value, self.arabic_hello_unicode)
        self.assert_equal_utf8(dn1, b'cn=' + self.arabic_hello_utf8)

        with self.fail_py3(TypeError):
            dn1 = DN(('cn', self.arabic_hello_utf8))
        if six.PY2:
            self.assertIsInstance(dn1[0].attr,  unicode)
            self.assertIsInstance(dn1[0].value, unicode)
            self.assertEqual(dn1[0].value, self.arabic_hello_unicode)
            self.assertEqual(str(dn1), b'cn=' + self.arabic_hello_utf8)


if __name__ == '__main__':
    unittest.main()
