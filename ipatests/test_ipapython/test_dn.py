
import contextlib
import pytest

from cryptography import x509
import six

from ipapython.dn import DN, RDN, AVA, str2dn, dn2str, DECODING_ERROR
from ipapython import dn_ctypes


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


class TestAVA:
    @pytest.fixture(autouse=True)
    def ava_setup(self):
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
        assert obj.__class__ is expected_class(klass, component)

    def test_create(self):
        # Create with attr,value pair
        ava1 = AVA(self.attr1, self.value1)
        self.assertExpectedClass(AVA, ava1, 'self')
        assert ava1 == self.ava1

        # Create with "attr=value" string
        ava1 = AVA(self.str_ava1)
        self.assertExpectedClass(AVA, ava1, 'self')
        assert ava1 == self.ava1

        # Create with tuple (attr, value)
        ava1 = AVA((self.attr1, self.value1))
        self.assertExpectedClass(AVA, ava1, 'self')
        assert ava1 == self.ava1

        # Create with list [attr, value]
        ava1 = AVA([self.attr1, self.value1])
        self.assertExpectedClass(AVA, ava1, 'self')
        assert ava1 == self.ava1

        # Create with no args should fail
        with pytest.raises(TypeError):
            AVA()

        # Create with more than 3 args should fail
        with pytest.raises(TypeError):
            AVA(self.attr1, self.value1, self.attr1, self.attr1)

        # Create with 1 arg which is not string should fail
        with pytest.raises(TypeError):
            AVA(1)

        # Create with malformed AVA string should fail
        with pytest.raises(ValueError):
            AVA("cn")

        # Create with non-string parameters, should convert
        ava1 = AVA(1, self.value1)
        self.assertExpectedClass(AVA, ava1, 'self')
        assert ava1.attr == u'1'

        ava1 = AVA((1, self.value1))
        self.assertExpectedClass(AVA, ava1, 'self')
        assert ava1.attr == u'1'

        ava1 = AVA(self.attr1, 1)
        self.assertExpectedClass(AVA, ava1, 'self')
        assert ava1.value == u'1'

        ava1 = AVA((self.attr1, 1))
        self.assertExpectedClass(AVA, ava1, 'self')
        assert ava1.value == u'1'

    def test_indexing(self):
        ava1 = AVA(self.ava1)

        assert ava1[self.attr1] == self.value1

        assert ava1[0] == self.attr1
        assert ava1[1] == self.value1

        with pytest.raises(KeyError):
            ava1['foo']  # pylint: disable=pointless-statement

        with pytest.raises(KeyError):
            ava1[3]  # pylint: disable=pointless-statement

    def test_properties(self):
        ava1 = AVA(self.ava1)

        assert ava1.attr == self.attr1
        assert isinstance(ava1.attr, unicode)

        assert ava1.value == self.value1
        assert isinstance(ava1.value, unicode)

    def test_str(self):
        ava1 = AVA(self.ava1)

        assert str(ava1) == self.str_ava1
        assert isinstance(str(ava1), str)

    def test_cmp(self):
        # Equality
        ava1 = AVA(self.attr1, self.value1)

        assert ava1 == self.ava1
        assert ava1 == self.ava1

        assert ava1 == self.str_ava1
        assert ava1 == self.str_ava1

        result = cmp(ava1, self.ava1)
        assert result == 0

        # Upper case attr should still be equal
        ava1 = AVA(self.attr1.upper(), self.value1)

        assert ava1.attr != self.attr1
        assert ava1.value == self.value1
        assert ava1 == self.ava1
        assert ava1 == self.ava1

        result = cmp(ava1, self.ava1)
        assert result == 0

        # Upper case value should still be equal
        ava1 = AVA(self.attr1, self.value1.upper())

        assert ava1.attr == self.attr1
        assert ava1.value != self.value1
        assert ava1 == self.ava1
        assert ava1 == self.ava1

        result = cmp(ava1, self.ava1)
        assert result == 0

        # Make ava1's attr greater
        with pytest.raises(AttributeError):
            ava1.attr = self.attr1 + "1"
        ava1 = AVA(self.attr1 + "1", self.value1.upper())

        assert ava1 != self.ava1
        assert ava1 != self.ava1

        result = cmp(ava1, self.ava1)
        assert result == 1

        result = cmp(self.ava1, ava1)
        assert result == -1

        # Reset ava1's attr, should be equal again
        with pytest.raises(AttributeError):
            ava1.attr = self.attr1
        ava1 = AVA(self.attr1, self.value1.upper())

        result = cmp(ava1, self.ava1)
        assert result == 0

        # Make ava1's value greater
        # attr will be equal, this tests secondary comparision component
        with pytest.raises(AttributeError):
            ava1.value = self.value1 + "1"
        ava1 = AVA(self.attr1, self.value1 + "1")

        result = cmp(ava1, self.ava1)
        assert result == 1

        result = cmp(self.ava1, ava1)
        assert result == -1

    def test_hashing(self):
        # create AVA's that are equal but differ in case
        ava1 = AVA((self.attr1.lower(), self.value1.upper()))
        ava2 = AVA((self.attr1.upper(), self.value1.lower()))

        # AVAs that are equal should hash to the same value.
        assert ava1 == ava2
        assert hash(ava1) == hash(ava2)

        # Different AVA objects with the same value should
        # map to 1 common key and 1 member in a set. The key and
        # member are based on the object's value.

        ava1_a = AVA(self.ava1)
        ava1_b = AVA(self.ava1)

        ava2_a = AVA(self.ava2)
        ava2_b = AVA(self.ava2)

        ava3_a = AVA(self.ava3)
        ava3_b = AVA(self.ava3)

        assert ava1_a == ava1_b
        assert ava2_a == ava2_b
        assert ava3_a == ava3_b

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

        assert len(d) == 2
        assert len(s) == 2
        assert sorted(d) == sorted([ava1_a, ava2_a])
        assert sorted(s) == sorted([ava1_a, ava2_a])

        assert ava1_a in d
        assert ava1_b in d
        assert ava2_a in d
        assert ava2_b in d
        assert ava3_a not in d
        assert ava3_b not in d

        assert ava1_a in s
        assert ava1_b in s
        assert ava2_a in s
        assert ava2_b in s
        assert ava3_a not in s
        assert ava3_b not in s


class TestRDN:
    @pytest.fixture(autouse=True)
    def rdn_setup(self):
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
        assert obj.__class__ is expected_class(klass, component)

    def test_create(self):
        # Create with single attr,value pair
        rdn1 = RDN((self.attr1, self.value1))

        assert len(rdn1) == 1
        assert rdn1 == self.rdn1
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')
        assert rdn1[0] == self.ava1

        # Create with multiple attr,value pairs
        rdn3 = RDN((self.attr1, self.value1), (self.attr2, self.value2))
        assert len(rdn3) == 2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        assert rdn3[0] == self.ava1
        assert rdn3[1] == self.ava2

        # Create with multiple attr,value pairs passed as lists
        rdn3 = RDN([self.attr1, self.value1], [self.attr2, self.value2])
        assert len(rdn3) == 2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        assert rdn3[0] == self.ava1
        assert rdn3[1] == self.ava2

        # Create with multiple attr,value pairs but reverse
        # constructor parameter ordering. RDN canonical ordering
        # should remain the same
        rdn3 = RDN((self.attr2, self.value2), (self.attr1, self.value1))
        assert len(rdn3) == 2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        assert rdn3[0] == self.ava1
        assert rdn3[1] == self.ava2

        # Create with single AVA object
        rdn1 = RDN(self.ava1)
        assert len(rdn1) == 1
        assert rdn1 == self.rdn1
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')
        assert rdn1[0] == self.ava1

        # Create with multiple AVA objects
        rdn3 = RDN(self.ava1, self.ava2)
        assert len(rdn3) == 2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        assert rdn3[0] == self.ava1
        assert rdn3[1] == self.ava2


        # Create with multiple AVA objects but reverse constructor
        # parameter ordering.  RDN canonical ordering should remain
        # the same
        rdn3 = RDN(self.ava2, self.ava1)
        assert len(rdn3) == 2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        assert rdn3[0] == self.ava1
        assert rdn3[1] == self.ava2

        # Create with single string with 1 AVA
        rdn1 = RDN(self.str_rdn1)
        assert len(rdn1) == 1
        assert rdn1 == self.rdn1
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')
        assert rdn1[0] == self.ava1

        # Create with single string with 2 AVA's
        rdn3 = RDN(self.str_rdn3)
        assert len(rdn3) == 2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')
        assert rdn3[0] == self.ava1
        assert rdn3[1] == self.ava2

    def test_properties(self):
        rdn1 = RDN(self.rdn1)
        rdn2 = RDN(self.rdn2)
        rdn3 = RDN(self.rdn3)

        assert rdn1.attr == self.attr1
        assert isinstance(rdn1.attr, unicode)

        assert rdn1.value == self.value1
        assert isinstance(rdn1.value, unicode)

        assert rdn2.attr == self.attr2
        assert isinstance(rdn2.attr, unicode)

        assert rdn2.value == self.value2
        assert isinstance(rdn2.value, unicode)

        assert rdn3.attr == self.attr1
        assert isinstance(rdn3.attr, unicode)

        assert rdn3.value == self.value1
        assert isinstance(rdn3.value, unicode)

    def test_str(self):
        rdn1 = RDN(self.rdn1)
        rdn2 = RDN(self.rdn2)
        rdn3 = RDN(self.rdn3)

        assert str(rdn1) == self.str_rdn1
        assert isinstance(str(rdn1), str)

        assert str(rdn2) == self.str_rdn2
        assert isinstance(str(rdn2), str)

        assert str(rdn3) == self.str_rdn3
        assert isinstance(str(rdn3), str)

    def test_cmp(self):
        # Equality
        rdn1 = RDN((self.attr1, self.value1))

        assert rdn1 == self.rdn1
        assert rdn1 == self.rdn1

        assert rdn1 == self.str_rdn1
        assert rdn1 == self.str_rdn1

        result = cmp(rdn1, self.rdn1)
        assert result == 0

        # Make rdn1's attr greater
        rdn1 = RDN((self.attr1 + "1", self.value1))

        assert rdn1 != self.rdn1
        assert rdn1 != self.rdn1

        result = cmp(rdn1, self.rdn1)
        assert result == 1

        result = cmp(self.rdn1, rdn1)
        assert result == -1

        # Reset rdn1's attr, should be equal again
        rdn1 = RDN((self.attr1, self.value1))

        result = cmp(rdn1, self.rdn1)
        assert result == 0

        # Make rdn1's value greater
        # attr will be equal, this tests secondary comparision component
        rdn1 = RDN((self.attr1, self.value1 + "1"))

        result = cmp(rdn1, self.rdn1)
        assert result == 1

        result = cmp(self.rdn1, rdn1)
        assert result == -1

        # Make sure rdn's with more ava's are greater
        result = cmp(self.rdn1, self.rdn3)
        assert result == -1
        result = cmp(self.rdn3, self.rdn1)
        assert result == 1

    def test_indexing(self):
        rdn1 = RDN(self.rdn1)
        rdn2 = RDN(self.rdn2)
        rdn3 = RDN(self.rdn3)

        assert rdn1[0] == self.ava1
        assert rdn1[self.ava1.attr] == self.ava1.value
        with pytest.raises(KeyError):
            rdn1['foo']  # pylint: disable=pointless-statement

        assert rdn2[0] == self.ava2
        assert rdn2[self.ava2.attr] == self.ava2.value
        with pytest.raises(KeyError):
            rdn2['foo']  # pylint: disable=pointless-statement

        assert rdn3[0] == self.ava1
        assert rdn3[self.ava1.attr] == self.ava1.value
        assert rdn3[1] == self.ava2
        assert rdn3[self.ava2.attr] == self.ava2.value
        with pytest.raises(KeyError):
            rdn3['foo']  # pylint: disable=pointless-statement

        assert rdn1.attr == self.attr1
        assert rdn1.value == self.value1

        with pytest.raises(TypeError):
            rdn3[1.0]  # pylint: disable=pointless-statement

        # Slices
        assert rdn3[0:1] == [self.ava1]
        assert rdn3[:] == [self.ava1, self.ava2]

    def test_assignments(self):
        rdn = RDN((self.attr1, self.value1))
        with pytest.raises(TypeError):
            # pylint: disable=unsupported-assignment-operation
            rdn[0] = self.ava2

    def test_iter(self):
        rdn1 = RDN(self.rdn1)
        rdn2 = RDN(self.rdn2)
        rdn3 = RDN(self.rdn3)

        assert len(rdn1) == 1
        assert rdn1[:] == [self.ava1]
        for i, ava in enumerate(rdn1):
            if i == 0:
                assert ava == self.ava1
            else:
                pytest.fail(
                    "got iteration index %d, but len=%d" % (i, len(rdn1)))

        assert len(rdn2) == 1
        assert rdn2[:] == [self.ava2]
        for i, ava in enumerate(rdn2):
            if i == 0:
                assert ava == self.ava2
            else:
                pytest.fail(
                    "got iteration index %d, but len=%d" % (i, len(rdn2)))

        assert len(rdn3) == 2
        assert rdn3[:] == [self.ava1, self.ava2]
        for i, ava in enumerate(rdn3):
            if i == 0:
                assert ava == self.ava1
            elif i == 1:
                assert ava == self.ava2
            else:
                pytest.fail(
                    "got iteration index %d, but len=%d" % (i, len(rdn3)))


    def test_concat(self):
        rdn1 = RDN((self.attr1, self.value1))
        rdn2 = RDN((self.attr2, self.value2))

        # in-place addtion
        rdn1 += rdn2
        assert rdn1 == self.rdn3
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')

        rdn1 = RDN((self.attr1, self.value1))
        rdn1 += self.ava2
        assert rdn1 == self.rdn3
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')

        rdn1 = RDN((self.attr1, self.value1))
        rdn1 += self.str_ava2
        assert rdn1 == self.rdn3
        self.assertExpectedClass(RDN, rdn1, 'self')
        for i in range(0, len(rdn1)):
            self.assertExpectedClass(RDN, rdn1[i], 'AVA')

        # concatenation
        rdn1 = RDN((self.attr1, self.value1))
        rdn3 = rdn1 + rdn2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')

        rdn3 = rdn1 + self.ava2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')

        rdn3 = rdn1 + self.str_ava2
        assert rdn3 == self.rdn3
        self.assertExpectedClass(RDN, rdn3, 'self')
        for i in range(0, len(rdn3)):
            self.assertExpectedClass(RDN, rdn3[i], 'AVA')


    def test_hashing(self):
        # create RDN's that are equal but differ in case
        rdn1 = RDN((self.attr1.lower(), self.value1.upper()))
        rdn2 = RDN((self.attr1.upper(), self.value1.lower()))

        # RDNs that are equal should hash to the same value.
        assert rdn1 == rdn2
        assert hash(rdn1) == hash(rdn2)


class TestDN:
    @pytest.fixture(autouse=True)
    def dn_setup(self):
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
        c = x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'AU')
        st = x509.NameAttribute(
            x509.NameOID.STATE_OR_PROVINCE_NAME, 'Queensland')
        self.x500name = x509.Name([ou, cn])
        self.x500nameMultiRDN = x509.Name([
            x509.RelativeDistinguishedName([c, st]),
            x509.RelativeDistinguishedName([cn]),
        ])
        self.x500nameMultiRDN2 = x509.Name([
            x509.RelativeDistinguishedName([st, c]),
            x509.RelativeDistinguishedName([cn]),
        ])

    def assertExpectedClass(self, klass, obj, component):
        assert obj.__class__ is expected_class(klass, component)

    def test_create(self):
        # Create with single attr,value pair
        dn1 = DN((self.attr1, self.value1))
        assert len(dn1) == 1
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
        assert isinstance(dn1[0].attr, unicode)
        assert isinstance(dn1[0].value, unicode)
        assert dn1[0] == self.rdn1

        # Create with single attr,value pair passed as a tuple
        dn1 = DN((self.attr1, self.value1))
        assert len(dn1) == 1
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn1

        # Creation with multiple attr,value string pairs should fail
        with pytest.raises(ValueError):
            dn1 = DN(self.attr1, self.value1, self.attr2, self.value2)

        # Create with multiple attr,value pairs passed as tuples & lists
        dn1 = DN((self.attr1, self.value1), [self.attr2, self.value2])
        assert len(dn1) == 2
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn1
        assert dn1[1] == self.rdn2

        # Create with multiple attr,value pairs passed as tuple and RDN
        dn1 = DN((self.attr1, self.value1), RDN((self.attr2, self.value2)))
        assert len(dn1) == 2
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn1
        assert dn1[1] == self.rdn2

        # Create with multiple attr,value pairs but reverse
        # constructor parameter ordering. RDN ordering should also be
        # reversed because DN's are a ordered sequence of RDN's
        dn1 = DN((self.attr2, self.value2), (self.attr1, self.value1))
        assert len(dn1) == 2
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn2
        assert dn1[1] == self.rdn1

        # Create with single RDN object
        dn1 = DN(self.rdn1)
        assert len(dn1) == 1
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn1

        # Create with multiple RDN objects, assure ordering is preserved.
        dn1 = DN(self.rdn1, self.rdn2)
        assert len(dn1) == 2
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn1
        assert dn1[1] == self.rdn2

        # Create with multiple RDN objects in different order, assure
        # ordering is preserved.
        dn1 = DN(self.rdn2, self.rdn1)
        assert len(dn1) == 2
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn2
        assert dn1[1] == self.rdn1

        # Create with single string with 1 RDN
        dn1 = DN(self.str_rdn1)
        assert len(dn1) == 1
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn1

        # Create with single string with 2 RDN's
        dn1 = DN(self.str_dn3)
        assert len(dn1) == 2
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn1
        assert dn1[1] == self.rdn2

        # Create with a python-cryptography 'Name'
        dn1 = DN(self.x500name)
        assert len(dn1) == 2
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')
            assert isinstance(dn1[i].attr, unicode)
            assert isinstance(dn1[i].value, unicode)
        assert dn1[0] == self.rdn1
        assert dn1[1] == self.rdn2

        # Create from 'Name' with multi-valued RDN
        dn1 = DN(self.x500nameMultiRDN)
        assert len(dn1) == 2
        assert len(dn1[1]) == 2
        assert AVA('c', 'au') in dn1[1]
        assert AVA('st', 'queensland') in dn1[1]
        assert len(dn1[0]) == 1
        assert self.ava1 in dn1[0]

        # Create with RDN, and 2 DN's (e.g. attr + container + base)
        dn1 = DN((self.attr1, self.value1), self.container_dn, self.base_dn)
        assert len(dn1) == 5
        dn_str = ','.join([str(self.rdn1),
                            str(self.container_rdn1), str(self.container_rdn2),
                            str(self.base_rdn1), str(self.base_rdn2)])
        assert str(dn1) == dn_str

    def test_str(self):
        dn1 = DN(self.dn1)
        dn2 = DN(self.dn2)
        dn3 = DN(self.dn3)

        assert str(dn1) == self.str_dn1
        assert isinstance(str(dn1), str)

        assert str(dn2) == self.str_dn2
        assert isinstance(str(dn2), str)

        assert str(dn3) == self.str_dn3
        assert isinstance(str(dn3), str)

    def test_cmp(self):
        # Equality
        dn1 = DN((self.attr1, self.value1))

        assert dn1 == self.dn1
        assert dn1 == self.dn1

        assert dn1 == self.str_dn1
        assert dn1 == self.str_dn1

        result = cmp(dn1, self.dn1)
        assert result == 0

        # Make dn1's attr greater
        with pytest.raises(AttributeError):
            dn1[0].attr = self.attr1 + "1"
        dn1 = DN((self.attr1 + "1", self.value1))

        assert dn1 != self.dn1
        assert dn1 != self.dn1

        result = cmp(dn1, self.dn1)
        assert result == 1

        result = cmp(self.dn1, dn1)
        assert result == -1

        # Reset dn1's attr, should be equal again
        with pytest.raises(AttributeError):
            dn1[0].attr = self.attr1
        dn1 = DN((self.attr1, self.value1))

        result = cmp(dn1, self.dn1)
        assert result == 0

        # Make dn1's value greater
        # attr will be equal, this tests secondary comparision component
        with pytest.raises(AttributeError):
            dn1[0].value = self.value1 + "1"
        dn1 = DN((self.attr1, self.value1 + "1"))

        result = cmp(dn1, self.dn1)
        assert result == 1

        result = cmp(self.dn1, dn1)
        assert result == -1

        # Make sure dn's with more rdn's are greater
        result = cmp(self.dn1, self.dn3)
        assert result == -1
        result = cmp(self.dn3, self.dn1)
        assert result == 1


        # Test startswith, endswith
        container_dn = DN(self.container_dn)
        base_container_dn = DN(self.base_container_dn)

        assert base_container_dn.startswith(self.rdn1)
        assert base_container_dn.startswith(self.dn1)
        assert base_container_dn.startswith(self.dn1 + container_dn)
        assert not base_container_dn.startswith(self.dn2)
        assert not base_container_dn.startswith(self.rdn2)
        assert base_container_dn.startswith((self.dn1))
        assert base_container_dn.startswith((self.rdn1))
        assert not base_container_dn.startswith((self.rdn2))
        assert base_container_dn.startswith((self.rdn2, self.rdn1))
        assert base_container_dn.startswith((self.dn1, self.dn2))

        assert base_container_dn.endswith(self.base_dn)
        assert base_container_dn.endswith(container_dn + self.base_dn)
        assert not base_container_dn.endswith(DN(self.base_rdn1))
        assert base_container_dn.endswith(DN(self.base_rdn2))
        assert base_container_dn.endswith(
            (DN(self.base_rdn1), DN(self.base_rdn2)))

        # Test "in" membership
        assert self.container_rdn1 in container_dn
        # pylint: disable=comparison-with-itself
        assert container_dn in container_dn
        assert self.base_rdn1 not in container_dn

        assert self.container_rdn1 in base_container_dn
        assert container_dn in base_container_dn
        assert container_dn + self.base_dn in base_container_dn
        assert self.dn1 + container_dn + self.base_dn in base_container_dn
        assert self.dn1 + container_dn + self.base_dn == base_container_dn

        assert self.container_rdn1 not in self.base_dn

    def test_eq_multi_rdn(self):
        dn1 = DN(self.ava1, 'ST=Queensland+C=AU')
        dn2 = DN(self.ava1, 'C=AU+ST=Queensland')
        assert dn1 == dn2

        # ensure AVAs get sorted when constructing from x509.Name
        dn3 = DN(self.x500nameMultiRDN)
        dn4 = DN(self.x500nameMultiRDN2)
        assert dn3 == dn4

        # ensure AVAs get sorted in the same way regardless of what
        # the DN was constructed from
        assert dn1 == dn3
        assert dn1 == dn4
        assert dn2 == dn3
        assert dn2 == dn4

    def test_indexing(self):
        dn1 = DN(self.dn1)
        dn2 = DN(self.dn2)
        dn3 = DN(self.dn3)

        assert dn1[0] == self.rdn1
        assert dn1[self.rdn1.attr] == self.rdn1.value
        with pytest.raises(KeyError):
            dn1['foo']  # pylint: disable=pointless-statement

        assert dn2[0] == self.rdn2
        assert dn2[self.rdn2.attr] == self.rdn2.value
        with pytest.raises(KeyError):
            dn2['foo']  # pylint: disable=pointless-statement

        assert dn3[0] == self.rdn1
        assert dn3[self.rdn1.attr] == self.rdn1.value
        assert dn3[1] == self.rdn2
        assert dn3[self.rdn2.attr] == self.rdn2.value
        with pytest.raises(KeyError):
            dn3['foo']  # pylint: disable=pointless-statement

        with pytest.raises(TypeError):
            dn3[1.0]  # pylint: disable=pointless-statement

    def test_assignments(self):
        dn = DN('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=8,t=9')
        with pytest.raises(TypeError):
            # pylint: disable=unsupported-assignment-operation
            dn[0] = RDN('t=a')
        with pytest.raises(TypeError):
            # pylint: disable=unsupported-assignment-operation
            dn[0:1] = [RDN('t=a'), RDN('t=b')]

    def test_iter(self):
        dn1 = DN(self.dn1)
        dn2 = DN(self.dn2)
        dn3 = DN(self.dn3)

        assert len(dn1) == 1
        assert dn1[:] == self.rdn1
        for i, ava in enumerate(dn1):
            if i == 0:
                assert ava == self.rdn1
            else:
                pytest.fail(
                    "got iteration index %d, but len=%d" % (i, len(self.rdn1)))

        assert len(dn2) == 1
        assert dn2[:] == self.rdn2
        for i, ava in enumerate(dn2):
            if i == 0:
                assert ava == self.rdn2
            else:
                pytest.fail(
                    "got iteration index %d, but len=%d" % (i, len(self.rdn2)))

        assert len(dn3) == 2
        assert dn3[:] == DN(self.rdn1, self.rdn2)
        for i, ava in enumerate(dn3):
            if i == 0:
                assert ava == self.rdn1
            elif i == 1:
                assert ava == self.rdn2
            else:
                pytest.fail(
                    "got iteration index %d, but len=%d" % (i, len(dn3)))

    def test_concat(self):
        dn1 = DN((self.attr1, self.value1))
        dn2 = DN([self.attr2, self.value2])

        # in-place addtion

        dn1 += dn2
        assert dn1 == self.dn3
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')


        dn1 = DN((self.attr1, self.value1))
        dn1 += self.rdn2
        assert dn1 == self.dn3
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')


        dn1 = DN((self.attr1, self.value1))
        dn1 += self.dn2
        assert dn1 == self.dn3
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')


        dn1 = DN((self.attr1, self.value1))
        dn1 += self.str_dn2
        assert dn1 == self.dn3
        self.assertExpectedClass(DN, dn1, 'self')
        for i in range(0, len(dn1)):
            self.assertExpectedClass(DN, dn1[i], 'RDN')
            for j in range(0, len(dn1[i])):
                self.assertExpectedClass(DN, dn1[i][j], 'AVA')


        # concatenation
        dn1 = DN((self.attr1, self.value1))
        dn3 = dn1 + dn2
        assert dn3 == self.dn3
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            for j in range(0, len(dn3[i])):
                self.assertExpectedClass(DN, dn3[i][j], 'AVA')


        dn1 = DN((self.attr1, self.value1))
        dn3 = dn1 + self.rdn2
        assert dn3 == self.dn3
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            for j in range(0, len(dn3[i])):
                self.assertExpectedClass(DN, dn3[i][j], 'AVA')

        dn3 = dn1 + self.str_rdn2
        assert dn3 == self.dn3
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            self.assertExpectedClass(DN, dn3[i][0], 'AVA')

        dn3 = dn1 + self.str_dn2
        assert dn3 == self.dn3
        self.assertExpectedClass(DN, dn3, 'self')
        self.assertExpectedClass(DN, dn3, 'self')
        for i in range(0, len(dn3)):
            self.assertExpectedClass(DN, dn3[i], 'RDN')
            for j in range(0, len(dn3[i])):
                self.assertExpectedClass(DN, dn3[i][j], 'AVA')

        dn3 = dn1 + self.dn2
        assert dn3 == self.dn3
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
        assert dn.find(pat) == 2
        assert dn.find(pat, 1) == 2
        assert dn.find(pat, 1, 3) == 2
        assert dn.find(pat, 2, 3) == 2
        assert dn.find(pat, 6) == 6

        assert dn.find(pat, 7) == -1
        assert dn.find(pat, 1, 2) == -1

        with pytest.raises(ValueError):
            assert dn.index(pat, 7) == -1
        with pytest.raises(ValueError):
            assert dn.index(pat, 1, 2) == -1

        # reverse
        assert dn.rfind(pat) == 6
        assert dn.rfind(pat, -4) == 6
        assert dn.rfind(pat, 6) == 6
        assert dn.rfind(pat, 6, 8) == 6
        assert dn.rfind(pat, 6, 8) == 6
        assert dn.rfind(pat, -8) == 6
        assert dn.rfind(pat, -8, -4) == 6
        assert dn.rfind(pat, -8, -5) == 2

        assert dn.rfind(pat, 7) == -1
        assert dn.rfind(pat, -3) == -1

        with pytest.raises(ValueError):
            assert dn.rindex(pat, 7) == -1
        with pytest.raises(ValueError):
            assert dn.rindex(pat, -3) == -1

    def test_replace(self):
        # pylint: disable=no-member
        dn = DN('t=0,t=1,t=2,t=3,t=4,t=5,t=6,t=7,t=8,t=9')
        with pytest.raises(AttributeError):
            dn.replace  # pylint: disable=pointless-statement

    def test_hashing(self):
        # create DN's that are equal but differ in case
        dn1 = DN((self.attr1.lower(), self.value1.upper()))
        dn2 = DN((self.attr1.upper(), self.value1.lower()))

        # DNs that are equal should hash to the same value.
        assert dn1 == dn2

        # Good, everyone's equal, now verify their hash values

        assert hash(dn1) == hash(dn2)

        # Different DN objects with the same value should
        # map to 1 common key and 1 member in a set. The key and
        # member are based on the object's value.

        dn1_a = DN(self.dn1)
        dn1_b = DN(self.dn1)

        dn2_a = DN(self.dn2)
        dn2_b = DN(self.dn2)

        dn3_a = DN(self.dn3)
        dn3_b = DN(self.dn3)

        assert dn1_a == dn1_b
        assert dn2_a == dn2_b
        assert dn3_a == dn3_b

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

        assert len(d) == 2
        assert len(s) == 2
        assert sorted(d) == sorted([dn1_a, dn2_a])
        assert sorted(s) == sorted([dn1_a, dn2_a])

        assert dn1_a in d
        assert dn1_b in d
        assert dn2_a in d
        assert dn2_b in d
        assert dn3_a not in d
        assert dn3_b not in d

        assert dn1_a in s
        assert dn1_b in s
        assert dn2_a in s
        assert dn2_b in s
        assert dn3_a not in s
        assert dn3_b not in s

    def test_x500_text(self):
        # null DN x500 ordering and LDAP ordering are the same
        nulldn = DN()
        assert nulldn.ldap_text() == nulldn.x500_text()

        # reverse a DN with a single RDN
        assert self.dn1.ldap_text() == self.dn1.x500_text()

        # reverse a DN with 2 RDNs
        dn3_x500 = self.dn3.x500_text()
        dn3_rev = DN(self.rdn2, self.rdn1)
        assert dn3_rev.ldap_text() == dn3_x500

        # reverse a longer DN
        longdn_x500 = self.base_container_dn.x500_text()
        longdn_rev = DN(longdn_x500)
        l = len(self.base_container_dn)
        for i in range(l):
            assert longdn_rev[i] == self.base_container_dn[l - 1 - i]


class TestEscapes:
    @pytest.fixture(autouse=True)
    def escapes_setup(self):
        self.privilege = 'R,W privilege'
        self.dn_str_hex_escape = 'cn=R\\2cW privilege,cn=privileges,cn=pbac,dc=idm,dc=lab,dc=bos,dc=redhat,dc=com'
        self.dn_str_backslash_escape = 'cn=R\\,W privilege,cn=privileges,cn=pbac,dc=idm,dc=lab,dc=bos,dc=redhat,dc=com'

    def test_escape(self):
        dn = DN(self.dn_str_hex_escape)
        assert dn['cn'] == self.privilege
        assert dn[0].value == self.privilege

        dn = DN(self.dn_str_backslash_escape)
        assert dn['cn'] == self.privilege
        assert dn[0].value == self.privilege


class TestInternationalization:
    @pytest.fixture(autouse=True)
    def i18n_setup(self):
        # Hello in Arabic
        self.arabic_hello_utf8 = (b'\xd9\x85\xd9\x83\xd9\x8a\xd9\x84' +
                                  b'\xd8\xb9\x20\xd9\x85\xd8\xa7\xd9' +
                                  b'\x84\xd9\x91\xd8\xb3\xd9\x84\xd8\xa7')

        self.arabic_hello_unicode = self.arabic_hello_utf8.decode('utf-8')

    def assert_equal_utf8(self, obj, b):
        if six.PY2:
            assert str(obj) == b
        else:
            assert str(obj) == b.decode('utf-8')

    @contextlib.contextmanager
    def fail_py3(self, exception_type):
        try:
            yield
        except exception_type:
            if six.PY2:
                raise

    def test_i18n(self):
        actual = self.arabic_hello_unicode.encode('utf-8')
        expected = self.arabic_hello_utf8
        assert actual == expected

        # AVA's
        # test attr i18n
        ava1 = AVA(self.arabic_hello_unicode, 'foo')
        assert isinstance(ava1.attr, unicode)
        assert isinstance(ava1.value, unicode)
        assert ava1.attr == self.arabic_hello_unicode
        self.assert_equal_utf8(ava1, self.arabic_hello_utf8 + b'=foo')

        with self.fail_py3(TypeError):
            ava1 = AVA(self.arabic_hello_utf8, 'foo')
        if six.PY2:
            assert isinstance(ava1.attr, unicode)
            assert isinstance(ava1.value, unicode)
            assert ava1.attr == self.arabic_hello_unicode
            self.assert_equal_utf8(ava1, self.arabic_hello_utf8 + b'=foo')

        # test value i18n
        ava1 = AVA('cn', self.arabic_hello_unicode)
        assert isinstance(ava1.attr, unicode)
        assert isinstance(ava1.value, unicode)
        assert ava1.value == self.arabic_hello_unicode
        self.assert_equal_utf8(ava1, b'cn=' + self.arabic_hello_utf8)

        with self.fail_py3(TypeError):
            ava1 = AVA('cn', self.arabic_hello_utf8)
        if six.PY2:
            assert isinstance(ava1.attr, unicode)
            assert isinstance(ava1.value, unicode)
            assert ava1.value == self.arabic_hello_unicode
            self.assert_equal_utf8(ava1, b'cn=' + self.arabic_hello_utf8)

        # RDN's
        # test attr i18n
        rdn1 = RDN((self.arabic_hello_unicode, 'foo'))
        assert isinstance(rdn1.attr, unicode)
        assert isinstance(rdn1.value, unicode)
        assert rdn1.attr == self.arabic_hello_unicode
        self.assert_equal_utf8(rdn1, self.arabic_hello_utf8 + b'=foo')

        with self.fail_py3(TypeError):
            rdn1 = RDN((self.arabic_hello_utf8, 'foo'))
        if six.PY2:
            assert isinstance(rdn1.attr, unicode)
            assert isinstance(rdn1.value, unicode)
            assert rdn1.attr == self.arabic_hello_unicode
            assert str(rdn1) == self.arabic_hello_utf8 + b'=foo'

        # test value i18n
        rdn1 = RDN(('cn', self.arabic_hello_unicode))
        assert isinstance(rdn1.attr, unicode)
        assert isinstance(rdn1.value, unicode)
        assert rdn1.value == self.arabic_hello_unicode
        self.assert_equal_utf8(rdn1, b'cn=' + self.arabic_hello_utf8)

        with self.fail_py3(TypeError):
            rdn1 = RDN(('cn', self.arabic_hello_utf8))
        if six.PY2:
            assert isinstance(rdn1.attr, unicode)
            assert isinstance(rdn1.value, unicode)
            assert rdn1.value == self.arabic_hello_unicode
            assert str(rdn1) == b'cn=' + self.arabic_hello_utf8

        # DN's
        # test attr i18n
        dn1 = DN((self.arabic_hello_unicode, 'foo'))
        assert isinstance(dn1[0].attr, unicode)
        assert isinstance(dn1[0].value, unicode)
        assert dn1[0].attr == self.arabic_hello_unicode
        self.assert_equal_utf8(dn1, self.arabic_hello_utf8 + b'=foo')

        with self.fail_py3(TypeError):
            dn1 = DN((self.arabic_hello_utf8, 'foo'))
        if six.PY2:
            assert isinstance(dn1[0].attr, unicode)
            assert isinstance(dn1[0].value, unicode)
            assert dn1[0].attr == self.arabic_hello_unicode
            assert str(dn1) == self.arabic_hello_utf8 + b'=foo'

        # test value i18n
        dn1 = DN(('cn', self.arabic_hello_unicode))
        assert isinstance(dn1[0].attr, unicode)
        assert isinstance(dn1[0].value, unicode)
        assert dn1[0].value == self.arabic_hello_unicode
        self.assert_equal_utf8(dn1, b'cn=' + self.arabic_hello_utf8)

        with self.fail_py3(TypeError):
            dn1 = DN(('cn', self.arabic_hello_utf8))
        if six.PY2:
            assert isinstance(dn1[0].attr, unicode)
            assert isinstance(dn1[0].value, unicode)
            assert dn1[0].value == self.arabic_hello_unicode
            assert str(dn1) == b'cn=' + self.arabic_hello_utf8


# 1: LDAP_AVA_STRING
# 4: LDAP_AVA_NONPRINTABLE
@pytest.mark.parametrize(
    'dnstring,expected',
    [
        ('', []),
        ('cn=bob', [[('cn', 'bob', 1)]]),
        ('cn=Bob', [[('cn', 'Bob', 1)]]),
        (u'cn=b\xf6b', [[('cn', u'b\xf6b', 4)]]),
        ('cn=bob,sn=builder', [[('cn', 'bob', 1)], [('sn', 'builder', 1)]]),
        (u'cn=b\xf6b,sn=builder', [
            [('cn', u'b\xf6b', 4)], [('sn', 'builder', 1)]
        ]),
        ('cn=bob+sn=builder', [[('cn', 'bob', 1), ('sn', 'builder', 1)]]),
        ('dc=ipa,dc=example', [[('dc', 'ipa', 1)], [('dc', 'example', 1)]]),
        ('cn=R\\,W privilege', [[('cn', 'R,W privilege', 1)]]),
    ]
)
def test_str2dn2str(dnstring, expected):
    dn = str2dn(dnstring)
    assert dn == expected
    assert dn2str(dn) == dnstring
    assert dn_ctypes.str2dn(dnstring) == dn
    assert dn_ctypes.dn2str(dn) == dnstring


@pytest.mark.parametrize(
    'dnstring',
    [
        'cn',
        'cn=foo,',
        'cn=foo+bar',
    ]
)
def test_str2dn_errors(dnstring):
    with pytest.raises(DECODING_ERROR):
        str2dn(dnstring)
    with pytest.raises(dn_ctypes.DECODING_ERROR):
        dn_ctypes.str2dn(dnstring)


def test_dn2str_special():
    dnstring = 'cn=R\\2cW privilege'
    dnstring2 = 'cn=R\\,W privilege'
    expected = [[('cn', 'R,W privilege', 1)]]

    dn = str2dn(dnstring)
    assert dn == expected
    assert dn2str(dn) == dnstring2
    assert dn_ctypes.str2dn(dnstring) == dn
    assert dn_ctypes.dn2str(dn) == dnstring2
