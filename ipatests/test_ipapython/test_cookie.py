# Authors:
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2012  Red Hat
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

import unittest
import datetime
import email.utils
import calendar
from ipapython.cookie import Cookie

import pytest

pytestmark = pytest.mark.tier0

class TestParse(unittest.TestCase):

    def test_parse(self):
        # Empty string
        s = ''
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 0)

        # Invalid single token
        s = 'color'
        with self.assertRaises(ValueError):
            cookies = Cookie.parse(s)

        # Invalid single token that's keyword
        s = 'HttpOnly'
        with self.assertRaises(ValueError):
            cookies = Cookie.parse(s)

        # Invalid key/value pair whose key is a keyword
        s = 'domain=example.com'
        with self.assertRaises(ValueError):
            cookies = Cookie.parse(s)

        # 1 cookie with empty value
        s = 'color='
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, '')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=")
        self.assertEqual(cookie.http_cookie(), "color=;")

        # 1 cookie with name/value
        s = 'color=blue'
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue")
        self.assertEqual(cookie.http_cookie(), "color=blue;")

        # 1 cookie with whose value is quoted
        # Use "get by name" utility to extract specific cookie
        s = 'color="blue"'
        cookie = Cookie.get_named_cookie_from_string(s, 'color')
        self.assertIsNotNone(cookie)
        self.assertIsNotNone(cookie, Cookie)
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue")
        self.assertEqual(cookie.http_cookie(), "color=blue;")

        # 1 cookie with name/value and domain, path attributes.
        # Change up the whitespace a bit.
        s = 'color =blue; domain= example.com ; path = /toplevel '
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, 'example.com')
        self.assertEqual(cookie.path, '/toplevel')
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue; Domain=example.com; Path=/toplevel")
        self.assertEqual(cookie.http_cookie(), "color=blue;")

        # 2 cookies, various attributes
        s = 'color=blue; Max-Age=3600; temperature=hot; HttpOnly'
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 2)
        cookie = cookies[0]
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, 3600)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue; Max-Age=3600")
        self.assertEqual(cookie.http_cookie(), "color=blue;")
        cookie = cookies[1]
        self.assertEqual(cookie.key, 'temperature')
        self.assertEqual(cookie.value, 'hot')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, True)
        self.assertEqual(str(cookie), "temperature=hot; HttpOnly")
        self.assertEqual(cookie.http_cookie(), "temperature=hot;")

class TestExpires(unittest.TestCase):

    def setUp(self):
        # Force microseconds to zero because cookie timestamps only have second resolution
        self.now = datetime.datetime.utcnow().replace(microsecond=0)
        self.now_timestamp = calendar.timegm(self.now.utctimetuple())
        self.now_string = email.utils.formatdate(self.now_timestamp, usegmt=True)

        self.max_age = 3600     # 1 hour
        self.age_expiration = self.now + datetime.timedelta(seconds=self.max_age)
        self.age_timestamp = calendar.timegm(self.age_expiration.utctimetuple())
        self.age_string = email.utils.formatdate(self.age_timestamp, usegmt=True)

        self.expires = self.now + datetime.timedelta(days=1) # 1 day
        self.expires_timestamp = calendar.timegm(self.expires.utctimetuple())
        self.expires_string = email.utils.formatdate(self.expires_timestamp, usegmt=True)

    def test_expires(self):
        # 1 cookie with name/value and no Max-Age and no Expires
        s = 'color=blue;'
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        # Force timestamp to known value
        cookie.timestamp = self.now
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue")
        self.assertEqual(cookie.get_expiration(), None)
        # Normalize
        self.assertEqual(cookie.normalize_expiration(), None)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(str(cookie), "color=blue")

        # 1 cookie with name/value and Max-Age
        s = 'color=blue; max-age=%d' % (self.max_age)
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        # Force timestamp to known value
        cookie.timestamp = self.now
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, self.max_age)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue; Max-Age=%d" % (self.max_age))
        self.assertEqual(cookie.get_expiration(), self.age_expiration)
        # Normalize
        self.assertEqual(cookie.normalize_expiration(), self.age_expiration)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, self.age_expiration)
        self.assertEqual(str(cookie), "color=blue; Expires=%s" % (self.age_string))


        # 1 cookie with name/value and Expires
        s = 'color=blue; Expires=%s' % (self.expires_string)
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        # Force timestamp to known value
        cookie.timestamp = self.now
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, self.expires)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue; Expires=%s" % (self.expires_string))
        self.assertEqual(cookie.get_expiration(), self.expires)
        # Normalize
        self.assertEqual(cookie.normalize_expiration(), self.expires)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, self.expires)
        self.assertEqual(str(cookie), "color=blue; Expires=%s" % (self.expires_string))

        # 1 cookie with name/value witht both Max-Age and Expires, Max-Age takes precedence
        s = 'color=blue; Expires=%s; max-age=%d' % (self.expires_string, self.max_age)
        cookies = Cookie.parse(s)
        self.assertEqual(len(cookies), 1)
        cookie = cookies[0]
        # Force timestamp to known value
        cookie.timestamp = self.now
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, self.max_age)
        self.assertEqual(cookie.expires, self.expires)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue; Max-Age=%d; Expires=%s" % (self.max_age, self.expires_string))
        self.assertEqual(cookie.get_expiration(), self.age_expiration)
        # Normalize
        self.assertEqual(cookie.normalize_expiration(), self.age_expiration)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, self.age_expiration)
        self.assertEqual(str(cookie), "color=blue; Expires=%s" % (self.age_string))

        # Verify different types can be assigned to the timestamp and
        # expires attribute.

        cookie = Cookie('color', 'blue')
        cookie.timestamp = self.now
        self.assertEqual(cookie.timestamp, self.now)
        cookie.timestamp = self.now_timestamp
        self.assertEqual(cookie.timestamp, self.now)
        cookie.timestamp = self.now_string
        self.assertEqual(cookie.timestamp, self.now)

        self.assertEqual(cookie.expires, None)

        cookie.expires = self.expires
        self.assertEqual(cookie.expires, self.expires)
        cookie.expires = self.expires_timestamp
        self.assertEqual(cookie.expires, self.expires)
        cookie.expires = self.expires_string
        self.assertEqual(cookie.expires, self.expires)

class TestInvalidAttributes(unittest.TestCase):
    def test_invalid(self):
        # Invalid Max-Age
        s = 'color=blue; Max-Age=over-the-hill'
        with self.assertRaises(ValueError):
            Cookie.parse(s)

        cookie = Cookie('color', 'blue')
        with self.assertRaises(ValueError):
            cookie.max_age = 'over-the-hill'

        # Invalid Expires
        s = 'color=blue; Expires=Sun, 06 Xxx 1994 08:49:37 GMT'
        with self.assertRaises(ValueError):
            Cookie.parse(s)

        cookie = Cookie('color', 'blue')
        with self.assertRaises(ValueError):
            cookie.expires = 'Sun, 06 Xxx 1994 08:49:37 GMT'


class TestAttributes(unittest.TestCase):
    def test_attributes(self):
        cookie = Cookie('color', 'blue')
        self.assertEqual(cookie.key, 'color')
        self.assertEqual(cookie.value, 'blue')
        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)
        self.assertEqual(cookie.max_age, None)
        self.assertEqual(cookie.expires, None)
        self.assertEqual(cookie.secure, None)
        self.assertEqual(cookie.httponly, None)

        cookie.domain = 'example.com'
        self.assertEqual(cookie.domain, 'example.com')
        cookie.domain = None
        self.assertEqual(cookie.domain, None)

        cookie.path = '/toplevel'
        self.assertEqual(cookie.path, '/toplevel')
        cookie.path = None
        self.assertEqual(cookie.path, None)

        cookie.max_age = 400
        self.assertEqual(cookie.max_age, 400)
        cookie.max_age = None
        self.assertEqual(cookie.max_age, None)

        cookie.expires = 'Sun, 06 Nov 1994 08:49:37 GMT'
        self.assertEqual(cookie.expires, datetime.datetime(1994, 11, 6, 8, 49, 37))
        cookie.expires = None
        self.assertEqual(cookie.expires, None)

        cookie.secure = True
        self.assertEqual(cookie.secure, True)
        self.assertEqual(str(cookie), "color=blue; Secure")
        cookie.secure = False
        self.assertEqual(cookie.secure, False)
        self.assertEqual(str(cookie), "color=blue")
        cookie.secure = None
        self.assertEqual(cookie.secure, None)
        self.assertEqual(str(cookie), "color=blue")

        cookie.httponly = True
        self.assertEqual(cookie.httponly, True)
        self.assertEqual(str(cookie), "color=blue; HttpOnly")
        cookie.httponly = False
        self.assertEqual(cookie.httponly, False)
        self.assertEqual(str(cookie), "color=blue")
        cookie.httponly = None
        self.assertEqual(cookie.httponly, None)
        self.assertEqual(str(cookie), "color=blue")


class TestHTTPReturn(unittest.TestCase):
    def setUp(self):
        self.url = 'http://www.foo.bar.com/one/two'

    def test_no_attributes(self):
        cookie = Cookie('color', 'blue')
        self.assertTrue(cookie.http_return_ok(self.url))

    def test_domain(self):
        cookie = Cookie('color', 'blue', domain='www.foo.bar.com')
        self.assertTrue(cookie.http_return_ok(self.url))

        cookie = Cookie('color', 'blue', domain='.foo.bar.com')
        self.assertTrue(cookie.http_return_ok(self.url))

        cookie = Cookie('color', 'blue', domain='.bar.com')
        self.assertTrue(cookie.http_return_ok(self.url))

        cookie = Cookie('color', 'blue', domain='bar.com')
        with self.assertRaises(Cookie.URLMismatch):
            self.assertTrue(cookie.http_return_ok(self.url))

        cookie = Cookie('color', 'blue', domain='bogus.com')
        with self.assertRaises(Cookie.URLMismatch):
            self.assertTrue(cookie.http_return_ok(self.url))

        cookie = Cookie('color', 'blue', domain='www.foo.bar.com')
        with self.assertRaises(Cookie.URLMismatch):
            self.assertTrue(cookie.http_return_ok('http://192.168.1.1/one/two'))

    def test_path(self):
        cookie = Cookie('color', 'blue')
        self.assertTrue(cookie.http_return_ok(self.url))

        cookie = Cookie('color', 'blue', path='/')
        self.assertTrue(cookie.http_return_ok(self.url))

        cookie = Cookie('color', 'blue', path='/one')
        self.assertTrue(cookie.http_return_ok(self.url))

        cookie = Cookie('color', 'blue', path='/oneX')
        with self.assertRaises(Cookie.URLMismatch):
            self.assertTrue(cookie.http_return_ok(self.url))

    def test_expires(self):
        now = datetime.datetime.utcnow().replace(microsecond=0)

        # expires 1 day from now
        expires = now + datetime.timedelta(days=1)

        cookie = Cookie('color', 'blue', expires=expires)
        self.assertTrue(cookie.http_return_ok(self.url))

        # expired 1 day ago
        expires = now + datetime.timedelta(days=-1)
        cookie = Cookie('color', 'blue', expires=expires)
        with self.assertRaises(Cookie.Expired):
            self.assertTrue(cookie.http_return_ok(self.url))


    def test_httponly(self):
        cookie = Cookie('color', 'blue', httponly=True)
        self.assertTrue(cookie.http_return_ok('http://example.com'))
        self.assertTrue(cookie.http_return_ok('https://example.com'))

        with self.assertRaises(Cookie.URLMismatch):
            self.assertTrue(cookie.http_return_ok('ftp://example.com'))

    def test_secure(self):
        cookie = Cookie('color', 'blue', secure=True)
        self.assertTrue(cookie.http_return_ok('https://Xexample.com'))

        with self.assertRaises(Cookie.URLMismatch):
            self.assertTrue(cookie.http_return_ok('http://Xexample.com'))

class TestNormalization(unittest.TestCase):
    def setUp(self):
        # Force microseconds to zero because cookie timestamps only have second resolution
        self.now = datetime.datetime.utcnow().replace(microsecond=0)
        self.now_timestamp = calendar.timegm(self.now.utctimetuple())
        self.now_string = email.utils.formatdate(self.now_timestamp, usegmt=True)

        self.max_age = 3600     # 1 hour
        self.age_expiration = self.now + datetime.timedelta(seconds=self.max_age)
        self.age_timestamp = calendar.timegm(self.age_expiration.utctimetuple())
        self.age_string = email.utils.formatdate(self.age_timestamp, usegmt=True)

        self.expires = self.now + datetime.timedelta(days=1) # 1 day
        self.expires_timestamp = calendar.timegm(self.expires.utctimetuple())
        self.expires_string = email.utils.formatdate(self.expires_timestamp, usegmt=True)

    def test_path_normalization(self):
        self.assertEqual(Cookie.normalize_url_path(''),          '/')
        self.assertEqual(Cookie.normalize_url_path('foo'),       '/')
        self.assertEqual(Cookie.normalize_url_path('foo/'),      '/')
        self.assertEqual(Cookie.normalize_url_path('/foo'),      '/')
        self.assertEqual(Cookie.normalize_url_path('/foo/'),     '/foo')
        self.assertEqual(Cookie.normalize_url_path('/Foo/bar'),  '/foo')
        self.assertEqual(Cookie.normalize_url_path('/foo/baR/'), '/foo/bar')

    def test_normalization(self):
        cookie = Cookie('color', 'blue', expires=self.expires)
        cookie.timestamp = self.now_timestamp

        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)

        url = 'http://example.COM/foo'
        cookie.normalize(url)
        self.assertEqual(cookie.domain, 'example.com')
        self.assertEqual(cookie.path, '/')
        self.assertEqual(cookie.expires, self.expires)

        cookie = Cookie('color', 'blue', max_age=self.max_age)
        cookie.timestamp = self.now_timestamp

        self.assertEqual(cookie.domain, None)
        self.assertEqual(cookie.path, None)

        url = 'http://example.com/foo/'
        cookie.normalize(url)
        self.assertEqual(cookie.domain, 'example.com')
        self.assertEqual(cookie.path, '/foo')
        self.assertEqual(cookie.expires, self.age_expiration)

        cookie = Cookie('color', 'blue')
        url = 'http://example.com/foo'
        cookie.normalize(url)
        self.assertEqual(cookie.domain, 'example.com')
        self.assertEqual(cookie.path, '/')

        cookie = Cookie('color', 'blue')
        url = 'http://example.com/foo/bar'
        cookie.normalize(url)
        self.assertEqual(cookie.domain, 'example.com')
        self.assertEqual(cookie.path, '/foo')

        cookie = Cookie('color', 'blue')
        url = 'http://example.com/foo/bar/'
        cookie.normalize(url)
        self.assertEqual(cookie.domain, 'example.com')
        self.assertEqual(cookie.path, '/foo/bar')


#-------------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()
