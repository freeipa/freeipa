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

import datetime
import email.utils
import calendar
from ipapython.cookie import Cookie

import pytest

pytestmark = pytest.mark.tier0


class TestParse:

    def test_parse(self):
        # Empty string
        s = ''
        cookies = Cookie.parse(s)
        assert len(cookies) == 0

        # Invalid single token
        s = 'color'
        with pytest.raises(ValueError):
            cookies = Cookie.parse(s)

        # Invalid single token that's keyword
        s = 'HttpOnly'
        with pytest.raises(ValueError):
            cookies = Cookie.parse(s)

        # Invalid key/value pair whose key is a keyword
        s = 'domain=example.com'
        with pytest.raises(ValueError):
            cookies = Cookie.parse(s)

        # 1 cookie with empty value
        s = 'color='
        cookies = Cookie.parse(s)
        assert len(cookies) == 1
        cookie = cookies[0]
        assert cookie.key == 'color'
        assert cookie.value == ''
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age is None
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is None
        assert str(cookie) == "color="
        assert cookie.http_cookie() == "color=;"

        # 1 cookie with name/value
        s = 'color=blue'
        cookies = Cookie.parse(s)
        assert len(cookies) == 1
        cookie = cookies[0]
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age is None
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is None
        assert str(cookie) == "color=blue"
        assert cookie.http_cookie() == "color=blue;"

        # 1 cookie with whose value is quoted
        # Use "get by name" utility to extract specific cookie
        s = 'color="blue"'
        cookie = Cookie.get_named_cookie_from_string(s, 'color')
        assert cookie is not None, Cookie
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age is None
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is None
        assert str(cookie) == "color=blue"
        assert cookie.http_cookie() == "color=blue;"

        # 1 cookie with name/value and domain, path attributes.
        # Change up the whitespace a bit.
        s = 'color =blue; domain= example.com ; path = /toplevel '
        cookies = Cookie.parse(s)
        assert len(cookies) == 1
        cookie = cookies[0]
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain == 'example.com'
        assert cookie.path == '/toplevel'
        assert cookie.max_age is None
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is None
        assert str(cookie) == "color=blue; Domain=example.com; Path=/toplevel"
        assert cookie.http_cookie() == "color=blue;"

        # 2 cookies, various attributes
        s = 'color=blue; Max-Age=3600; temperature=hot; HttpOnly'
        cookies = Cookie.parse(s)
        assert len(cookies) == 2
        cookie = cookies[0]
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age == 3600
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is None
        assert str(cookie) == "color=blue; Max-Age=3600"
        assert cookie.http_cookie() == "color=blue;"
        cookie = cookies[1]
        assert cookie.key == 'temperature'
        assert cookie.value == 'hot'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age is None
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is True
        assert str(cookie) == "temperature=hot; HttpOnly"
        assert cookie.http_cookie() == "temperature=hot;"


class TestExpires:

    @pytest.fixture(autouse=True)
    def expires_setup(self):
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
        assert len(cookies) == 1
        cookie = cookies[0]
        # Force timestamp to known value
        cookie.timestamp = self.now
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age is None
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is None
        assert str(cookie) == "color=blue"
        assert cookie.get_expiration() is None
        # Normalize
        assert cookie.normalize_expiration() is None
        assert cookie.max_age is None
        assert cookie.expires is None
        assert str(cookie) == "color=blue"

        # 1 cookie with name/value and Max-Age
        s = 'color=blue; max-age=%d' % (self.max_age)
        cookies = Cookie.parse(s)
        assert len(cookies) == 1
        cookie = cookies[0]
        # Force timestamp to known value
        cookie.timestamp = self.now
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age == self.max_age
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is None
        assert str(cookie) == "color=blue; Max-Age=%d" % (self.max_age)
        assert cookie.get_expiration() == self.age_expiration
        # Normalize
        assert cookie.normalize_expiration() == self.age_expiration
        assert cookie.max_age is None
        assert cookie.expires == self.age_expiration
        assert str(cookie) == "color=blue; Expires=%s" % (self.age_string)


        # 1 cookie with name/value and Expires
        s = 'color=blue; Expires=%s' % (self.expires_string)
        cookies = Cookie.parse(s)
        assert len(cookies) == 1
        cookie = cookies[0]
        # Force timestamp to known value
        cookie.timestamp = self.now
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age is None
        assert cookie.expires == self.expires
        assert cookie.secure is None
        assert cookie.httponly is None
        assert str(cookie) == "color=blue; Expires=%s" % (self.expires_string)
        assert cookie.get_expiration() == self.expires
        # Normalize
        assert cookie.normalize_expiration() == self.expires
        assert cookie.max_age is None
        assert cookie.expires == self.expires
        assert str(cookie) == "color=blue; Expires=%s" % (self.expires_string)

        # 1 cookie with name/value witht both Max-Age and Expires, Max-Age takes precedence
        s = 'color=blue; Expires=%s; max-age=%d' % (self.expires_string, self.max_age)
        cookies = Cookie.parse(s)
        assert len(cookies) == 1
        cookie = cookies[0]
        # Force timestamp to known value
        cookie.timestamp = self.now
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age == self.max_age
        assert cookie.expires == self.expires
        assert cookie.secure is None
        assert cookie.httponly is None
        expected = "color=blue; Max-Age={}; Expires={}".format(
            self.max_age, self.expires_string)
        assert str(cookie) == expected
        assert cookie.get_expiration() == self.age_expiration
        # Normalize
        assert cookie.normalize_expiration() == self.age_expiration
        assert cookie.max_age is None
        assert cookie.expires == self.age_expiration
        assert str(cookie) == "color=blue; Expires=%s" % (self.age_string)

        # Verify different types can be assigned to the timestamp and
        # expires attribute.

        cookie = Cookie('color', 'blue')
        cookie.timestamp = self.now
        assert cookie.timestamp == self.now
        cookie.timestamp = self.now_timestamp
        assert cookie.timestamp == self.now
        cookie.timestamp = self.now_string
        assert cookie.timestamp == self.now

        assert cookie.expires is None

        cookie.expires = self.expires
        assert cookie.expires == self.expires
        cookie.expires = self.expires_timestamp
        assert cookie.expires == self.expires
        cookie.expires = self.expires_string
        assert cookie.expires == self.expires


class TestInvalidAttributes:
    def test_invalid(self):
        # Invalid Max-Age
        s = 'color=blue; Max-Age=over-the-hill'
        with pytest.raises(ValueError):
            Cookie.parse(s)

        cookie = Cookie('color', 'blue')
        with pytest.raises(ValueError):
            cookie.max_age = 'over-the-hill'

        # Invalid Expires
        s = 'color=blue; Expires=Sun, 06 Xxx 1994 08:49:37 GMT'
        with pytest.raises(ValueError):
            Cookie.parse(s)

        cookie = Cookie('color', 'blue')
        with pytest.raises(ValueError):
            cookie.expires = 'Sun, 06 Xxx 1994 08:49:37 GMT'


class TestAttributes:
    def test_attributes(self):
        cookie = Cookie('color', 'blue')
        assert cookie.key == 'color'
        assert cookie.value == 'blue'
        assert cookie.domain is None
        assert cookie.path is None
        assert cookie.max_age is None
        assert cookie.expires is None
        assert cookie.secure is None
        assert cookie.httponly is None

        cookie.domain = 'example.com'
        assert cookie.domain == 'example.com'
        cookie.domain = None
        assert cookie.domain is None

        cookie.path = '/toplevel'
        assert cookie.path == '/toplevel'
        cookie.path = None
        assert cookie.path is None

        cookie.max_age = 400
        assert cookie.max_age == 400
        cookie.max_age = None
        assert cookie.max_age is None

        cookie.expires = 'Sun, 06 Nov 1994 08:49:37 GMT'
        assert cookie.expires == datetime.datetime(1994, 11, 6, 8, 49, 37)
        cookie.expires = None
        assert cookie.expires is None

        cookie.secure = True
        assert cookie.secure is True
        assert str(cookie) == "color=blue; Secure"
        cookie.secure = False
        assert cookie.secure is False
        assert str(cookie) == "color=blue"
        cookie.secure = None
        assert cookie.secure is None
        assert str(cookie) == "color=blue"

        cookie.httponly = True
        assert cookie.httponly is True
        assert str(cookie) == "color=blue; HttpOnly"
        cookie.httponly = False
        assert cookie.httponly is False
        assert str(cookie) == "color=blue"
        cookie.httponly = None
        assert cookie.httponly is None
        assert str(cookie) == "color=blue"


class TestHTTPReturn:
    @pytest.fixture(autouse=True)
    def http_return_setup(self):
        self.url = 'http://www.foo.bar.com/one/two'

    def test_no_attributes(self):
        cookie = Cookie('color', 'blue')
        assert cookie.http_return_ok(self.url)

    def test_domain(self):
        cookie = Cookie('color', 'blue', domain='www.foo.bar.com')
        assert cookie.http_return_ok(self.url)

        cookie = Cookie('color', 'blue', domain='.foo.bar.com')
        assert cookie.http_return_ok(self.url)

        cookie = Cookie('color', 'blue', domain='.bar.com')
        assert cookie.http_return_ok(self.url)

        cookie = Cookie('color', 'blue', domain='bar.com')
        with pytest.raises(Cookie.URLMismatch):
            assert cookie.http_return_ok(self.url)

        cookie = Cookie('color', 'blue', domain='bogus.com')
        with pytest.raises(Cookie.URLMismatch):
            assert cookie.http_return_ok(self.url)

        cookie = Cookie('color', 'blue', domain='www.foo.bar.com')
        with pytest.raises(Cookie.URLMismatch):
            assert cookie.http_return_ok('http://192.168.1.1/one/two')

    def test_path(self):
        cookie = Cookie('color', 'blue')
        assert cookie.http_return_ok(self.url)

        cookie = Cookie('color', 'blue', path='/')
        assert cookie.http_return_ok(self.url)

        cookie = Cookie('color', 'blue', path='/one')
        assert cookie.http_return_ok(self.url)

        cookie = Cookie('color', 'blue', path='/oneX')
        with pytest.raises(Cookie.URLMismatch):
            assert cookie.http_return_ok(self.url)

    def test_expires(self):
        now = datetime.datetime.utcnow().replace(microsecond=0)

        # expires 1 day from now
        expires = now + datetime.timedelta(days=1)

        cookie = Cookie('color', 'blue', expires=expires)
        assert cookie.http_return_ok(self.url)

        # expired 1 day ago
        expires = now + datetime.timedelta(days=-1)
        cookie = Cookie('color', 'blue', expires=expires)
        with pytest.raises(Cookie.Expired):
            assert cookie.http_return_ok(self.url)


    def test_httponly(self):
        cookie = Cookie('color', 'blue', httponly=True)
        assert cookie.http_return_ok('http://example.com')
        assert cookie.http_return_ok('https://example.com')

        with pytest.raises(Cookie.URLMismatch):
            assert cookie.http_return_ok('ftp://example.com')

    def test_secure(self):
        cookie = Cookie('color', 'blue', secure=True)
        assert cookie.http_return_ok('https://Xexample.com')

        with pytest.raises(Cookie.URLMismatch):
            assert cookie.http_return_ok('http://Xexample.com')


class TestNormalization:
    @pytest.fixture(autouse=True)
    def normalization_setup(self):
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
        assert Cookie.normalize_url_path('') == '/'
        assert Cookie.normalize_url_path('foo') == '/'
        assert Cookie.normalize_url_path('foo/') == '/'
        assert Cookie.normalize_url_path('/foo') == '/'
        assert Cookie.normalize_url_path('/foo/') == '/foo'
        assert Cookie.normalize_url_path('/Foo/bar') == '/foo'
        assert Cookie.normalize_url_path('/foo/baR/') == '/foo/bar'

    def test_normalization(self):
        cookie = Cookie('color', 'blue', expires=self.expires)
        cookie.timestamp = self.now_timestamp

        assert cookie.domain is None
        assert cookie.path is None

        url = 'http://example.COM/foo'
        cookie.normalize(url)
        assert cookie.domain == 'example.com'
        assert cookie.path == '/'
        assert cookie.expires == self.expires

        cookie = Cookie('color', 'blue', max_age=self.max_age)
        cookie.timestamp = self.now_timestamp

        assert cookie.domain is None
        assert cookie.path is None

        url = 'http://example.com/foo/'
        cookie.normalize(url)
        assert cookie.domain == 'example.com'
        assert cookie.path == '/foo'
        assert cookie.expires == self.age_expiration

        cookie = Cookie('color', 'blue')
        url = 'http://example.com/foo'
        cookie.normalize(url)
        assert cookie.domain == 'example.com'
        assert cookie.path == '/'

        cookie = Cookie('color', 'blue')
        url = 'http://example.com/foo/bar'
        cookie.normalize(url)
        assert cookie.domain == 'example.com'
        assert cookie.path == '/foo'

        cookie = Cookie('color', 'blue')
        url = 'http://example.com/foo/bar/'
        cookie.normalize(url)
        assert cookie.domain == 'example.com'
        assert cookie.path == '/foo/bar'
