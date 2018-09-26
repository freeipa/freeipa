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

import re
import datetime
import email.utils
from calendar import timegm

# pylint: disable=import-error
from six.moves.urllib.parse import urlparse
# pylint: enable=import-error

'''
Core Python has two cookie libraries, Cookie.py targeted to server
side and cookielib.py targeted to client side. So why this module and
not use the standard libraries?

Cookie.py has some serious bugs, it cannot correctly parse the
HttpOnly, Secure, and Expires cookie attributes (more of a client side
need and not what it was designed for). Since we utilize those
attributes that makes Cookie.py a non-starter. Plus it's API awkard
and limited (we would have to build more on top of it).

The Cookie.py bug reports are:

http://bugs.python.org/issue3073
http://bugs.python.org/issue16611

cookielib.py has a lot of good featuress, a nice API and covers all
the relevant RFC's as well as actual practice in the field. However
cookielib.py is tighly integrated with urllib2 and it's not possible
to use most of the features of cookielib without simultaneously using
urllib2. Unfortunataely we only use httplib because of our dependency
on xmlrpc.client. Without urllib2 cookielib is a non-starter.

This module is a minimal implementation of Netscape cookies which
works equally well on either the client or server side. It's API is
easy to use with cookie attributes as class properties which can be
read or set easily. The Cookie object automatically converts Expires
and Max-Age attributes into datetime objects for easy time
comparision. Cookies in strings can easily be parsed, including
multiple cookies in the HTTP_COOKIE envionment variable.

The cookie RFC is silent on any escaping requirements for cookie
contents as such this module does not provide any automated support
escaping and unescapin.

'''

#-------------------------------------------------------------------------------


class Cookie:
    '''
    A Cookie object has the following attributes:

        key
            The name of the cookie
        value
            The value of the cookie

    A Cookie also supports these predefined optional attributes. If an
    optional attribute is not set on the cookie it's value is None.

        domain
            Restrict cookie usage to this domain
        path
            Restrict cookie usage to this path or below
        expires
            Cookie is invalid after this UTC timestamp
        max_age
            Cookie is invalid this many seconds in the future.
            Has precedence over the expires attribute.
        secure
            Cookie should only be returned on secure (i.e. SSL/TLS)
            connections.
        httponly
            Cookie is intended only for HTTP communication, it can
            never be utilized in any other context (e.g. browser
            Javascript).

    See the documentation of get_expiration() for an explanation of
    how the expires and max-age attributes interact as well as the
    role of the timestamp attribute. Expiration values are stored as
    datetime objects for easy manipulation and comparision.

    There are two ways to instantiate a Cookie object. Either directly
    via the constructor or by calling the class function parse() which
    returns a list of Cookie objects found in a string.

    To create a cookie to sent to a client:

    Example:

    cookie = Cookie('session', session_id,
                    domain=my_domain, path=mypath,
                    httponly=True, secure=True, expires=expiration)
    headers.append(('Set-Cookie', str(cookie)))


    To receive cookies from a request:

    Example:

    cookies = Cookie.parse(response.getheader('Set-Cookie'), request_url)

    '''

    class Expired(ValueError):
        pass

    class URLMismatch(ValueError):
        pass

    # regexp to split fields at a semi-colon
    field_re = re.compile(r';\s*')

    # regexp to locate a key/value pair
    kv_pair_re = re.compile(r'^\s*([a-zA-Z0-9\!\#\$\%\&\'\*\+\-\.\^\_\`\|\~]+)\s*=\s*(.*?)\s*$', re.IGNORECASE)

    # Reserved attribute names, maps from lower case protocol name to
    # object attribute name
    attrs = {'domain'   : 'domain',
             'path'     : 'path',
             'max-age'  : 'max_age',
             'expires'  : 'expires',
             'secure'   : 'secure',
             'httponly' : 'httponly'}

    @classmethod
    def datetime_to_time(cls, dt):
        '''
        Timestamps (timestamp & expires) are stored as datetime
        objects in UTC.  It's non-obvious how to convert a naive UTC
        datetime into a unix time value (seconds since the epoch
        UTC). That functionality is oddly missing from the datetime
        and time modules. This utility provides that missing
        functionality.
        '''
        # Use timegm from the calendar module
        return timegm(dt.utctimetuple())

    @classmethod
    def datetime_to_string(cls, dt=None):
        '''
        Given a datetime object in UTC generate RFC 1123 date string.
        '''

        # Try to verify dt is specified as UTC. If utcoffset is not
        # available we'll just have to assume the caller is using the
        # correct timezone.
        utcoffset = dt.utcoffset()
        if utcoffset is not None and utcoffset.total_seconds() != 0.0:
            raise ValueError("timezone is not UTC")

        # Do not use strftime because it respects the locale, instead
        # use the RFC 1123 formatting function which uses only English

        return email.utils.formatdate(cls.datetime_to_time(dt), usegmt=True)

    @classmethod
    def parse_datetime(cls, s):
        '''
        Parse a RFC 822, RFC 1123 date string, return a datetime naive object in UTC.
        '''

        s = s.strip()

        # Do not use strptime because it respects the locale, instead
        # use the RFC 1123 parsing function which uses only English

        try:
            dt = datetime.datetime(*email.utils.parsedate(s)[0:6])
        except Exception as e:
            raise ValueError("unable to parse expires datetime '%s': %s" % (s, e))

        return dt

    @classmethod
    def normalize_url_path(cls, url_path):
        '''
        Given a URL path, possibly empty, return a path consisting
        only of directory components. The URL path must end with a
        trailing slash for the last path element to be considered a
        directory. Also the URL path must begin with a slash. Empty
        input returns '/'.

        Examples:

        ''          -> '/'
        '/'         -> '/'
        'foo'       -> '/'
        'foo/'      -> '/'
        '/foo       -> '/'
        '/foo/'     -> '/foo'
        '/foo/bar'  -> '/foo'
        '/foo/bar/' -> '/foo/bar'
        '''
        url_path = url_path.lower()

        if not url_path:
            return '/'

        if not url_path.startswith('/'):
            return '/'

        if url_path.count('/') <= 1:
            return'/'

        return url_path[:url_path.rindex('/')]


    @classmethod
    def parse(cls, cookie_string, request_url=None):
        '''
        Given a string containing one or more cookies (the
        HTTP_COOKIES environment variable typically contains multiple
        cookies) parse the string and return a list of Cookie objects
        found in the string.
        '''

        # Our list of returned cookies
        cookies = []

        # Split the input string at semi-colon boundaries, we call this a
        # field. A field may either be a single keyword or a key=value
        # pair.
        fields = Cookie.field_re.split(cookie_string)

        # The input string may have multiple cookies inside it. This is
        # common when the string comes from a HTTP_COOKIE environment
        # variable. All the cookies will be contenated, separated by a
        # semi-colon. Semi-colons are also the separator between
        # attributes in a cookie.
        #
        # To distinguish between two adjacent cookies in a string we
        # have to locate the key=value pair at the start of a
        # cookie. Unfortunately cookies have attributes that also look
        # like key/value pairs, the only way to distinguish a cookie
        # attribute from a cookie is the fact the attribute names are
        # reserved. A cookie attribute may either be a key/value pair
        # or a single key (e.g. HttpOnly). As we scan the cookie we
        # first identify the key=value (cookie name, cookie
        # value). Then we continue scanning, if a bare key or
        # key/value pair follows and is a known reserved keyword than
        # that's an attribute belonging to the current cookie. As soon
        # as we see a key/value pair whose key is not reserved we know
        # we've found a new cookie. Bare keys (no value) can never
        # start a new cookie.

        # Iterate over all the fields and emit a new cookie whenever the
        # next field is not a known attribute.
        cookie = None
        for field in fields:
            match = Cookie.kv_pair_re.search(field)
            if match:
                key = match.group(1)
                value = match.group(2)

                # Double quoted value?
                if value and value[0] == '"':
                    if value[-1] == '"':
                        value = value[1:-1]
                    else:
                        raise ValueError("unterminated quote in '%s'" % value)
                kv_pair = True
            else:
                key = field
                value = True        # True because bare keys are boolean flags
                kv_pair = False

            is_attribute = key.lower() in Cookie.attrs

            # First cookie found, create new cookie object
            if cookie is None and kv_pair and not is_attribute:
                cookie = Cookie(key, value)

            # If start of new cookie then flush previous cookie and create
            # a new one (it's a new cookie because it's a key/value pair
            # whose key is not a reserved keyword).
            elif cookie and kv_pair and not is_attribute:
                if request_url is not None:
                    cookie.normalize(request_url)
                cookies.append(cookie)
                cookie = Cookie(key, value)

            # If it's a reserved keyword add that as an attribute to the
            # current cookie being scanned.
            elif cookie and is_attribute:
                cookie.__set_attr(key, value)
            # If we've found a non-empty single token that's not a
            # reserved keyword it's an error. An empty token can occur
            # when there are two adjacent semi-colons (i.e. "; ;").
            # We don't consider empty tokens an error.
            elif key:
                raise ValueError("unknown cookie token '%s'" % key)

        # Flush out final cookie
        if cookie:
            if request_url is not None:
                cookie.normalize(request_url)
            cookies.append(cookie)

        return cookies

    @classmethod
    def get_named_cookie_from_string(cls, cookie_string, cookie_name,
                                     request_url=None, timestamp=None):
        '''
        A cookie string may contain multiple cookies, parse the cookie
        string and return the last cookie in the string matching the
        cookie name or None if not found.

        This is basically a utility wrapper around the parse() class
        method which iterates over what parse() returns looking for
        the specific cookie.

        When cookie_name appears more than once the last instance is
        returned rather than the first because the ordering sequence
        makes the last instance the current value.
        '''

        target_cookie = None

        cookies = cls.parse(cookie_string)
        for cookie in cookies:
            if cookie.key == cookie_name:
                target_cookie = cookie

        if timestamp is not None:
            target_cookie.timestamp = timestamp
        if request_url is not None:
            target_cookie.normalize(request_url)
        return target_cookie


    def __init__(self, key, value, domain=None, path=None, max_age=None, expires=None,
                 secure=None, httponly=None, timestamp=None):
        self.key = key
        self.value = value
        self.domain = domain
        self.path = path
        self.max_age = max_age
        self.expires = expires
        self.secure = secure
        self.httponly = httponly
        self.timestamp = timestamp

    @property
    def timestamp(self):
        '''
        The UTC moment at which cookie was received for purposes of
        computing the expiration given a Max-Age offset. The
        expiration will be timestamp + max_age. The timestamp value
        will aways be a datetime object.

        By default the timestamp will be the moment the Cookie object
        is created as this often corresponds to the moment the cookie
        is received (the intent of the Max-Age attribute). But becuase
        it's sometimes desirable to force a specific moment for
        purposes of computing the expiration from the Max-Age the
        Cookie timestamp can be updated.

        Setting a value of None causes the timestamp to be set to the
        current UTC time (now). You may also assign with a numeric
        UNIX timestamp (seconds since the epoch UTC) or a formatted time
        sting, in all cases the value will be converted to a datetime
        object.
        '''
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        if value is None:
            self._timestamp = None
        elif isinstance(value, datetime.datetime):
            self._timestamp = value
        elif isinstance(value, (int, float)):
            self._timestamp = datetime.datetime.utcfromtimestamp(value)
        elif isinstance(value, str):
            self._timestamp = Cookie.parse_datetime(value)
        else:
            raise TypeError('value must be datetime, int, long, float, basestring or None, not %s' % \
                            value.__class__.__name__)

    @property
    def expires(self):
        '''
        The expiration timestamp (in UTC) as a datetime object for the
        cookie, or None if not set.

        You may assign a value of None, a datetime object, a numeric
        UNIX timestamp (seconds since the epoch UTC) or formatted time
        string (the latter two will be converted to a datetime object.
        '''
        return self._expires

    @expires.setter
    def expires(self, value):
        if value is None:
            self._expires = None
        elif isinstance(value, datetime.datetime):
            self._expires = value
        elif isinstance(value, (int, float)):
            self._expires = datetime.datetime.utcfromtimestamp(value)
        elif isinstance(value, str):
            self._expires = Cookie.parse_datetime(value)
        else:
            raise TypeError('value must be datetime, int, long, float, basestring or None, not %s' % \
                            value.__class__.__name__)

    @property
    def max_age(self):
        '''
        The lifetime duration of the cookie. Computed as an offset
        from the cookie's timestamp.
        '''
        return self._max_age

    @max_age.setter
    def max_age(self, value):
        if value is None:
            self._max_age = None
        else:
            try:
                self._max_age = int(value)
            except Exception:
                raise ValueError("Max-Age value '%s' not convertable to integer" % value)

    def __set_attr(self, name, value):
        '''
        Sets one of the predefined cookie attributes.
        '''
        attr_name = Cookie.attrs.get(name.lower(), None)
        if attr_name is None:
            raise ValueError("unknown cookie attribute '%s'" % name)
        setattr(self, attr_name, value)

    def __str__(self):
        components = []

        components.append("%s=%s" % (self.key, self.value))

        if self.domain is not None:
            components.append("Domain=%s" % self.domain)

        if self.path is not None:
            components.append("Path=%s" % self.path)

        if self.max_age is not None:
            components.append("Max-Age=%s" % self.max_age)

        if self.expires is not None:
            components.append("Expires=%s" % Cookie.datetime_to_string(self.expires))

        if self.secure:
            components.append("Secure")

        if self.httponly:
            components.append("HttpOnly")

        return '; '.join(components)

    def get_expiration(self):
        '''
        Return the effective expiration of the cookie as a datetime
        object or None if no expiration is defined. Expiration may be
        defined either by the "Expires" timestamp attribute or the
        "Max-Age" duration attribute. If both are set "Max-Age" takes
        precedence. If neither is set the cookie has no expiration and
        None will be returned.

        "Max-Age" specifies the number of seconds in the future from when the
        cookie is received until it expires. Effectively it means
        adding "Max-Age" seconds to a timestamp to arrive at an
        expiration. By default the timestamp used to mark the arrival
        of the cookie is set to the moment the cookie object is
        created. However sometimes it is desirable to adjust the
        received timestamp to something other than the moment of
        object creation, therefore you can explicitly set the arrival
        timestamp used in the "Max-Age" calculation.

        "Expires" specifies an explicit timestamp.

        If "Max-Age" is set a datetime object is returned which is the
        sum of the arrival timestamp and "Max-Age".

        If "Expires" is set a datetime object is returned matching the
        timestamp specified as the "Expires" value.

        If neither is set None is returned.
        '''

        if self.max_age is not None:
            return self.timestamp + datetime.timedelta(seconds=self.max_age)

        if self.expires is not None:
            return self.expires

        return None

    def normalize_expiration(self):
        '''
        An expiration may be specified either with an explicit
        timestamp in the "Expires" attribute or via an offset
        specified witht the "Max-Age" attribute. The "Max-Age"
        attribute has precedence over "Expires" if both are
        specified.

        This method normalizes the expiration of the cookie such that
        only a "Expires" attribute remains after consideration of the
        "Max-Age" attribute. This is useful when storing the cookie
        for future reference.
        '''

        self.expires = self.get_expiration()
        self.max_age = None
        return self.expires

    def set_defaults_from_url(self, url):
        '''
        If cookie domain and path attributes are not specified then
        they assume defaults from the request url the cookie was
        received from.
        '''

        _scheme, domain, path, _params, _query, _fragment = urlparse(url)

        if self.domain is None:
            self.domain = domain.lower()

        if self.path is None:
            self.path = self.normalize_url_path(path)


    def normalize(self, url):
        '''
        Missing cookie attributes will receive default values derived
        from the request URL. The expiration value is normalized.
        '''

        self.set_defaults_from_url(url)
        self.normalize_expiration()

    def http_cookie(self):
        '''
        Return a string with just the key and value (no attributes).
        This is appropriate for including in a HTTP Cookie header.
        '''
        return '%s=%s;' % (self.key, self.value)

    def http_return_ok(self, url):
        '''
        Tests to see if a cookie should be returned when a request is
        sent to a specific URL.

        * The request url's host must match the cookie's doman
          otherwise raises Cookie.URLMismatch.

        * The path in the request url must contain the cookie's path
          otherwise raises Cookie.URLMismatch.

        * If the cookie defines an expiration date then the current
          time must be less or equal to the cookie's expiration
          timestamp. Will raise Cookie.Expired if a defined expiration
          is not valid.

        If the test fails Cookie.Expired or Cookie.URLMismatch will be raised,
        otherwise True is returned.

        '''

        def domain_valid(url_domain, cookie_domain):
            '''
            Compute domain component and perform test per
            RFC 6265, Section 5.1.3. "Domain Matching"
            '''
            # FIXME: At the moment we can't import from ipalib at the
            # module level because of a dependency loop (cycle) in the
            # import. Our module layout needs to be refactored.
            # pylint: disable=ipa-forbidden-import
            from ipalib.util import validate_domain_name
            # pylint: enable=ipa-forbidden-import
            try:
                validate_domain_name(url_domain)
            except Exception:
                return False

            if cookie_domain is None:
                return True

            url_domain = url_domain.lower()
            cookie_domain = cookie_domain.lower()

            if url_domain == cookie_domain:
                return True

            if url_domain.endswith(cookie_domain):
                if cookie_domain.startswith('.'):
                    return True

            return False

        def path_valid(url_path, cookie_path):
            '''
            Compute path component and perform test per
            RFC 6265, Section 5.1.4. "Paths and Path-Match"
            '''

            if cookie_path is None:
                return True

            cookie_path = cookie_path.lower()
            request_path = self.normalize_url_path(url_path)

            if cookie_path == request_path:
                return True

            if cookie_path and request_path.startswith(cookie_path):
                if cookie_path.endswith('/'):
                    return True

                tail = request_path[len(cookie_path):]
                if tail.startswith('/'):
                    return True

            return False

        cookie_name = self.key

        (
            url_scheme, url_domain, url_path,
            _url_params, _url_query, _url_fragment
        ) = urlparse(url)

        cookie_expiration = self.get_expiration()
        if cookie_expiration is not None:
            now = datetime.datetime.utcnow()
            if cookie_expiration < now:
                raise Cookie.Expired("cookie named '%s'; expired at %s'" % \
                                     (cookie_name,
                                      self.datetime_to_string(cookie_expiration)))

        if not domain_valid(url_domain, self.domain):
            raise Cookie.URLMismatch("cookie named '%s'; it's domain '%s' does not match URL domain '%s'" % \
                                  (cookie_name, self.domain, url_domain))

        if not path_valid(url_path, self.path):
            raise Cookie.URLMismatch("cookie named '%s'; it's path '%s' does not contain the URL path '%s'" % \
                                  (cookie_name, self.path, url_path))

        url_scheme = url_scheme.lower()

        if self.httponly:
            if url_scheme not in ('http', 'https'):
                raise Cookie.URLMismatch("cookie named '%s'; is restricted to HTTP but it's URL scheme is '%s'" % \
                                         (cookie_name, url_scheme))

        if self.secure:
            if url_scheme not in ('https',):
                raise Cookie.URLMismatch("cookie named '%s'; is restricted to secure transport but it's URL scheme is '%s'" % \
                                         (cookie_name, url_scheme))


        return True
