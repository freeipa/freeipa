#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Test LDAPClient.find_entries() and iter_entries() against a fake
python-ldap connection.

No server is needed. The fake follows python-ldap: search_ext() returns
a message id, result3() hands out the entries one by one and then the
SearchResultDone with its response controls, and server limits are
raised from result3() at the SearchResultDone, after some entries of
the page have been received.
"""

from unittest import mock

import ldap
from ldap.controls import SimplePagedResultsControl
from ldap.controls.simple import GetEffectiveRightsControl
import pytest

from ipalib import errors
from ipapython import ipaldap
from ipapython.dn import DN

BASE = "cn=users,cn=accounts,dc=example,dc=test"


def ldap_error(exc_class):
    return exc_class({"desc": "limit exceeded", "info": ""})


def make_entries(count):
    """Return (dn, attrs) tuples as python-ldap returns them."""
    return [
        ("uid=user%d,%s" % (i, BASE), {"uid": [b"user%d" % i]})
        for i in range(count)
    ]


class FakeLDAPConnection:
    """Stand-in for ldap.ldapobject.LDAPObject, with a tiny server.

    entries: what the server holds for any search.
    limits: {request index: (exception class, entries delivered before
            the exception is raised from result3())}.
    failures: {request index: exception class}, raised from result3()
            before any entry of that request is delivered.
    paged_results: whether the server supports the paged results
            control. Cookies are bytes, as python-ldap decodes them.

    Everything the client does is recorded: requests (one dict per
    search_ext()), cancel_requests (the same for the cancels of paged
    searches, sent with search_ext_s()), cancels (their cookies) and
    result3_calls.
    """

    def __init__(
        self,
        entries=(),
        limits=None,
        failures=None,
        paged_results=True,
        referrals=(),
    ):
        self.entries = list(entries)
        self.limits = limits or {}
        self.failures = failures or {}
        self.paged_results = paged_results
        self.referrals = list(referrals)
        self.requests = []
        self.cancel_requests = []
        self.result3_calls = 0
        self._messages = {}

    @property
    def cancels(self):
        """Cookies of the paged searches that were cancelled."""
        return [r["cookie"] for r in self.cancel_requests]

    def whoami_s(self):
        return "dn: uid=admin,%s" % BASE

    def search_ext(
        self,
        base,
        scope,
        filterstr=None,
        attrlist=None,
        attrsonly=0,
        serverctrls=None,
        clientctrls=None,
        timeout=-1,
        sizelimit=0,
    ):
        request = self._request(
            base, scope, filterstr, attrlist, serverctrls, timeout, sizelimit
        )
        index = len(self.requests)
        self.requests.append(request)
        msgid = index + 1
        self._messages[msgid] = self._reply(index, self._paged(serverctrls))
        return msgid

    @staticmethod
    def _paged(serverctrls):
        return [
            c
            for c in serverctrls or []
            if isinstance(c, SimplePagedResultsControl)
        ]

    def _request(
        self, base, scope, filterstr, attrlist, serverctrls, timeout, sizelimit
    ):
        paged = self._paged(serverctrls)
        return {
            "base": base,
            "scope": scope,
            "filterstr": filterstr,
            "attrlist": attrlist,
            "timeout": timeout,
            "sizelimit": sizelimit,
            "page_size": paged[0].size if paged else None,
            "critical": paged[0].criticality if paged else None,
            "cookie": paged[0].cookie if paged else None,
            "has_effective_rights": any(
                isinstance(c, GetEffectiveRightsControl)
                for c in serverctrls or []
            ),
        }

    def _reply(self, index, paged):
        """Build the messages the server sends for request number index."""
        if paged and self.paged_results:
            start = int(paged[0].cookie or 0)
            end = start + paged[0].size
            page = self.entries[start:end]
            more = end < len(self.entries)
            done = [
                SimplePagedResultsControl(
                    False, 0, b"%d" % end if more else b""
                )
            ]
        else:
            page = self.entries
            done = []

        messages = []
        for entry in page:
            messages.append((ldap.RES_SEARCH_ENTRY, [entry], []))
        if self.referrals and index == 0:
            messages.append(
                (ldap.RES_SEARCH_REFERENCE, [(None, self.referrals)], [])
            )

        if index in self.failures:
            messages = [("raise", ldap_error(self.failures[index]))]
        elif index in self.limits:
            exc_class, delivered = self.limits[index]
            messages = messages[:delivered]
            messages.append(("raise", ldap_error(exc_class)))
        else:
            messages.append((ldap.RES_SEARCH_RESULT, [], done))
        return messages

    def result3(self, msgid, all=1, timeout=None):
        """Return one message, or with all true, all up to the last."""
        self.result3_calls += 1
        messages = self._messages[msgid]
        collected = []
        while True:
            message = messages.pop(0)
            if message[0] == "raise":
                raise message[1]
            objtype, res_list, ctrls = message
            if not all or objtype == ldap.RES_SEARCH_RESULT:
                break
            collected.extend(res_list)
        if all:
            return objtype, collected, msgid, ctrls
        return objtype, res_list, msgid, ctrls

    def search_ext_s(
        self,
        base,
        scope,
        filterstr=None,
        attrlist=None,
        attrsonly=0,
        serverctrls=None,
        clientctrls=None,
        timeout=-1,
        sizelimit=0,
    ):
        """Only the cancel of a paged search is sent synchronously."""
        request = self._request(
            base, scope, filterstr, attrlist, serverctrls, timeout, sizelimit
        )
        assert request["page_size"] == 0
        self.cancel_requests.append(request)
        return []


def make_client(conn):
    with mock.patch.object(ipaldap, "ldap_initialize", return_value=conn):
        return ipaldap.LDAPClient("ldap://ipa.example.test", no_schema=True)


def find(client, **kwargs):
    kwargs.setdefault("base_dn", DN(BASE))
    return client.find_entries(**kwargs)


def uids(entries):
    return [entry.dn[0]["uid"] for entry in entries]


def test_no_match_raises_empty_result():
    """No entry and no limit hit: EmptyResult."""
    client = make_client(FakeLDAPConnection())
    with pytest.raises(errors.EmptyResult):
        find(client)


def test_no_match_with_limit_hit_returns_flag_not_error():
    """No entry but a limit hit: empty list and the flag."""
    conn = FakeLDAPConnection(limits={0: (ldap.TIMELIMIT_EXCEEDED, 0)})
    entries, truncated = find(make_client(conn))
    assert entries == []
    assert truncated is ipaldap.TRUNCATED_TIME_LIMIT


def test_unpaged_search_by_default_returns_everything_in_one_request():
    """paged_search defaults to False: one request, no paging control."""
    conn = FakeLDAPConnection(make_entries(3))
    entries, truncated = find(make_client(conn))
    assert uids(entries) == ["user0", "user1", "user2"]
    assert truncated is False
    assert len(conn.requests) == 1
    assert conn.requests[0]["page_size"] is None


def test_paged_search_one_page_makes_one_request():
    """Fewer entries than a page: a single request, nothing to cancel."""
    conn = FakeLDAPConnection(make_entries(3))
    entries, truncated = find(make_client(conn), paged_search=True)
    assert uids(entries) == ["user0", "user1", "user2"]
    assert truncated is False
    assert [r["cookie"] for r in conn.requests] == [""]
    assert [r["critical"] for r in conn.requests] == [False]
    assert conn.cancels == []


def test_paged_search_without_size_limit_uses_pages_of_1999():
    """With no size limit a page is 2000 - 1 entries."""
    conn = FakeLDAPConnection(make_entries(4000))
    entries, truncated = find(make_client(conn), paged_search=True)
    assert len(entries) == 4000
    assert uids(entries)[:2] == ["user0", "user1"]
    assert uids(entries)[-1] == "user3999"
    assert truncated is False
    assert [r["page_size"] for r in conn.requests] == [1999] * 3
    assert [r["cookie"] for r in conn.requests] == ["", b"1999", b"3998"]
    assert conn.cancels == []


@pytest.mark.parametrize(
    "size_limit, page_size",
    [
        (0, 1999),
        (-1, 1999),
        (-1.0, 1999),
        (1, None),
        (2, 1),
        (3, 2),
        (10, 9),
    ],
)
def test_page_size_for_size_limit(size_limit, page_size):
    """The page is one less than size_limit; unpaged if that is 0.

    A negative or zero size_limit means no limit: pages of 1999. The
    float -1.0 is what ldap2 holds after a disconnect.
    """
    conn = FakeLDAPConnection(make_entries(3))
    client = make_client(conn)
    client.size_limit = size_limit
    find(client, paged_search=True)
    assert conn.requests
    assert {r["page_size"] for r in conn.requests} == {page_size}


@pytest.mark.parametrize(
    "exc_class, flag",
    [
        (ldap.SIZELIMIT_EXCEEDED, ipaldap.TRUNCATED_SIZE_LIMIT),
        (ldap.TIMELIMIT_EXCEEDED, ipaldap.TRUNCATED_TIME_LIMIT),
        (ldap.ADMINLIMIT_EXCEEDED, ipaldap.TRUNCATED_ADMIN_LIMIT),
    ],
)
class TestTruncation:

    def test_limit_on_later_page_keeps_earlier_pages_and_flag(
        self, exc_class, flag
    ):
        """A limit on page 2 keeps page 1 and what arrived of page 2."""
        conn = FakeLDAPConnection(make_entries(6), limits={1: (exc_class, 1)})
        entries, truncated = find(
            make_client(conn), paged_search=True, size_limit=4
        )
        assert uids(entries) == ["user0", "user1", "user2", "user3"]
        assert truncated is flag
        assert len(conn.requests) == 2


def test_error_on_later_page_cancels_paged_search_with_cookie():
    """A non-limit error on page 2 cancels with the cookie of page 1."""
    conn = FakeLDAPConnection(
        make_entries(6), failures={1: ldap.INSUFFICIENT_ACCESS}
    )
    with pytest.raises(errors.ACIError):
        find(make_client(conn), paged_search=True, size_limit=4)
    assert conn.cancels == [b"3"]


def test_referral_is_ignored():
    """A referral between entries is skipped, entries are kept."""
    conn = FakeLDAPConnection(
        make_entries(2), referrals=["ldap://other.example.test/"]
    )
    entries, truncated = find(make_client(conn))
    assert uids(entries) == ["user0", "user1"]
    assert truncated is False


@pytest.mark.parametrize("paged_search", [False, True])
def test_get_effective_rights_control_is_sent(paged_search):
    """The GetEffectiveRights control goes with every request."""
    conn = FakeLDAPConnection(make_entries(3))
    find(
        make_client(conn),
        paged_search=paged_search,
        size_limit=3,
        get_effective_rights=True,
    )
    assert conn.requests
    assert all(r["has_effective_rights"] for r in conn.requests)


def test_arguments_are_normalized_before_the_search():
    """Defaults, limit types and attribute names as sent to the server."""
    conn = FakeLDAPConnection(make_entries(1))
    client = make_client(conn)
    client.time_limit = -1.0
    client.size_limit = 0
    find(
        client,
        base_dn=None,
        filter="",
        attrs_list=["UID", "CN", "UID"],
        size_limit="7",
        time_limit=0,
    )
    assert len(conn.requests) == 1
    request = conn.requests[0]
    assert request["base"] == ""
    assert request["filterstr"] == "(objectClass=*)"
    assert sorted(request["attrlist"]) == ["cn", "uid"]
    assert request["sizelimit"] == 7
    assert request["timeout"] == -1.0


def test_find_entries_does_not_log_truncation(caplog):
    """The limit is reported by the flag only, not logged as an error."""
    conn = FakeLDAPConnection(
        make_entries(3), limits={0: (ldap.SIZELIMIT_EXCEEDED, 1)}
    )
    with caplog.at_level("ERROR"):
        find(make_client(conn))
    assert not caplog.records


def iterate(client, **kwargs):
    kwargs.setdefault("base_dn", DN(BASE))
    return client.iter_entries(**kwargs)


def test_iter_entries_yields_entries_across_pages():
    """Entries of all pages come in order, one request per page."""
    conn = FakeLDAPConnection(make_entries(7))
    seen = list(iterate(make_client(conn), page_size=3))
    assert uids(seen) == ["user%d" % i for i in range(7)]
    assert [r["cookie"] for r in conn.requests] == ["", b"3", b"6"]


def test_iter_entries_early_stop_cancels_with_last_cookie():
    """Closing the generator after page 1 cancels with its cookie."""
    conn = FakeLDAPConnection(make_entries(9))
    gen = iterate(make_client(conn), page_size=3)
    assert next(gen).dn[0]["uid"] == "user0"
    gen.close()
    assert conn.cancels == [b"3"]
    assert len(conn.requests) == 1


def test_iter_entries_no_match_raises_empty_result():
    """No entry and no limit hit: EmptyResult, as find_entries()."""
    client = make_client(FakeLDAPConnection())
    with pytest.raises(errors.EmptyResult):
        list(iterate(client))


def test_iter_entries_limit_raises_after_earlier_entries():
    """The entries received before the limit come before the error."""
    conn = FakeLDAPConnection(
        make_entries(6), limits={1: (ldap.SIZELIMIT_EXCEEDED, 2)}
    )
    seen = []
    with pytest.raises(errors.SizeLimitExceeded):
        for entry in iterate(make_client(conn), page_size=3):
            seen.append(entry)
    assert uids(seen) == ["user0", "user1", "user2", "user3", "user4"]
