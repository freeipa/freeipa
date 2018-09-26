#
# Copyright (C) 2018  FreeIPA Contributors.  See COPYING for license
#
import dns.name
import dns.rdataclass
import dns.rdatatype
from dns.rdtypes.IN.SRV import SRV
from dns.rdtypes.ANY.URI import URI

from ipapython import dnsutil

import pytest


def mksrv(priority, weight, port, target):
    return SRV(
        rdclass=dns.rdataclass.IN,
        rdtype=dns.rdatatype.SRV,
        priority=priority,
        weight=weight,
        port=port,
        target=dns.name.from_text(target)
    )


def mkuri(priority, weight, target):
    return URI(
        rdclass=dns.rdataclass.IN,
        rdtype=dns.rdatatype.URI,
        priority=priority,
        weight=weight,
        target=target
    )


class TestSortSRV:
    def test_empty(self):
        assert dnsutil.sort_prio_weight([]) == []

    def test_one(self):
        h1 = mksrv(1, 0, 443, u"host1")
        assert dnsutil.sort_prio_weight([h1]) == [h1]

        h2 = mksrv(10, 5, 443, u"host2")
        assert dnsutil.sort_prio_weight([h2]) == [h2]

    def test_prio(self):
        h1 = mksrv(1, 0, 443, u"host1")
        h2 = mksrv(2, 0, 443, u"host2")
        h3 = mksrv(3, 0, 443, u"host3")
        assert dnsutil.sort_prio_weight([h3, h2, h1]) == [h1, h2, h3]
        assert dnsutil.sort_prio_weight([h3, h3, h3]) == [h3]
        assert dnsutil.sort_prio_weight([h2, h2, h1, h1]) == [h1, h2]

        h380 = mksrv(4, 0, 80, u"host3")
        assert dnsutil.sort_prio_weight([h1, h3, h380]) == [h1, h3, h380]

        hs = mksrv(-1, 0, 443, u"special")
        assert dnsutil.sort_prio_weight([h1, h2, hs]) == [hs, h1, h2]

    def assert_permutations(self, answers, permutations):
        seen = set()
        for _unused in range(1000):
            result = tuple(dnsutil.sort_prio_weight(answers))
            assert result in permutations
            seen.add(result)
            if seen == permutations:
                break
        else:
            pytest.fail("sorting didn't exhaust all permutations.")

    def test_sameprio(self):
        h1 = mksrv(1, 0, 443, u"host1")
        h2 = mksrv(1, 0, 443, u"host2")
        permutations = {
            (h1, h2),
            (h2, h1),
        }
        self.assert_permutations([h1, h2], permutations)

    def test_weight(self):
        h1 = mksrv(1, 0, 443, u"host1")
        h2_w15 = mksrv(2, 15, 443, u"host2")
        h3_w10 = mksrv(2, 10, 443, u"host3")

        permutations = {
            (h1, h2_w15, h3_w10),
            (h1, h3_w10, h2_w15),
        }
        self.assert_permutations([h1, h2_w15, h3_w10], permutations)

    def test_large(self):
        records = tuple(
            mksrv(1, i, 443, "host{}".format(i)) for i in range(1000)
        )
        assert len(dnsutil.sort_prio_weight(records)) == len(records)


class TestSortURI:
    def test_prio(self):
        h1 = mkuri(1, 0, u"https://host1/api")
        h2 = mkuri(2, 0, u"https://host2/api")
        h3 = mkuri(3, 0, u"https://host3/api")
        assert dnsutil.sort_prio_weight([h3, h2, h1]) == [h1, h2, h3]
        assert dnsutil.sort_prio_weight([h3, h3, h3]) == [h3]
        assert dnsutil.sort_prio_weight([h2, h2, h1, h1]) == [h1, h2]
