# Copyright (C) 2026  FreeIPA Contributors - see LICENSE file

from ipaserver.dcerpc import dns_names_collide, find_namespace_collision


class TestDnsNamesCollide:
    def test_exact_match_collides(self):
        assert dns_names_collide('c.b.a.test', 'c.b.a.test') is True

    def test_exact_match_case_insensitive(self):
        assert dns_names_collide('C.B.A.TEST', 'c.b.a.test') is True

    def test_subdomain_collides(self):
        assert dns_names_collide('deep.c.b.a.test', 'c.b.a.test') is True

    def test_superdomain_collides(self):
        assert dns_names_collide('c.b.a.test', 'deep.c.b.a.test') is True

    def test_unrelated_names_do_not_collide(self):
        assert dns_names_collide('d.test', 'c.b.a.test') is False

    def test_sibling_labels_do_not_collide(self):
        # "bb.a.test" is not a subdomain of "b.a.test" even though the
        # strings share a prefix -- label boundaries matter.
        assert dns_names_collide('bb.a.test', 'b.a.test') is False


class TestFindNamespaceCollision:
    def test_no_collision(self):
        other_trusts = [
            {'cn': 'a.test', 'suffixes': [], 'exclusions': []},
        ]
        result = find_namespace_collision(
            ['d.test', 'deep.unrelated.test'], [], other_trusts)
        assert result is None

    def test_collision_against_domain_name(self):
        other_trusts = [
            {'cn': 'c.b.a.test', 'suffixes': [], 'exclusions': []},
        ]
        result = find_namespace_collision(
            ['deep.c.b.a.test'], [], other_trusts)
        assert result == ('deep.c.b.a.test', 'c.b.a.test', 'c.b.a.test')

    def test_collision_against_other_trusts_suffix(self):
        # The trust's own domain name ("unrelated-forest.test") must NOT
        # itself be a DNS ancestor of the candidate, so the only possible
        # collision is via its UPN suffix specifically.
        other_trusts = [
            {'cn': 'unrelated-forest.test', 'suffixes': ['deep.c.b.a.test'],
             'exclusions': []},
        ]
        result = find_namespace_collision(
            ['sub.deep.c.b.a.test'], [], other_trusts)
        assert result == (
            'sub.deep.c.b.a.test', 'unrelated-forest.test',
            'deep.c.b.a.test')

    def test_exact_match_exclusion_on_other_trust_cancels(self):
        other_trusts = [
            {'cn': 'c.b.a.test', 'suffixes': [],
             'exclusions': ['deep.c.b.a.test']},
        ]
        result = find_namespace_collision(
            ['deep.c.b.a.test'], [], other_trusts)
        assert result is None

    def test_exact_match_exclusion_on_own_trust_cancels(self):
        other_trusts = [
            {'cn': 'c.b.a.test', 'suffixes': [], 'exclusions': []},
        ]
        result = find_namespace_collision(
            ['deep.c.b.a.test'], ['deep.c.b.a.test'], other_trusts)
        assert result is None

    def test_exclusion_does_not_cover_subdomain_of_excluded_name(self):
        other_trusts = [
            {'cn': 'c.b.a.test', 'suffixes': [],
             'exclusions': ['deep.c.b.a.test']},
        ]
        result = find_namespace_collision(
            ['sub.deep.c.b.a.test'], [], other_trusts)
        assert result == (
            'sub.deep.c.b.a.test', 'c.b.a.test', 'c.b.a.test')

    def test_exclusion_on_other_trust_is_case_insensitive(self):
        other_trusts = [
            {'cn': 'c.b.a.test', 'suffixes': [],
             'exclusions': ['Deep.C.B.A.Test']},
        ]
        result = find_namespace_collision(
            ['deep.c.b.a.test'], [], other_trusts)
        assert result is None

    def test_exclusion_on_own_trust_is_case_insensitive(self):
        other_trusts = [
            {'cn': 'c.b.a.test', 'suffixes': [], 'exclusions': []},
        ]
        result = find_namespace_collision(
            ['Deep.C.B.A.Test'], ['deep.c.b.a.test'], other_trusts)
        assert result is None
