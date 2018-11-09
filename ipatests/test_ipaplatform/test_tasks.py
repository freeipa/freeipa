#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

from ipaplatform.tasks import tasks


def test_ipa_version():
    v3 = tasks.parse_ipa_version('3.0')
    assert v3.version == u'3.0'
    if hasattr(v3, '_rpmvercmp'):
        assert v3._rpmvercmp_func is None
        v3._rpmvercmp(b'1', b'2')
        assert v3._rpmvercmp_func is not None

    v4 = tasks.parse_ipa_version('4.0')
    assert v4.version == u'4.0'
    if hasattr(v4, '_rpmvercmp'):
        assert v4._rpmvercmp_func is not None

    # pylint: disable=comparison-with-itself
    assert v3 < v4
    assert v3 <= v4
    assert v3 <= v3
    assert v3 != v4
    assert v3 == v3
    assert not v3 == v4
    assert v4 > v3
    assert v4 >= v3
