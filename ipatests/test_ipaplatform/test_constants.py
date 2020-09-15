#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
import pytest

from ipaplatform.base.constants import User, Group


def test_user_root():
    user = User("root")
    assert user == "root"
    assert str(user) == "root"
    assert type(str(user)) is str
    assert repr(user) == '<User "root">'
    assert user.uid == 0
    assert user.pgid == 0
    assert user.entity.pw_uid == 0

    assert User(user) is user
    assert User(str(user)) is not user


def test_user_invalid():
    invalid = User("invalid")
    with pytest.raises(ValueError) as e:
        assert invalid.uid
    assert str(e.value) == "user 'invalid' not found"


def test_group():
    group = Group("root")
    assert group == "root"
    assert str(group) == "root"
    assert type(str(group)) is str
    assert repr(group) == '<Group "root">'
    assert group.gid == 0
    assert group.entity.gr_gid == 0

    assert Group(group) is group
    assert Group(str(group)) is not group


def test_group_invalid():
    invalid = Group("invalid")
    with pytest.raises(ValueError) as e:
        assert invalid.gid
    assert str(e.value) == "group 'invalid' not found"


@pytest.mark.skip_if_platform("debian", reason="test is Fedora specific")
@pytest.mark.skip_if_platform("suse", reason="test is Fedora specific")
def test_user_group_daemon():
    # daemon user / group are always defined
    user = User("daemon")
    assert user == "daemon"
    assert user.uid == 2
    assert user.pgid == 2

    group = Group("daemon")
    assert group == "daemon"
    assert group.gid == 2

    assert Group(user) is not user
