#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""
Module provides unit tests to verify that the FileStore code works.
"""

from __future__ import absolute_import

import collections
import filecmp
import os
import shutil
from hashlib import sha256

import pytest
import six

# pylint: disable=import-error
if six.PY3:
    # The SafeConfigParser class has been renamed to ConfigParser in Py3
    from configparser import ConfigParser as SafeConfigParser
    from configparser import MissingSectionHeaderError
else:
    from ConfigParser import SafeConfigParser
    from ConfigParser import MissingSectionHeaderError
# pylint: enable=import-error

from ipalib.install import sysrestore
from ipalib.install.sysrestore import SYSRESTORE_SEP as SEP
from ipaplatform.paths import paths


TESTDATA = {
    "test_create": [
        {},
        {"path": "notdefault_storedir"},
        {"path": "notdefault_storedir", "index_file": "notdefault_indexfile"},
        {"index_file": "notdefault_indexfile"},
    ],
    "test_restore": [
        {"path": "/oldpath"},
        {"new_path": "newpath", "path": "/oldpath"},
    ],
}


# helpers
def backuped_name(path):
    """
    Return an expected internal name of a file being backuped to filestore
    """
    backupfile = os.path.basename(path)
    with open(path, "rb") as f:
        cont_hash = sha256(f.read()).hexdigest()
    return "{hexhash}-{bcppath}".format(
        hexhash=cont_hash, bcppath=backupfile
    )


def mkfile_source(sourcedir, sourcefile="sourcepath", content="content"):
    """
    Prepare an arbitrary source file
    """
    sourcepath = os.path.join(sourcedir, sourcefile)
    with open(sourcepath, "w") as f:
        f.write(content)
    return sourcepath


def index_path(index_dict):
    """
    Build an expected path (string) of index file from a given dict
    """
    indexdir = index_dict.get("path", sysrestore.SYSRESTORE_PATH)
    indexfile = index_dict.get("index_file", sysrestore.SYSRESTORE_INDEXFILE)
    return os.path.join(indexdir, indexfile)


def idf(val):
    """
    Improve readability of parameterization
    """
    if not val:
        return "@default"
    else:
        return "@" + str(val)


@pytest.fixture
def sysrestore_dirs(request, tmpdir):
    """
    Prepare sysrestore dirs for tests.
    Monkeypatch paths.SYSRESTORE to override the default one
    to prevent damage installed IPA.
    """
    sysrest_orig = paths.SYSRESTORE
    paths.SYSRESTORE = str(tmpdir.mkdir("default_store"))

    import importlib
    importlib.reload(sysrestore)

    def fin():
        paths.SYSRESTORE = sysrest_orig
        importlib.reload(sysrestore)

    request.addfinalizer(fin)

    store_dir = str(tmpdir.mkdir("sysrestore"))
    source_dir = str(tmpdir.mkdir("sourcedir"))
    return {"store_dir": store_dir, "source_dir": source_dir}


@pytest.fixture
def fstore(sysrestore_dirs):
    """
    Create a FileStore in specified location
    """
    fstore = sysrestore.FileStore(path=sysrestore_dirs["store_dir"])
    return fstore


@pytest.mark.parametrize("testdata", TESTDATA["test_create"], ids=idf)
def test_create_new(testdata, sysrestore_dirs):
    """
    Condition: new (not existing before) filestore.
    Expected result: there should be no files within the store.
    """
    if "path" in testdata.keys():
        testdata["path"] = sysrestore_dirs["store_dir"]
    fstore = sysrestore.FileStore(**testdata)
    assert not fstore.files


@pytest.mark.parametrize("testdata", TESTDATA["test_create"], ids=idf)
def test_create_empty_existing(testdata, sysrestore_dirs):
    """
    Condition: existing but empty filestore.
    Expected result: there should be no files within the store.
    """
    if "path" in testdata.keys():
        testdata["path"] = sysrestore_dirs["store_dir"]
    with open(index_path(testdata), "w") as f:
        f.write("")
    fstore = sysrestore.FileStore(**testdata)
    assert not fstore.files


@pytest.mark.parametrize("testdata", TESTDATA["test_create"], ids=idf)
def test_create_no_headers(testdata, sysrestore_dirs):
    """
    Condition: existing filestore but having no headers.
    Expected result: there should be an exception.
    """
    if "path" in testdata.keys():
        testdata["path"] = sysrestore_dirs["store_dir"]
    fstore = None
    with open(index_path(testdata), "w") as f:
        f.write("noheaders")

    with pytest.raises(MissingSectionHeaderError):
        fstore = sysrestore.FileStore(**testdata)
        pytest.fail("Attempting to parse a config file which has"
                    "no section headers should raise an exception")

    assert fstore is None


@pytest.mark.parametrize(
    "testdata", [
        {"index_file": ""},
        {"index_file": "/some/path"},
    ],
    ids=idf,
)
def test_create_non_indexfile(testdata, sysrestore_dirs):
    """
    Condition: create filestore with index file having name with leading dirs.
    Expected result: there should be an exception.
    """
    fstore = None
    if "path" in testdata.keys():
        testdata["path"] = sysrestore_dirs["store_dir"]
    with pytest.raises(ValueError):
        fstore = sysrestore.FileStore(**testdata)
        pytest.fail("Attempting to create a filestore with empty "
                    "index or with index file having name with "
                    "leading dirs should raise an exception")

    assert fstore is None


@pytest.mark.parametrize("testdata", TESTDATA["test_create"], ids=idf)
def test_create_wrong_header(testdata, sysrestore_dirs):
    """
    Condition: existing filestore, but having wrong headers.
    Expected result: there should be no files within the store.
    """
    if "path" in testdata.keys():
        testdata["path"] = sysrestore_dirs["store_dir"]
    p = SafeConfigParser()
    p.read_dict(
        collections.OrderedDict([
            ("wrongheader",
             collections.OrderedDict([
                 ("key", "value"),
             ])),
        ])
    )
    with open(index_path(testdata), "w") as f:
        p.write(f)
    fstore = sysrestore.FileStore(**testdata)
    assert not fstore.files


@pytest.mark.parametrize("testdata", TESTDATA["test_create"], ids=idf)
def test_create_broken_store(testdata, sysrestore_dirs):
    """
    Condition: existing filestore, but having broken state.
    Expected result: there should be an exception.
    """
    if "path" in testdata.keys():
        testdata["path"] = sysrestore_dirs["store_dir"]
    p = SafeConfigParser()
    # make key name case sensitive
    p.optionxform = str

    expected_files = collections.OrderedDict([
        ("key", SEP * (sysrestore.SYSRESTORE_MAX_INDEX - 1)),
    ])
    p.read_dict(
        collections.OrderedDict([
            (sysrestore.SYSRESTORE_SECTION, expected_files),
        ])
    )

    with open(index_path(testdata), "w") as f:
        p.write(f)

    fstore = None
    with pytest.raises(ValueError) as error:
        fstore = sysrestore.FileStore(**testdata)
        pytest.fail("Attempting to load FileStore with broken value"
                    " should raise exception")
    assert str(error.value) == "Broken store {0}".format(
        index_path(testdata)
    )
    assert fstore is None


@pytest.mark.parametrize("testdata", TESTDATA["test_create"], ids=idf)
def test_create(testdata, sysrestore_dirs):
    """
    Condition: existing filestore with files within.
    Expected result: successful creation of filestore.
    """
    if "path" in testdata.keys():
        testdata["path"] = sysrestore_dirs["store_dir"]
    p = SafeConfigParser()
    # make key name case sensitive
    p.optionxform = str

    expected_files = collections.OrderedDict([
        ("key", SEP * sysrestore.SYSRESTORE_MAX_INDEX),
    ])
    p.read_dict(
        collections.OrderedDict([
            (sysrestore.SYSRESTORE_SECTION, expected_files),
        ])
    )

    with open(index_path(testdata), "w") as f:
        p.write(f)

    fstore = sysrestore.FileStore(**testdata)
    assert fstore.files == expected_files


def test_save_empty(fstore):
    """
    Condition: cleared filestore.
    Expected result: lack of store index.
    """
    fstore.files.clear()
    # if files is an empty dict then store should be removed
    fstore.save()
    assert not os.path.isfile(fstore._index)


def test_save_broken_store(fstore):
    """
    Condition: filestore with broken state.
    Expected result: there should be an exception.
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * (sysrestore.SYSRESTORE_MAX_INDEX - 1)),
    ])

    with pytest.raises(ValueError) as error:
        fstore.save()
        pytest.fail("Attempting to save FileStore with broken value"
                    " should raise ValueError exception")
    assert str(error.value) == "Broken store {0}".format(fstore._index)
    assert not os.path.isfile(fstore._index)


def test_save(fstore):
    """
    Condition: filestore with files within.
    Expected result: successful saving to store index.
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * sysrestore.SYSRESTORE_MAX_INDEX),
    ])
    fstore.save()

    p = SafeConfigParser()
    p.optionxform = str
    p.read(fstore._index)

    expected_files = collections.OrderedDict()
    for section in p.sections():
        for (key, value) in p.items(section):
            expected_files[key] = value

    assert fstore.files == expected_files


@pytest.mark.parametrize("nonabs_path", ["", "../relative/"], ids=idf)
def test_backup_not_abs(nonabs_path, fstore, sysrestore_dirs):
    """
    Condition: path to be backuped is empty or non-absolute.
    Expected result: there should be an exception.
    """
    with pytest.raises(ValueError) as error:
        fstore.backup_file(nonabs_path)
        pytest.fail("Attempting to backup empty or relative "
                    "path should raise an exception")
    assert str(error.value) == "Absolute path required"
    assert not os.listdir(sysrestore_dirs["store_dir"])


def test_backup_file_not_exist(fstore, sysrestore_dirs):
    """
    Condition: path to be backuped does not exist.
    Expected result: there should be no file in the store.
    """
    fstore.backup_file("/notexisted")
    assert not os.listdir(sysrestore_dirs["store_dir"])


def test_backup_dir(fstore, sysrestore_dirs):
    """
    Condition: path to be backuped is directory.
    Expected result: there should be an exception.
    """
    with pytest.raises(ValueError) as error:
        fstore.backup_file(sysrestore_dirs["source_dir"])
        pytest.fail("Attempting to backup a non-regular file "
                    "should raise an exception")
    assert str(error.value) == "Regular file required"
    assert not os.listdir(sysrestore_dirs["store_dir"])


def test_backup_broken_store(fstore, sysrestore_dirs):
    """
    Condition: filestore with broken state.
    Expected result: there should be an exception.
    """
    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    fstore.files = collections.OrderedDict([
        ("key", SEP * (sysrestore.SYSRESTORE_MAX_INDEX - 1)),
    ])

    with pytest.raises(ValueError) as error:
        fstore.backup_file(sourcepath)
        pytest.fail("Attempting to backup file into broken "
                    "store should raise an exception")
    assert str(error.value) == "Broken store {0}".format(fstore._index)
    assert not os.listdir(sysrestore_dirs["store_dir"])


def test_backup(fstore, sysrestore_dirs):
    """
    Condition: new filestore.
    Expected result: successful backup of file.
    """
    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    expected_stat = os.lstat(sourcepath)
    expected_mode = expected_stat.st_mode

    template = "{stats.st_mode},{stats.st_uid},{stats.st_gid},{path}"
    value = template.format(stats=expected_stat, path=sourcepath)
    expected_files = collections.OrderedDict()
    expected_files[backuped_name(sourcepath)] = value

    fstore.backup_file(sourcepath)
    assert fstore.files == expected_files

    backupfile = os.path.join(sysrestore_dirs["store_dir"],
                              backuped_name(sourcepath))
    actual_stat = os.lstat(backupfile)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    # check content
    assert filecmp.cmp(sourcepath, backupfile, shallow=False)


def test_backup_same_file(fstore, sysrestore_dirs):
    """
    Condition: new filestore with the same file within.
    Expected result: no backup of file, no store changes.
    """
    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    fstore.backup_file(sourcepath)
    backupfile = os.path.join(sysrestore_dirs["store_dir"],
                              backuped_name(sourcepath))
    expected_stat = os.lstat(backupfile)
    expected_mode = expected_stat.st_mode
    expected_files = collections.OrderedDict(fstore.files)

    # repeat backup
    fstore.backup_file(sourcepath)
    actual_stat = os.lstat(backupfile)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    assert fstore.files == expected_files


def test_backup_same_filename(fstore, sysrestore_dirs):
    """
    Condition: source file has been already backuped, but the content
    is different. Updated file should be appended to the filestore.
    Expected result: successful backup; ordered store.
    """
    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    expected_stat = os.lstat(sourcepath)
    template = "{stats.st_mode},{stats.st_uid},{stats.st_gid},{path}"
    value = template.format(stats=expected_stat, path=sourcepath)
    expected_files = collections.OrderedDict()
    expected_files[backuped_name(sourcepath)] = value

    fstore.backup_file(sourcepath)

    # overwrite source
    sourcepath = mkfile_source(sysrestore_dirs["source_dir"],
                               content="overwrite_content")
    expected_stat = os.lstat(sourcepath)
    expected_mode = expected_stat.st_mode
    value = template.format(stats=expected_stat, path=sourcepath)
    expected_files[backuped_name(sourcepath)] = value

    fstore.backup_file(sourcepath)
    # check an internal state of store
    assert len(fstore.files) == 2
    assert fstore.files == expected_files

    backupfile = os.path.join(sysrestore_dirs["store_dir"],
                              backuped_name(sourcepath))
    actual_stat = os.lstat(backupfile)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    # check content
    assert filecmp.cmp(sourcepath, backupfile, shallow=False)


def test_has_file_empty_store(fstore):
    """
    Condition: new filestore without files within.
    Expected result: filestore has no file.
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * sysrestore.SYSRESTORE_MAX_INDEX),
    ])
    assert not fstore.has_file("testpath")


def test_has_file_broken_store(fstore):
    """
    Condition: new filestore with broken state.
    Expected result: there should be an exception.
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * (sysrestore.SYSRESTORE_MAX_INDEX - 1)),
    ])
    with pytest.raises(ValueError) as error:
        fstore.has_file("testpath")
        pytest.fail("Attempting to read from broken store "
                    "should raise an exception")
    assert str(error.value) == "Broken store {0}".format(fstore._index)


def test_has_file_no_file(fstore):
    """
    Condition: filestore with files within, but has not a given one.
    Expected result: filestore has no file.
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * sysrestore.SYSRESTORE_MAX_INDEX),
    ])
    assert not fstore.has_file("testpath")


def test_has_file(fstore):
    """
    Condition: filestore with files within.
    Expected result: filestore has file.
    """
    value = SEP * sysrestore.SYSRESTORE_MAX_INDEX
    parts = value.split(SEP)
    parts[sysrestore.SYSRESTORE_PATH_INDEX] = "testpath"
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("key", value),
    ])
    assert fstore.has_file("testpath")


@pytest.mark.parametrize("nonabs_path", ["", "../relative/"], ids=idf)
def test_restore_not_abs(nonabs_path, fstore, sysrestore_dirs):
    """
    Condition: path to be restored is empty or relative.
    Expected result: there should be an exception.
    """
    with pytest.raises(ValueError) as error:
        fstore.restore_file(nonabs_path)
        pytest.fail("Attempting to restore empty or non-absolute "
                    "path should raise an exception")
    assert str(error.value) == "Absolute path required"
    assert not os.listdir(sysrestore_dirs["source_dir"])


@pytest.mark.parametrize("nonabs_path", ["", "../relative/"], ids=idf)
def test_restore_not_abs_new(nonabs_path, fstore, sysrestore_dirs):
    """
    Condition: new path to be restored to is empty or relative.
    Expected result: there should be an exception.
    """
    with pytest.raises(ValueError) as error:
        fstore.restore_file(path="/oldpath", new_path=nonabs_path)
        pytest.fail("Attempting to restore to a non-absolute "
                    "path should raise an exception")
    assert str(error.value) == "Absolute new path required"
    assert not os.listdir(sysrestore_dirs["source_dir"])


@pytest.mark.parametrize("testdata", TESTDATA["test_restore"], ids=idf)
def test_restore_broken_store(testdata, fstore, sysrestore_dirs):
    """
    Condition: filestore with a broken state.
    Expected result: there should be an exception.
    """
    if "new_path" in testdata.keys():
        testdata["new_path"] = os.path.join(sysrestore_dirs["source_dir"],
                                            testdata["new_path"])
    fstore.files = collections.OrderedDict([
        ("key", SEP * (sysrestore.SYSRESTORE_MAX_INDEX - 1)),
    ])
    with pytest.raises(ValueError) as error:
        fstore.restore_file(**testdata)
        pytest.fail("Attempting to restore from broken store "
                    "should raise an exception")
    assert str(error.value) == "Broken store {0}".format(fstore._index)
    assert not os.listdir(sysrestore_dirs["source_dir"])


@pytest.mark.parametrize("testdata", TESTDATA["test_restore"], ids=idf)
def test_restore_no_filename(testdata, fstore, sysrestore_dirs):
    """
    Condition: filestore with empty key.
    Expected result: there should be an exception.
    """
    if "new_path" in testdata.keys():
        testdata["new_path"] = os.path.join(sysrestore_dirs["source_dir"],
                                            testdata["new_path"])
    value = SEP * sysrestore.SYSRESTORE_MAX_INDEX
    parts = value.split(SEP)
    parts[sysrestore.SYSRESTORE_PATH_INDEX] = testdata["path"]
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("", value),
    ])
    with pytest.raises(ValueError) as error:
        fstore.restore_file(**testdata)
        pytest.fail("Attempting to restore a file "
                    "without name should raise an exception")
    assert str(error.value) == "No such file name in the index"
    assert not os.listdir(sysrestore_dirs["source_dir"])


@pytest.mark.parametrize("testdata", TESTDATA["test_restore"], ids=idf)
def test_restore_no_filepath(testdata, fstore, sysrestore_dirs):
    """
    Condition: filestore with empty file path.
    Expected result: there should be an exception.
    """
    if "new_path" in testdata.keys():
        testdata["new_path"] = os.path.join(sysrestore_dirs["source_dir"],
                                            testdata["new_path"])
    value = SEP * sysrestore.SYSRESTORE_MAX_INDEX
    parts = value.split(SEP)
    parts[sysrestore.SYSRESTORE_PATH_INDEX] = "nopath"
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("key", value),
    ])
    with pytest.raises(ValueError) as error:
        fstore.restore_file(**testdata)
        pytest.fail("Attempting to restore a file "
                    "without path should raise an exception")
    assert str(error.value) == "No such file name in the index"
    assert not os.listdir(sysrestore_dirs["source_dir"])


@pytest.mark.parametrize("testdata", TESTDATA["test_restore"], ids=idf)
def test_restore_no_backup(testdata, fstore, sysrestore_dirs):
    """
    Condition: filestore with missing file.
    Expected result: restoration should fail.
    """
    if "new_path" in testdata.keys():
        testdata["new_path"] = os.path.join(sysrestore_dirs["source_dir"],
                                            testdata["new_path"])
    value = SEP * sysrestore.SYSRESTORE_MAX_INDEX
    parts = value.split(SEP)
    parts[sysrestore.SYSRESTORE_PATH_INDEX] = testdata["path"]
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("/notexisted", value),
    ])
    assert not fstore.restore_file(**testdata)
    assert not os.listdir(sysrestore_dirs["source_dir"])


@pytest.mark.parametrize("testdata", TESTDATA["test_restore"], ids=idf)
def test_restore_file(testdata, fstore, sysrestore_dirs):
    """
    Condition: filestore with backuped file within.
    Expected result: successful restoration of file.
    """
    if "new_path" in testdata.keys():
        testdata["new_path"] = os.path.join(sysrestore_dirs["source_dir"],
                                            testdata["new_path"])
    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    testdata["path"] = sourcepath
    restorepath = testdata.get("new_path")
    if restorepath is None:
        restorepath = sourcepath

    expected_stat = os.lstat(sourcepath)
    expected_mode = expected_stat.st_mode

    bkwargs = dict(testdata)
    try:
        del bkwargs["new_path"]
    except KeyError:
        pass
    fstore.backup_file(**bkwargs)
    # do not remove because it is used for content compare
    bakfile = sourcepath + ".bak"
    os.rename(sourcepath, bakfile)
    assert fstore.restore_file(**testdata)
    assert not fstore.files

    actual_stat = os.lstat(restorepath)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    assert actual_stat.st_uid == expected_stat.st_uid
    assert actual_stat.st_gid == expected_stat.st_gid
    # check content
    assert filecmp.cmp(restorepath, bakfile, shallow=False)

    assert not os.listdir(sysrestore_dirs["store_dir"])


@pytest.mark.parametrize("newpath", ["", "newpath"], ids=idf)
def test_restore_stacked_backup(newpath, fstore, sysrestore_dirs):
    """
    Condition: filestore with backuped n-times file within.
    Expected result: successful restoration of file.
    """
    NUM_ITERS = 10
    kwargs = {}
    backups = []

    if newpath:
        newpath = os.path.join(sysrestore_dirs["source_dir"], newpath)
        kwargs["new_path"] = newpath

    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    kwargs["path"] = sourcepath
    bkwargs = dict(kwargs)
    try:
        del bkwargs["new_path"]
    except KeyError:
        pass

    # create stack of backups for file with same name
    for num in range(NUM_ITERS):
        sourcepath = mkfile_source(sysrestore_dirs["source_dir"],
                                   content="content" + str(num))
        kwargs["path"] = sourcepath

        expected_stat = os.lstat(sourcepath)

        fstore.backup_file(**bkwargs)
        # do not remove because it is used for content compare
        backups.append([backuped_name(sourcepath), expected_stat])
        bakfile = sourcepath + ".bak" + str(num)
        os.rename(sourcepath, bakfile)

    # restore stack of backups
    for num in reversed(range(NUM_ITERS)):
        (expected_backupfile, expected_stat) = backups[num]
        expected_path = os.path.join(sysrestore_dirs["store_dir"],
                                     expected_backupfile)
        assert fstore.restore_file(**kwargs)
        assert expected_backupfile not in fstore.files
        assert not os.path.exists(expected_path)

        expected_mode = expected_stat.st_mode
        if newpath:
            restorepath = kwargs["new_path"]
        else:
            restorepath = sourcepath
        actual_stat = os.lstat(restorepath)
        actual_mode = actual_stat.st_mode
        assert oct(actual_mode) == oct(expected_mode)
        assert actual_stat.st_uid == expected_stat.st_uid
        assert actual_stat.st_gid == expected_stat.st_gid
        # check content
        bakfile = sourcepath + ".bak" + str(num)
        assert filecmp.cmp(restorepath, bakfile, shallow=False)

    assert not fstore.files
    assert not os.listdir(sysrestore_dirs["store_dir"])


def test_restoreall_no_files(fstore):
    """
    Condition: empty filestore.
    Expected result: restoration should fail.
    """
    fstore.files.clear()
    assert not fstore.restore_all_files()


def test_restoreall_files(fstore, sysrestore_dirs):
    """
    Condition: filestore with n different files
    Expected result: successful restoration of files
    """
    NUM_BACKUPS = 10
    backups = []

    # create backups
    for num in range(NUM_BACKUPS):
        sourcefile = "sourcefile" + str(num)
        sourcepath = mkfile_source(sysrestore_dirs["source_dir"], sourcefile,
                                   content="content" + str(num))
        expected_stat = os.lstat(sourcepath)

        fstore.backup_file(path=sourcepath)
        # do not remove because it is used for content compare
        backups.append([sourcepath, expected_stat])
        bakfile = sourcepath + ".bak"
        os.rename(sourcepath, bakfile)

    assert fstore.restore_all_files()
    assert not fstore.files
    assert not os.listdir(sysrestore_dirs["store_dir"])

    for (sourcepath, expected_stat) in backups:
        expected_mode = expected_stat.st_mode
        restorepath = sourcepath
        actual_stat = os.lstat(restorepath)
        actual_mode = actual_stat.st_mode
        assert oct(actual_mode) == oct(expected_mode)
        assert actual_stat.st_uid == expected_stat.st_uid
        assert actual_stat.st_gid == expected_stat.st_gid
        # check content
        bakfile = sourcepath + ".bak"
        assert filecmp.cmp(restorepath, bakfile, shallow=False)


def test_restoreall_file(fstore, sysrestore_dirs):
    """
    Condition: filestore with backuped n-times file within.
    Expected result: successful restoration of file.
    """
    NUM_BACKUPS = 10
    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    expected_stat = os.lstat(sourcepath)
    expected_mode = expected_stat.st_mode
    bakfile = sourcepath + ".bak"
    shutil.copy2(sourcepath, bakfile)
    fstore.backup_file(sourcepath)

    # create backups
    for num in range(NUM_BACKUPS):
        mkfile_source(sysrestore_dirs["source_dir"],
                      content="content" + str(num))
        fstore.backup_file(sourcepath)

    fstore.restore_all_files()
    assert not fstore.files
    assert not os.listdir(sysrestore_dirs["store_dir"])

    actual_stat = os.lstat(sourcepath)
    actual_mode = actual_stat.st_mode
    assert oct(actual_mode) == oct(expected_mode)
    assert actual_stat.st_uid == expected_stat.st_uid
    assert actual_stat.st_gid == expected_stat.st_gid
    # check content
    assert filecmp.cmp(sourcepath, bakfile, shallow=False)


def test_has_files_no_files(fstore):
    """
    Condition: empty filestore.
    Expected result: has not files.
    """
    fstore.files.clear()
    assert not fstore.has_files()


def test_has_files(fstore):
    """
    Condition: filestore with files within.
    Expected result: has files.
    """
    fstore.files.clear()
    value = SEP * sysrestore.SYSRESTORE_MAX_INDEX
    fstore.files = collections.OrderedDict([
        ("key", value),
    ])
    assert fstore.has_files()


@pytest.mark.parametrize("nonabs_path", ["", "../relative/"], ids=idf)
def test_untrack_file_not_abs(nonabs_path, fstore):
    """
    Condition: path to be untracked is empty or relative.
    Expected result: there should be an exception.
    """
    with pytest.raises(ValueError) as error:
        fstore.untrack_file(nonabs_path)
        pytest.fail("Attempting to untrack file with relative "
                    "path should raise an exception")
    assert str(error.value) == "Absolute path required"


def test_untrack_broken_store(fstore):
    """
    Condition: filestore with broken state.
    Expected result: there should be an exception.
    """
    fstore.files = collections.OrderedDict([
        ("key", SEP * (sysrestore.SYSRESTORE_MAX_INDEX - 1)),
    ])

    with pytest.raises(ValueError) as error:
        fstore.untrack_file("/somepath")
        pytest.fail("Attempting to untrack file from broken "
                    "store should raise an exception")
    assert str(error.value) == "Broken store {0}".format(fstore._index)


def test_untrack_no_filename(fstore):
    """
    Condition: filestore without filename.
    Expected result: there should be an exception.
    """
    value = SEP * sysrestore.SYSRESTORE_MAX_INDEX
    parts = value.split(SEP)
    parts[sysrestore.SYSRESTORE_PATH_INDEX] = "/somepath"
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("", value),
    ])
    with pytest.raises(ValueError) as error:
        fstore.untrack_file("/somepath")
        pytest.fail("Attempting to untrack a file "
                    "without name should raise an exception")
    assert str(error.value) == "No such file name in the index"


def test_untrack_no_filepath(fstore):
    """
    Condition: filestore without filepath.
    Expected result: there should be an exception.
    """
    value = SEP * sysrestore.SYSRESTORE_MAX_INDEX
    parts = value.split(SEP)
    parts[sysrestore.SYSRESTORE_PATH_INDEX] = "nopath"
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("key", value),
    ])
    with pytest.raises(ValueError) as error:
        fstore.untrack_file("/somepath")
        pytest.fail("Attempting to untrack a file "
                    "without path should raise an exception")
    assert str(error.value) == "No such file name in the index"


def test_untrack_no_backup(fstore):
    """
    Condition: filestore without backup.
    Expected result: untracking should fail.
    """
    value = SEP * sysrestore.SYSRESTORE_MAX_INDEX
    parts = value.split(SEP)
    parts[sysrestore.SYSRESTORE_PATH_INDEX] = "/somepath"
    value = SEP.join(parts)
    fstore.files = collections.OrderedDict([
        ("/notexisted", value),
    ])
    assert not fstore.untrack_file("/somepath")


def test_untrack(fstore, sysrestore_dirs):
    """
    Condition: filestore with files within.
    Expected result: successful untracking.
    """
    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    fstore.backup_file(sourcepath)
    assert fstore.untrack_file(sourcepath)
    assert not fstore.files
    assert not os.listdir(sysrestore_dirs["store_dir"])


def test_untrack_stacked_backup(fstore, sysrestore_dirs):
    """
    Condition: filestore with stacked backup of file.
    Expected result: successful untracking.
    """
    NUM_ITERS = 10
    backups = []

    sourcepath = mkfile_source(sysrestore_dirs["source_dir"])
    for num in range(NUM_ITERS):
        mkfile_source(sysrestore_dirs["source_dir"],
                      content="content" + str(num))
        fstore.backup_file(sourcepath)
        backups.append(os.path.join(sysrestore_dirs["store_dir"],
                       backuped_name(sourcepath)))

    # untrack stack of backups
    for num in reversed(range(NUM_ITERS)):
        expected_backupfile = backups[num]
        assert fstore.untrack_file(sourcepath)
        assert not os.path.exists(expected_backupfile)

    assert not fstore.files
    assert not os.listdir(sysrestore_dirs["store_dir"])
