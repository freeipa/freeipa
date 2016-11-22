# Copyright (C) 2015  FreeIPA Project Contributors - see LICENSE file

from __future__ import print_function
from ipaserver.secrets.store import iSecStore, NAME_DB_MAP, NSSCertDB
import os
import shutil
import subprocess
import unittest


def _test_password_callback():
    with open('test-ipa-sec-store/pwfile') as f:
        password = f.read()
    return password


class TestiSecStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            shutil.rmtree('test-ipa-sec-store')
        except Exception:  # pylint: disable=broad-except
            pass
        testdir = 'test-ipa-sec-store'
        pwfile = os.path.join(testdir, 'pwfile')
        os.mkdir(testdir)
        with open(pwfile, 'w') as f:
            f.write('testpw')
        cls.certdb = os.path.join(testdir, 'certdb')
        os.mkdir(cls.certdb)
        cls.cert2db = os.path.join(testdir, 'cert2db')
        os.mkdir(cls.cert2db)
        seedfile = os.path.join(testdir, 'seedfile')
        with open(seedfile, 'wb') as f:
            seed = os.urandom(1024)
            f.write(seed)
        subprocess.call(['certutil', '-d', cls.certdb, '-N', '-f', pwfile])
        subprocess.call(['certutil', '-d', cls.cert2db, '-N', '-f', pwfile])
        subprocess.call(['certutil', '-d', cls.certdb, '-S', '-f', pwfile,
                         '-s', 'CN=testCA', '-n', 'testCACert', '-x',
                         '-t', 'CT,C,C', '-m', '1', '-z', seedfile])

    def test_iSecStore(self):
        iss = iSecStore({})

        NAME_DB_MAP['test'] = {
            'type': 'NSSDB',
            'path': self.certdb,
            'handler': NSSCertDB,
            'pwcallback': _test_password_callback,
        }
        value = iss.get('keys/test/testCACert')

        NAME_DB_MAP['test']['path'] = self.cert2db
        iss.set('keys/test/testCACert', value)
