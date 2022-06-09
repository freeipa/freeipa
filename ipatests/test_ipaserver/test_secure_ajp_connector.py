# Copyright (C) 2021  FreeIPA Project Contributors - see LICENSE file

from collections import namedtuple
from io import BytesIO
from lxml.etree import parse as myparse  # pylint: disable=no-name-in-module
import pytest
import textwrap
from unittest.mock import mock_open, patch

from ipaplatform.constants import constants
from ipaserver.install import dogtaginstance


class MyDogtagInstance(dogtaginstance.DogtagInstance):
    """Purpose is to avoid reading configuration files.

       The real DogtagInstance will open up the system store and
       try to determine the actual version of tomcat installed.
       Fake it instead.
    """
    def __init__(self, is_newer):
        self.service_user = constants.PKI_USER
        self.ajp_secret = None
        self.is_newer = is_newer

    def _is_newer_tomcat_version(self, default=None):
        return self.is_newer


def mock_etree_parse(data):
    """Convert a string into a file-like object to pass in the XML"""
    f = BytesIO(data.strip().encode('utf-8'))
    return myparse(f)


def mock_pkiuser_entity():
    """Return struct_passwd for mocked pkiuser"""
    StructPasswd = namedtuple(
        "StructPasswd",
        [
            "pw_name",
            "pw_passwd",
            "pw_uid",
            "pw_gid",
            "pw_gecos",
            "pw_dir",
            "pw_shell",
        ]
    )
    pkiuser_entity = StructPasswd(
        constants.PKI_USER,
        pw_passwd="x",
        pw_uid=-1,
        pw_gid=-1,
        pw_gecos="",
        pw_dir="/dev/null",
        pw_shell="/sbin/nologin",
    )
    return pkiuser_entity


# Format of test_data is:
#    (
#        is_newer_tomcat (boolean),
#        XML input,
#        expected secret attribute(s),
#        expected password(s),
#        rewrite of XML file expected (boolean),
#    )

test_data = (
    (
        #  Case 1: Upgrade requiredSecret to secret
        True,
        textwrap.dedent("""
            <?xml version="1.0" encoding="UTF-8"?>
            <Server port="1234" shutdown="SHUTDOWN">
              <Service name="Catalina">
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost" requiredSecret="testing_ajp_secret" />
              </Service>
            </Server>
        """),
        ('secret',),
        ('testing_ajp_secret',),
        ('requiredSecret',),
        True,
    ),
    (
        #  Case 2: One connector with secret, no update is needed
        True,
        textwrap.dedent("""
            <?xml version="1.0" encoding="UTF-8"?>
            <Server port="1234" shutdown="SHUTDOWN">
              <Service name="Catalina">
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost" secret="testing_ajp_secret" />
              </Service>
            </Server>
        """),
        ('secret',),
        ('testing_ajp_secret',),
        ('requiredSecret',),
        False,
    ),
    (
        #  Case 3: Two connectors, old secret attribute, different secrets
        True,
        textwrap.dedent("""
            <?xml version="1.0" encoding="UTF-8"?>
            <Server port="1234" shutdown="SHUTDOWN">
              <Service name="Catalina">
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost4" requiredSecret="testing_ajp_secret" />
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost6" requiredSecret="other_secret" />
              </Service>
            </Server>
        """),
        ('secret', 'secret'),
        ('testing_ajp_secret', 'testing_ajp_secret'),
        ('requiredSecret', 'requiredSecret'),
        True,
    ),
    (
        #  Case 4: Two connectors, new secret attribute, same secrets
        True,
        textwrap.dedent("""
            <?xml version="1.0" encoding="UTF-8"?>
            <Server port="1234" shutdown="SHUTDOWN">
              <Service name="Catalina">
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost4" secret="testing_ajp_secret" />
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost6" secret="testing_ajp_secret" />
              </Service>
            </Server>
        """),
        ('secret', 'secret'),
        ('testing_ajp_secret', 'testing_ajp_secret'),
        ('requiredSecret', 'requiredSecret'),
        False,
    ),
    (
        #  Case 5: Two connectors, no secrets
        True,
        textwrap.dedent("""
            <?xml version="1.0" encoding="UTF-8"?>
            <Server port="1234" shutdown="SHUTDOWN">
              <Service name="Catalina">
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost4" />
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost6" />
              </Service>
            </Server>
        """),
        ('secret', 'secret'),
        ('RANDOM', 'RANDOM'),
        ('requiredSecret', 'requiredSecret'),
        True,
    ),
    (
        #  Case 6: Older tomcat, no update needed for requiredSecret
        False,
        textwrap.dedent("""
            <?xml version="1.0" encoding="UTF-8"?>
            <Server port="1234" shutdown="SHUTDOWN">
              <Service name="Catalina">
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost" requiredSecret="testing_ajp_secret" />
              </Service>
            </Server>
        """),
        ('requiredSecret',),
        ('testing_ajp_secret',),
        ('secret',),
        False,
    ),
    (
        #  Case 7: Older tomcat, both secrets are present, one s/b removed
        False,
        textwrap.dedent("""
            <?xml version="1.0" encoding="UTF-8"?>
            <Server port="1234" shutdown="SHUTDOWN">
              <Service name="Catalina">
                <Connector port="9000" protocol="AJP/1.3" redirectPort="443"
                 address="localhost" requiredSecret="testing_ajp_secret"
                 secret="other_secret" />
              </Service>
            </Server>
        """),
        ('requiredSecret',),
        ('testing_ajp_secret',),
        ('secret',),
        True,
    ),
)


class TestAJPSecretUpgrade:
    @patch("ipaplatform.base.constants.pwd.getpwnam")
    @patch("ipaplatform.base.constants.os.chown")
    @patch("ipaserver.install.dogtaginstance.lxml.etree.parse")
    @pytest.mark.parametrize("test_data", test_data)
    def test_connecter(self, mock_parse, mock_chown, mock_getpwnam, test_data):
        is_newer, data, secret, expect, ex_secret, rewrite = test_data
        mock_chown.return_value = None
        mock_parse.return_value = mock_etree_parse(data)
        mock_getpwnam.return_value = mock_pkiuser_entity()

        dogtag = MyDogtagInstance(is_newer)
        with patch('ipaserver.install.dogtaginstance.open', mock_open()) \
                as mocked_file:
            dogtag.secure_ajp_connector()
            if rewrite:
                newdata = mocked_file().write.call_args.args
                f = BytesIO(newdata[0])
                server_xml = myparse(f)
                doc = server_xml.getroot()
                connectors = doc.xpath('//Connector[@protocol="AJP/1.3"]')
                assert len(connectors) == len(secret)

                i = 0
                for connector in connectors:
                    if expect[i] == 'RANDOM':
                        assert connector.attrib[secret[i]]
                    else:
                        assert connector.attrib[secret[i]] == expect[i]
                    assert connector.attrib.get(ex_secret[i]) is None
                    i += 1
            else:
                assert mocked_file().write.call_args is None
