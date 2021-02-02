# Copyright (C) 2021  FreeIPA Project Contributors - see LICENSE file

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
        False,
    ),
)


class TestAJPSecretUpgrade:
    @patch('os.chown')
    @patch('lxml.etree.parse')
    @pytest.mark.parametrize('is_newer, data, secret, expect, rewrite',
                             test_data)
    def test_connecter(self, mock_parse, mock_chown, is_newer, data, secret,
                       expect, rewrite):
        mock_chown.return_value = None
        mock_parse.return_value = mock_etree_parse(data)

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
                    i += 1
            else:
                assert mocked_file().write.call_args is None
