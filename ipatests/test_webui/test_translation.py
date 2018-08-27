#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Test translations
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot

try:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.wait import WebDriverWait
except ImportError:
    pass

import pytest
from re import sub
from lxml import html
from ipalib import api, util


class ConfigPageBase(UI_driver):
    """
    Base class to test translation of pages which are located at /ipa/config/
    """

    page_name = ''

    def init_app(self):
        """
        Load a web page
        """
        self.url = '/'.join((self.get_base_url(), self.page_name))
        self.load()

    def get_base_url(self):
        """
        Get FreeIPA Web UI config url
        """
        host = self.config.get('ipa_server')
        if not host:
            self.skip('FreeIPA server hostname not configured')
        return 'https://%s/ipa/config' % host

    def files_loaded(self):
        """
        Test if dependencies were loaded. (Checks if page has been rendered)
        """
        indicator = self.find(".info-page", By.CSS_SELECTOR)
        return indicator is not None

    def load(self):
        """
        Navigate to Web page and wait for loading of all dependencies.
        """
        self.driver.get(self.url)
        runner = self
        WebDriverWait(self.driver, 10).until(
            lambda d: runner.files_loaded()
        )

    def page_raw_source(self):
        """
        Retrieve a raw source of the web page
        """
        host = api.env.host
        cacert = api.env.tls_ca_cert
        conn = util.create_https_connection(host, cafile=cacert)
        conn.request('GET', self.url)
        response = conn.getresponse()
        # check successful response from a server
        assert response.status == 200
        return response.read().decode('utf-8')

    def has_no_child(self, tag, child_tag):
        """
        Check if element with the given tag has no child with the given one
        """
        parent = self.find("#{}".format(tag), By.CSS_SELECTOR)
        if parent is None:
            return True
        child_element = self.find(".//{}".format(child_tag), By.XPATH, parent)
        return child_element is None

    def innerhtml(self, id):
        """
        Extract html text from the current opened page by the given id
        """
        dom_element = self.find("#{}".format(id), By.CSS_SELECTOR)
        return dom_element.get_attribute('innerHTML').split('\n')

    def innerhtml_noscript(self, id, raw_page):
        """
        Extract html text from the given raw source of the page under the
        'noscript' html tag with the given id
        """
        html_tree = html.fromstring(raw_page)
        noscript_tree = html_tree.xpath(
            "//div[@id='{}']/noscript/*".format(id)
        )
        noscript_html_text = ''.join([html.tostring(elem, encoding="unicode")
                                      for elem in noscript_tree])
        noscript_html = []
        # remove trailing whitespaces between close and open tags
        for html_row in noscript_html_text.split('\n'):
            noscript_html.append(sub('^[ ]+(?=(<|[ ]*$))', '', html_row))
        return noscript_html

    def check_noscript_innerhtml(self, html_id):
        """
        Compare inner html under enabled javascript and disabled one
        """
        # check if js is enabled in browser
        assert self.has_no_child(html_id, 'noscript')
        html_js_enabled = self.innerhtml(html_id)

        raw_page = self.page_raw_source()
        html_js_disabled = self.innerhtml_noscript(html_id, raw_page)
        assert html_js_enabled == html_js_disabled


@pytest.mark.tier1
class TestSsbrowserPage(ConfigPageBase):
    """
    Test translation of ssbrowser.html page
    """

    page_name = 'ssbrowser.html'

    @screenshot
    def test_long_text_of_ssbrowser_page(self):
        """
        Tests whether the text from '@i18n:ssbrowser-page' is synced
        against '<noscript>' tag to ensure a similarity of the behavior.
        """

        self.init_app()
        self.check_noscript_innerhtml('ssbrowser-msg')


@pytest.mark.tier1
class TestUnauthorizedPage(ConfigPageBase):
    """
    Test translation of unauthorized.html page
    """

    page_name = 'unauthorized.html'

    @screenshot
    def test_long_text_of_unauthorized_page(self):
        """
        Tests whether the text from '@i18n:unauthorized-page' is synced
        against '<noscript>' tag to ensure a similarity of the behavior.
        """

        self.init_app()
        self.check_noscript_innerhtml('unauthorized-msg')
