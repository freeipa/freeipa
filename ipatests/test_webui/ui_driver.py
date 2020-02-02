# Authors:
#   Petr Vobornik <pvoborni@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Base class for UI integration tests.

Contains browser driver and common tasks.
"""
from __future__ import print_function, absolute_import

from datetime import datetime
import time
import re
import os
from functools import wraps
import unittest
import paramiko

# pylint: disable=import-error
from six.moves.urllib.error import URLError
# pylint: enable=import-error

try:
    from selenium import webdriver
    from selenium.common.exceptions import NoSuchElementException
    from selenium.common.exceptions import InvalidElementStateException
    from selenium.common.exceptions import StaleElementReferenceException
    from selenium.common.exceptions import UnexpectedAlertPresentException
    from selenium.common.exceptions import WebDriverException
    from selenium.common.exceptions import ElementClickInterceptedException
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.support.expected_conditions import alert_is_present
    from selenium.webdriver.support.wait import WebDriverWait
    from selenium.webdriver.support.ui import Select
    NO_SELENIUM = False
except ImportError:
    NO_SELENIUM = True
try:
    import yaml
    NO_YAML = False
except ImportError:
    NO_YAML = True
from ipaplatform.paths import paths

ENV_MAP = {
    'MASTER': 'ipa_server',
    'ADMINID': 'ipa_admin',
    'ADMINPW': 'ipa_password',
    'DOMAIN': 'ipa_domain',
    'IPA_REALM': 'ipa_realm',
    'IPA_IP': 'ipa_ip',
    'IPA_NO_CA': 'no_ca',
    'IPA_NO_DNS': 'no_dns',
    'IPA_HAS_TRUSTS': 'has_trusts',
    'IPA_HAS_KRA': 'has_kra',
    'IPA_HOST_CSR_PATH': 'host_csr_path',
    'IPA_SERVICE_CSR_PATH': 'service_csr_path',
    'AD_DOMAIN': 'ad_domain',
    'AD_DC': 'ad_dc',
    'AD_ADMIN': 'ad_admin',
    'AD_PASSWORD': 'ad_password',
    'AD_DC_IP': 'ad_dc_ip',
    'TRUST_SECRET': 'trust_secret',
    'SEL_TYPE': 'type',
    'SEL_BROWSER': 'browser',
    'SEL_HOST': 'host',
    'FF_PROFILE': 'ff_profile',
}

DEFAULT_BROWSER = 'firefox'
DEFAULT_PORT = 4444
DEFAULT_TYPE = 'local'


def screenshot(fn):
    """
    Decorator for saving screenshot on exception (test fail)
    Should be applied on methods of UI_driver subclasses
    """
    @wraps(fn)
    def screenshot_wrapper(*args):
        try:
            return fn(*args)
        except unittest.SkipTest:
            raise
        except Exception:
            self = args[0]
            name = '%s_%s_%s' % (
                datetime.now().isoformat(),
                self.__class__.__name__,
                fn.__name__)
            self.take_screenshot(name)
            raise

    return screenshot_wrapper


def dismiss_unexpected_alert(fn):
    """
    Temporary fix for UnexpectedAlertPresentException.
    It is regression in Firefox 55
    Fixed in Firefox 65:
    https://bugzilla.mozilla.org/show_bug.cgi?id=1503015
    """
    @wraps(fn)
    def wrapped(*args, **kwargs):
        self = args[0]
        try:
            return fn(*args, **kwargs)
        except UnexpectedAlertPresentException:
            if alert_is_present()(self.driver):
                self.driver.switch_to.alert.dismiss()
            # One retry is enough for now.
            # But in the case of catching two alerts at the same time
            # loop or recursive call should be used.
            return fn(*args, **kwargs)
    return wrapped


class UI_driver(object):
    """
    Base class for all UI integration tests
    """

    request_timeout = 60

    @classmethod
    def setup_class(cls):
        if NO_SELENIUM:
            raise unittest.SkipTest('Selenium not installed')
        cls.load_config()

    def setup(self):
        self.driver = self.get_driver()
        self.driver.maximize_window()

    def teardown(self):
        self.driver.delete_all_cookies()
        self.driver.quit()

    @classmethod
    def load_config(cls):
        """
        Load configuration

        1) From ~/.ipa/ui_test.conf
        2) From environmental variables
        """

        # load config file
        path = os.path.join(os.path.expanduser("~"), ".ipa/ui_test.conf")
        if not NO_YAML and os.path.isfile(path):
            try:
                with open(path, 'r') as conf:
                    cls.config = yaml.load(conf)
            except yaml.YAMLError as e:
                raise unittest.SkipTest("Invalid Web UI config.\n%s" % e)
            except IOError as e:
                raise unittest.SkipTest(
                    "Can't load Web UI test config: %s" % e
                )
        else:
            cls.config = {}

        c = cls.config

        # override with environmental variables
        for k, v in ENV_MAP.items():
            val = os.environ.get(k)
            if val is not None:
                c[v] = val

        # apply defaults
        if 'port' not in c:
            c['port'] = DEFAULT_PORT
        if 'browser' not in c:
            c['browser'] = DEFAULT_BROWSER
        if 'type' not in c:
            c['type'] = DEFAULT_TYPE

    @classmethod
    def get_driver(cls):
        """
        Get WebDriver according to configuration
        """
        browser = cls.config["browser"]
        port = cls.config["port"]
        driver_type = cls.config["type"]

        options = None

        if browser == 'chromium':
            options = ChromeOptions()
            options.binary_location = paths.CHROMIUM_BROWSER

        if driver_type == 'remote':
            if 'host' not in cls.config:
                raise unittest.SkipTest('Selenium server host not configured')
            host = cls.config["host"]

            if browser == 'chrome':
                capabilities = DesiredCapabilities.CHROME
            elif browser == 'chromium':
                capabilities = options.to_capabilities()
            elif browser == 'ie':
                capabilities = DesiredCapabilities.INTERNETEXPLORER
            else:
                capabilities = DesiredCapabilities.FIREFOX
            try:
                driver = webdriver.Remote(
                    command_executor='http://%s:%d/wd/hub' % (host, port),
                    desired_capabilities=capabilities)
            except URLError as e:
                raise unittest.SkipTest(
                    'Error connecting to selenium server: %s' % e
                )
            except RuntimeError as e:
                raise unittest.SkipTest(
                    'Error while establishing webdriver: %s' % e
                )
        else:
            try:
                if browser in {'chrome', 'chromium'}:
                    driver = webdriver.Chrome(chrome_options=options)
                elif browser == 'ie':
                    driver = webdriver.Ie()
                else:
                    fp = None
                    if "ff_profile" in cls.config:
                        fp = webdriver.FirefoxProfile(cls.config["ff_profile"])
                    ff_log_path = cls.config.get("geckodriver_log_path")
                    driver = webdriver.Firefox(fp, log_path=ff_log_path)
            except URLError as e:
                raise unittest.SkipTest(
                    'Error connecting to selenium server: %s' % e
                )
            except RuntimeError as e:
                raise unittest.SkipTest(
                    'Error while establishing webdriver: %s' % e
                )

        return driver

    @dismiss_unexpected_alert
    def find(self, expression, by='id', context=None, many=False, strict=False):
        """
        Helper which calls selenium find_element_by_xxx methods.

        expression: search expression
        by: selenium.webdriver.common.by
        context: element to search on. Default: driver
        many: all matching elements
        strict: error out when element is not found

        Returns None instead of raising exception when element is not found.
        """

        assert expression, 'expression is missing'

        if context is None:
            context = self.driver

        if not many:
            method_name = 'find_element'
        else:
            method_name = 'find_elements'

        try:
            func = getattr(context, method_name)
            result = func(by, expression)
        except NoSuchElementException:
            if strict:
                raise
            else:
                result = None

        return result

    def files_loaded(self):
        """
        Test if dependencies were loaded. (Checks if UI has been rendered)
        """
        indicator = self.find(".global-activity-indicator", By.CSS_SELECTOR)
        return indicator is not None

    def has_ca(self):
        """
        FreeIPA server was installed with CA.
        """
        return not self.config.get('no_ca')

    def has_dns(self):
        """
        FreeIPA server was installed with DNS.
        """
        return not self.config.get('no_dns')

    def has_trusts(self):
        """
        FreeIPA server was installed with Trusts.
        """
        return self.config.get('has_trusts')

    def has_kra(self):
        """
        FreeIPA server was installed with Kra.
        """
        return self.config.get('has_kra')

    def has_active_request(self):
        """
        Check if there is running AJAX request
        """
        global_indicators = self.find(".global-activity-indicator", By.CSS_SELECTOR, many=True)
        for el in global_indicators:
            try:
                if not self.has_class(el, 'closed'):
                    return True
            except StaleElementReferenceException:
                # we don't care. Happens when indicator is part of removed dialog.
                continue
        return False

    def wait(self, seconds=0.2):
        """
        Wait specific amount of seconds
        """
        time.sleep(seconds)

    def wait_for_request(self, implicit=0.2, n=1, d=0):
        """
        Wait for AJAX request to finish
        """
        runner = self

        for _i in range(n):
            self.wait(implicit)
            WebDriverWait(self.driver, self.request_timeout).until_not(lambda d: runner.has_active_request())
            self.wait()
        self.wait(d)

    def wait_while_working(self, widget, implicit=0.2):
        """
        Wait while working widget active
        """

        working_widget = self.find('.working-widget', By.CSS_SELECTOR, widget)

        self.wait(implicit)
        WebDriverWait(self.driver, self.request_timeout).until_not(
            lambda d: working_widget.is_displayed()
        )
        self.wait(0.5)

    def xpath_has_val(self, attr, val):
        """
        Create xpath expression for matching a presence of item in attribute
        value where value is a list of items separated by space.
        """
        return "contains(concat(' ',normalize-space(@%s), ' '),' %s ')" % (attr, val)

    def init_app(self, login=None, password=None):
        """
        Load and login
        """
        self.load()
        self.wait(0.5)
        self.login(login, password)
        # metadata + default page
        self.wait_for_request(n=5)

    def load(self):
        """
        Navigate to Web UI first page and wait for loading of all dependencies.
        """
        # if is not any of above cases, we need to load the application for
        # its first time entering the URL in the address bar
        self.driver.get(self.get_base_url())
        runner = self
        WebDriverWait(self.driver, 10).until(lambda d: runner.files_loaded())
        self.wait_for_request()

    def login(self, login=None, password=None, new_password=None):
        """
        Log in if user is not logged in.
        """
        if self.logged_in():
            return

        if login is None:
            login = self.config['ipa_admin']
        if password is None:
            password = self.config['ipa_password']
        if not new_password:
            new_password = password

        auth = self.get_login_screen()
        login_tb = self.find("//input[@type='text'][@name='username']",
                             'xpath', auth, strict=True)
        psw_tb = self.find("//input[@type='password'][@name='password']",
                           'xpath', auth, strict=True)
        login_tb.send_keys(login)
        psw_tb.send_keys(password)
        psw_tb.send_keys(Keys.RETURN)
        self.wait(0.5)
        self.wait_for_request(n=2)

        # reset password if needed
        if self.login_screen_visible():
            newpw_tb = self.find("//input[@type='password'][@name='new_password']", 'xpath', auth)
            verify_tb = self.find("//input[@type='password'][@name='verify_password']", 'xpath', auth)
            if newpw_tb and newpw_tb.is_displayed():
                newpw_tb.send_keys(new_password)
                verify_tb.send_keys(new_password)
                verify_tb.send_keys(Keys.RETURN)
                self.wait(0.5)
                self.wait_for_request(n=2)

    def logged_in(self):
        """
        Check if user is logged in
        """
        login_as = self.find('loggedinas', 'class name')
        visible_name = len(login_as.text) > 0
        logged_in = not self.login_screen_visible() and visible_name
        return logged_in

    def logout(self):

        runner = self

        self.profile_menu_action('logout')
        # it may take some time to get login screen visible
        WebDriverWait(self.driver, self.request_timeout).until(
            lambda d: runner.login_screen_visible())

        assert self.login_screen_visible()

    def get_login_screen(self):
        """
        Get reference of login screen
        """
        return self.find('.login-pf', By.CSS_SELECTOR)

    def login_screen_visible(self):
        """
        Check if login screen is visible
        """
        screen = self.get_login_screen()
        return screen and screen.is_displayed()

    def take_screenshot(self, name):
        if self.config.get('save_screenshots'):
            scr_dir = self.config.get('screenshot_dir')
            path = name + '.png'
            if scr_dir:
                path = os.path.join(scr_dir, path)
            self.driver.get_screenshot_as_file(path)

    def navigate_to_entity(self, entity, facet=None):
        self.driver.get(self.get_url(entity, facet))
        self.wait_for_request(n=3, d=0.4)

    def navigate_by_menu(self, item, complete=True):
        """
        Navigate by using menu
        """

        if complete:
            parts = item.split('/')
            if len(parts) > 1:
                parent = parts[0:-1]
                self.navigate_by_menu('/'.join(parent), complete)

        s = ".navbar a[href='#%s']" % item
        link = self.find(s, By.CSS_SELECTOR, strict=True)
        assert link.is_displayed(), 'Navigation link is not displayed: %s' % item
        link.click()
        self.wait_for_request()
        self.wait_for_request(0.4)

    def navigate_by_breadcrumb(self, item):
        """
        Navigate by breadcrumb navigation
        """
        facet = self.get_facet()
        nav = self.find('.breadcrumb', By.CSS_SELECTOR, facet, strict=True)
        a = self.find(item, By.LINK_TEXT, nav, strict=True)
        a.click()
        self.wait_for_request()
        self.wait_for_request(0.4)

    def switch_to_facet(self, name):
        """
        Click on tab with given name
        """
        facet = self.get_facet()
        tabs = "div.facet-tabs"
        sidebar = "div.sidebar-pf"

        facets_container = self.find(tabs, By.CSS_SELECTOR, facet)

        # handle sidebar instead of facet-tabs
        # the webui facet can have only the facet-tabs OR sidebar, not both
        if not facets_container:
            facets_container = self.find(sidebar, By.CSS_SELECTOR, facet)

        s = "li[name='%s'] a" % name
        link = self.find(s, By.CSS_SELECTOR, facets_container, strict=True)
        link.click()
        # double wait because of facet's paging
        self.wait_for_request(0.5)
        self.wait_for_request()

    def get_url(self, entity, facet=None):
        """
        Create entity url
        """
        url = [self.get_base_url(), '#', 'e', entity]
        if facet:
            url.append(facet)
        return '/'.join(url)

    def get_base_url(self):
        """
        Get FreeIPA Web UI url
        """
        host = self.config.get('ipa_server')
        if not host:
            self.skip('FreeIPA server hostname not configured')
        return 'https://%s/ipa/ui' % host

    def get_facet(self):
        """
        Get currently displayed facet
        """
        facet = self.find('.active-facet', By.CSS_SELECTOR)
        assert facet is not None, "Current facet not found"
        return facet

    def get_facet_info(self, facet=None):
        """
        Get information of currently displayed facet
        """
        info = {}

        # get facet
        if facet is None:
            facet = self.get_facet()
        info["element"] = facet

        #get facet name and entity
        info["name"] = facet.get_attribute('data-name')
        info["entity"] = facet.get_attribute('data-entity')

        # get facet title
        el = self.find(".facet-header h3 *:first-child", By.CSS_SELECTOR, facet)
        if el:
            info["title"] = el.text

        # get facet pkey
        el = self.find(".facet-header h3 span.facet-pkey", By.CSS_SELECTOR, facet)
        if el:
            info["pkey"] = el.text

        return info

    def get_dialogs(self, strict=False, name=None):
        """
        Get all dialogs in DOM
        """
        s = '.modal-dialog'
        if name:
            s += "[data-name='%s']" % name
        dialogs = self.find(s, By.CSS_SELECTOR, many=True)
        if strict:
            assert dialogs, "No dialogs found"
        return dialogs

    def get_dialog(self, strict=False, name=None):
        """
        Get last opened dialog
        """
        dialogs = self.get_dialogs(strict, name)
        dialog = None
        if len(dialogs):
            dialog = dialogs[-1]
        return dialog

    def get_last_error_dialog(self, dialog_name='error_dialog'):
        """
        Get last opened error dialog or None.
        """
        s = ".modal-dialog[data-name='%s']" % dialog_name
        dialogs = self.find(s, By.CSS_SELECTOR, many=True)
        dialog = None
        if dialogs:
            dialog = dialogs[-1]
        return dialog

    def get_dialog_info(self):
        """
        Get last open dialog info: name, text if any.
        Returns None if no dialog is open.
        """
        dialog = self.get_dialog()

        info = None
        if dialog:
            body = self.find('.modal-body', By.CSS_SELECTOR, dialog, strict=True)
            info = {
                'name': dialog.get_attribute('data-name'),
                'text': body.text,
            }
        return info

    def execute_api_from_ui(self, method, args, options, timeout=30):
        """
        Executes FreeIPA API command/method from Web UI
        """
        script = """
        var method = arguments[0];
        var args = arguments[1];
        var options = arguments[2];
        var callback = arguments[arguments.length - 1];
        var rpc = require('freeipa/rpc');

        var cmd = rpc.command({
            method: method,
            args: args,
            options: options,
            on_success: callback,
            on_error: callback
        });

        cmd.execute();
        """
        self.driver.set_script_timeout(timeout)
        result = self.driver.execute_async_script(script, *[method, args, options])
        return result

    def click_on_link(self, text, parent=None):
        """
        Click on link with given text and parent.
        """
        if not parent:
            parent = self.get_form()

        link = self.find(text, By.LINK_TEXT, parent, strict=True)
        link.click()

    def click_undo_button(self, field, parent=None):
        """
        Click undo button/s of particular field
        """
        self.assert_undo_button(field)
        undo_btns = self.get_undo_buttons(field, parent)
        for btn in undo_btns:
            btn.click()
        self.assert_undo_button(field, visible=False)

    def facet_button_click(self, name):
        """
        Click on facet button with given name
        """
        facet = self.get_facet()
        s = ".facet-controls button[name=%s]" % name
        self._button_click(s, facet, name)

    def dialog_button_click(self, name, dialog=None):
        """
        Click on dialog button with given name

        Chooses last dialog if none is supplied
        """
        if not dialog:
            dialog = self.get_dialog(strict=True)

        s = ".rcue-dialog-buttons button[name='%s']" % name
        self._button_click(s, dialog, name)

    def action_button_click(self, name, parent):
        """
        Click on .action-button
        """
        if not parent:
            parent = self.get_form()

        s = "a[name='%s'].action-button" % name
        self._button_click(s, parent, name)

    def button_click(self, name, parent=None,
                     parents_css_sel=None):
        """
        Click on .ui-button
        """
        if not parent:
            if parents_css_sel:
                parent = self.find(parents_css_sel, By.CSS_SELECTOR,
                                   strict=True)
            else:
                parent = self.get_form()

        s = "[name='%s'].btn" % name
        self._button_click(s, parent, name)

    def _button_click(self, selector, parent, name=''):
        btn = self.find(selector, By.CSS_SELECTOR, parent, strict=True)

        # The small timeout (up to 5 seconds) allows to prevent exceptions when
        # driver attempts to click a button before it is rendered.
        WebDriverWait(self.driver, 5, 0.2).until(
            lambda d: btn.is_displayed(),
            'Button is not displayed: %s' % (name or selector)
        )
        self.move_to_element_in_page(btn)

        disabled = btn.get_attribute("disabled")
        assert not disabled, 'Invalid button state: disabled. Button: %s' % name
        btn.click()
        self.wait_for_request()

    def move_to_element_in_page(self, element):
        # workaround to move the page until the element is visible
        # more in https://github.com/mozilla/geckodriver/issues/776
        self.driver.execute_script('arguments[0].scrollIntoView(true);',
                                   element)

    def profile_menu_action(self, name):
        """
        Execute action from profile menu
        """
        menu_toggle = self.find('[name=profile-menu] > a', By.CSS_SELECTOR)
        menu_toggle.click()
        s = "[name=profile-menu] a[href='#%s']" % name
        btn = self.find(s, By.CSS_SELECTOR, strict=True)
        btn.click()
        # action is usually followed by opening a dialog, add wait to compensate
        # possible dialog transition effect
        self.wait(0.5)

    def close_notifications(self):
        """
        Close all notifications like success messages, warnings, infos
        """
        self.wait()
        while True:
            # get close button of notification
            s = ".notification-area .alert button"
            button = self.find(s, By.CSS_SELECTOR, strict=False)
            if button:
                button.click()
                self.wait()
            else:
                break

    def close_all_dialogs(self):
        """
        Close all currently opened dialogs
        """
        self.wait()
        while True:
            s = ".modal.fade.in .modal-header button.close"
            btn = self.find(s, By.CSS_SELECTOR)
            if btn:
                btn.click()
                self.wait(0.5)
            else:
                break

    def get_form(self):
        """
        Get last dialog or visible facet
        """
        form = self.get_dialog()
        if not form:
            form = self.get_facet()
        return form

    def select(self, selector, value, parent=None):
        """
        Select option with given value in select element
        """
        if not parent:
            parent = self.get_form()
        el = self.find(selector, By.CSS_SELECTOR, parent, strict=True)
        Select(el).select_by_value(value)

    def fill_text(self, selector, value, parent=None):
        """
        Clear and enter text into input defined by selector.
        Use for non-standard fields.
        """
        if not parent:
            parent = self.get_form()
        tb = self.find(selector, By.CSS_SELECTOR, parent, strict=True)
        try:
            tb.clear()
            tb.send_keys(value)
        except InvalidElementStateException as e:
            msg = "Invalid Element State, el: %s, value: %s, error: %s" % (selector, value, e)
            assert False, msg

    def fill_input(self, name, value, input_type="text", parent=None):
        """
        Type into input element specified by name and type.
        """
        s = "div[name='%s'] input[type='%s'][name='%s']" % (name, input_type, name)
        self.fill_text(s, value, parent)

    def fill_textarea(self, name, value, parent=None):
        """
        Clear and fill textarea.
        """
        s = "textarea[name='%s']" % (name)
        self.fill_text(s, value, parent)

    def fill_textbox(self, name, value, parent=None):
        """
        Clear and fill textbox.
        """
        self.fill_input(name, value, "text", parent)

    def fill_password(self, name, value, parent=None):
        """
        Clear and fill input[type=password]
        """
        self.fill_input(name, value, "password", parent)

    def fill_search_filter(self, value, parent=None):
        search_field_s = '.search-filter input[name=filter]'
        if not parent:
                parent = self.get_form()
        self.fill_text(search_field_s, value, parent)

    def add_multivalued(self, name, value, parent=None):
        """
        Add new value to multivalued textbox
        """
        if not parent:
            parent = self.get_form()
        s = "div[name='%s'].multivalued-widget" % name
        w = self.find(s, By.CSS_SELECTOR, parent, strict=True)
        add_btn = self.find("button[name=add]", By.CSS_SELECTOR, w, strict=True)
        add_btn.click()
        s = "div[name=value] input"
        inputs = self.find(s, By.CSS_SELECTOR, w, many=True)
        last = inputs[-1]
        last.send_keys(value)

    def edit_multivalued(self, name, value, new_value, parent=None):
        """
        Edit multivalued textbox
        """
        if not parent:
            parent = self.get_form()
        s = "div[name='%s'].multivalued-widget" % name
        w = self.find(s, By.CSS_SELECTOR, parent, strict=True)
        s = "div[name=value] input"
        inputs = self.find(s, By.CSS_SELECTOR, w, many=True)

        for i in inputs:
            val = i.get_attribute('value')
            if val == value:
                i.clear()
                i.send_keys(new_value)

    def undo_multivalued(self, name, value, parent=None):
        """
        Undo multivalued change
        """
        if not parent:
            parent = self.get_form()
        s = "div[name='%s'].multivalued-widget" % name
        w = self.find(s, By.CSS_SELECTOR, parent, strict=True)
        s = "div[name=value] input"
        inputs = self.find(s, By.CSS_SELECTOR, w, many=True)
        clicked = False
        for i in inputs:
            val = i.get_attribute('value')
            n = i.get_attribute('name')
            if val == value:
                s = "input[name='%s'] ~ .input-group-btn button[name=undo]" % n
                link = self.find(s, By.CSS_SELECTOR, w, strict=True)
                link.click()
                self.wait()
                clicked = True
                # lets try to find the undo button element again to check if
                # it is not present or displayed
                link = self.find(s, By.CSS_SELECTOR, w)
                assert not link or not link.is_displayed(), 'Undo btn present'

        assert clicked, 'Value was not undone: %s' % value

    def del_multivalued(self, name, value, parent=None):
        """
        Mark value in multivalued textbox as deleted.
        """
        if not parent:
            parent = self.get_form()
        s = "div[name='%s'].multivalued-widget" % name
        w = self.find(s, By.CSS_SELECTOR, parent, strict=True)
        s = "div[name=value] input"
        inputs = self.find(s, By.CSS_SELECTOR, w, many=True)
        clicked = False
        for i in inputs:
            val = i.get_attribute('value')
            n = i.get_attribute('name')
            if val == value:
                s = "input[name='%s'] ~ .input-group-btn button[name=remove]" % n
                link = self.find(s, By.CSS_SELECTOR, w, strict=True)
                link.click()
                self.wait()
                clicked = True

        assert clicked, 'Value was not removed: %s' % value

    def undo_all_multivalued(self, name, parent=None):
        """
        Undo all new values to multivalued textbox
        """
        if parent is None:
            parent = self.get_form()
        label = "div[name='{}'].multivalued-widget".format(name)
        widget = self.find(label, By.CSS_SELECTOR, parent, strict=True)
        add_btn = self.find("button[name=undo_all]", By.CSS_SELECTOR, widget,
                            strict=True)
        add_btn.click()

    def fill_multivalued(self, name, instructions, parent=None):
        """
        Add or delete a value from multivalued field
        """
        for instruction in instructions:
            t = instruction[0]
            value = instruction[1]
            if t == 'add':
                self.add_multivalued(name, value, parent)
            else:
                self.del_multivalued(name, value, parent)

    def check_option(self, name, value=None, parent=None):
        r"""
        Find checkbox or radio with name which matches ^NAME\d$ and
        check it by clicking on a label.
        """
        if not parent:
            parent = self.get_form()
        s = "//input[@type='checkbox' or 'radio'][contains(@name, '%s')]" % name
        if value is not None:
            s += "[@value='%s']" % value
        opts = self.find(s, "xpath", parent, many=True)
        label = None
        checkbox = None
        # Select only the one which matches exactly the name
        for o in opts:
            n = o.get_attribute("name")
            if n == name or re.match(r"^%s\d+$" % name, n):
                s = "label[for='%s']" % o.get_attribute("id")
                label = self.find(s, By.CSS_SELECTOR, parent, strict=True)
                checkbox = o
                break
        assert label is not None, "Option not found: %s" % name

        try:
            label.click()
        except ElementClickInterceptedException:
            checkbox.click()

    def select_combobox(self, name, value, parent=None, combobox_input=None):
        """
        Select value in a combobox. Search if not found.
        """
        if not parent:
            parent = self.get_form()
        s = "[name='%s'].combobox-widget" % name
        cb = self.find(s, By.CSS_SELECTOR, parent, strict=True)
        open_btn = self.find('a[name=open] i', By.CSS_SELECTOR, cb, strict=True)
        open_btn.click()
        self.wait()
        self.wait_for_request()

        list_cnt = self.find('.combobox-widget-list', By.CSS_SELECTOR, cb, strict=True)
        opt_s = "select[name=list] option[value='%s']" % value
        option = self.find(opt_s, By.CSS_SELECTOR, cb)

        if combobox_input:
            if not option:
                open_btn.click()
                self.fill_textbox(combobox_input, value, cb)
        else:
            if not option:
                # try to search
                self.fill_textbox('filter', value, cb)
                search_btn = self.find('a[name=search] i', By.CSS_SELECTOR, cb,
                                       strict=True)
                search_btn.click()
                self.wait_for_request()
                option = self.find(opt_s, By.CSS_SELECTOR, cb, strict=True)

            option.click()

        # Chrome does not close search area on click
        if list_cnt.is_displayed():
            self.driver.switch_to_active_element().send_keys(Keys.RETURN)

        self.wait()

    def get_text(self, selector, parent=None):
        if not parent:
            parent = self.get_form()

        el = self.find(selector, By.CSS_SELECTOR, parent, strict=True)
        return el.text

    def get_value(self, selector, parent=None):
        if not parent:
            parent = self.get_form()
        el = self.find(selector, By.CSS_SELECTOR, parent, strict=True)
        value = el.get_attribute('value')
        return value

    def get_field_text(self, name, parent=None, element='p'):

        s = ".controls %s[name='%s']" % (element, name)
        return self.get_text(s, parent)

    def get_field_value(self, name, parent=None, element='input'):
        s = ".controls %s[name='%s']" % (element, name)
        return self.get_value(s, parent)

    def get_multivalued_value(self, name, parent=None):

        s = "div[name='%s'] div[name='value'] input[name^='%s']" % (name, name)
        els = self.find(s, By.CSS_SELECTOR, parent, many=True)
        values = []
        for el in els:
            values.append(el.get_attribute('value'))
        return values

    def get_field_checked(self, name, parent=None):
        if not parent:
            parent = self.get_form()
        s = "div[name='%s'] input[name^='%s']" % (name, name)
        els = self.find(s, By.CSS_SELECTOR, parent, strict=True, many=True)
        values = []
        for el in els:
            if el.is_selected():
                values.append(el.get_attribute('value'))
        return values

    def get_field_selected(self, name, parent=None):
        if not parent:
            parent = self.get_form()
        s = "div[name='%s'] select[name='%s']" % (name, name)
        el = self.find(s, By.CSS_SELECTOR, parent, strict=True)
        select = Select(el)
        selected = select.all_selected_options
        values = []
        for opt in selected:
            values.append(opt.get_attribute('value'))
        return values

    def get_undo_buttons(self, field, parent):
        """
        Get field undo button
        """
        if not parent:
            parent = self.get_form()
        s = ".controls div[name='%s'] .btn.undo" % (field)
        undos = self.find(s, By.CSS_SELECTOR, parent, strict=True, many=True)
        return undos

    def get_rows(self, parent=None, name=None):
        """
        Return all rows of search table.
        """
        if not parent:
            parent = self.get_form()

        # select table rows
        s = self.get_table_selector(name)
        s += ' tbody tr'
        rows = self.find(s, By.CSS_SELECTOR, parent, many=True)
        return rows

    def get_row(self, pkey, parent=None, name=None):
        """
        Get row element of search table with given pkey. None if not found.
        """
        rows = self.get_rows(parent, name)
        s = "input[value='%s']" % pkey
        for row in rows:
            has = self.find(s, By.CSS_SELECTOR, row)
            if has:
                return row
        return None

    def navigate_to_row_record(self, row, pkey_column=None):
        """
        Navigate to record by clicking on a link.
        """
        s = 'a'
        if pkey_column:
            s = "div[name='%s'] a" % pkey_column
        link = self.find(s, By.CSS_SELECTOR, row, strict=True)
        link.click()
        self.wait_for_request(0.4)
        self.wait_for_request()

    def get_table_selector(self, name=None):
        """
        Construct table selector
        """
        s = "table"
        if name:
            s += "[name='%s']" % name
        s += '.table'
        return s

    def select_record(self, pkey, parent=None,
                      table_name=None, unselect=False):
        """
        Select record with given pkey in search table.
        """
        if not parent:
            parent = self.get_form()

        s = self.get_table_selector(table_name)
        input_s = s + " tbody td input[value='%s']" % pkey
        checkbox = self.find(input_s, By.CSS_SELECTOR, parent, strict=True)
        try:
            self.move_to_element_in_page(checkbox)
            checkbox.click()
        except WebDriverException as e:
            assert False, 'Can\'t click on checkbox label: %s \n%s' % (s, e)
        self.wait()
        if unselect:
            assert checkbox.is_selected() is not True
            self.wait()
        else:
            assert checkbox.is_selected(), \
                   'Record was not checked: %s' % input_s
            self.wait()

    def select_multiple_records(self, records):
        """
        Select multiple records
        """

        for data in records:
            pkey = data['pkey']
            self.select_record(pkey)

    def get_record_value(self, pkey, column, parent=None, table_name=None):
        """
        Get table column's text value
        """
        row = self.get_row(pkey, parent, table_name)
        s = "div[name=%s]" % column
        val = None
        if row:
            el = self.find(s, By.CSS_SELECTOR, row)
            val = el.text
        return val

    def has_record(self, pkey, parent=None, table_name=None):
        """
        Check if table contains specific record.
        """
        if not parent:
            parent = self.get_form()

        s = self.get_table_selector(table_name)
        s += " tbody td input[value='%s']" % pkey
        checkbox = self.find(s, By.CSS_SELECTOR, parent)
        return checkbox is not None

    def navigate_to_record(self, pkey, parent=None, table_name=None, entity=None, facet='search'):
        """
        Clicks on record with given pkey in search table and thus cause
        navigation to the record.
        """
        if entity:
            self.navigate_to_entity(entity, facet)

        if not parent:
            parent = self.get_facet()

        s = self.get_table_selector(table_name)
        s += " tbody"
        table = self.find(s, By.CSS_SELECTOR, parent, strict=True)
        link = self.find(pkey, By.LINK_TEXT, table, strict=True)
        link.click()
        self.wait_for_request()

    def delete_record(
            self, pkeys, fields=None, parent=None, table_name=None,
            facet_btn='remove', confirm_btn='ok'):
        """
        Delete records with given pkeys in currently opened search table.
        """
        if type(pkeys) is not list:
            pkeys = [pkeys]

        # select
        selected = False
        for pkey in pkeys:
            delete = self.has_record(pkey, parent, table_name)
            if delete:
                self.select_record(pkey, parent, table_name)
                selected = True

        # exec and confirm
        if selected:
            if table_name and parent:
                s = self.get_table_selector(table_name)
                table = self.find(s, By.CSS_SELECTOR, parent, strict=True)
                self.button_click(facet_btn, table)
            else:
                self.facet_button_click(facet_btn)
            if fields:
                self.fill_fields(fields)
            if not confirm_btn:
                return
            self.dialog_button_click(confirm_btn)
            self.wait_for_request(n=2)
            self.wait()

    def delete(self, entity, data_list, facet='search', navigate=True):
        """
        Delete entity records:
        """
        if navigate:
            self.navigate_to_entity(entity, facet)
        for data in data_list:
            pkey = data.get('pkey')
            fields = data.get('del')
            self.delete_record(pkey, fields)

    def fill_fields(
            self, fields, parent=None, undo=False, combobox_input=None):
        """
        Fill dialog or facet inputs with give data.

        Expected format:
        [
            ('widget_type', 'key', value'),
            ('widget_type', 'key2', value2'),
        ]
        """

        if not parent:
            parent = self.get_form()

        for field in fields:
            widget_type = field[0]
            key = field[1]
            val = field[2]

            if undo and not hasattr(key, '__call__'):
                self.assert_undo_button(key, False, parent)

            if widget_type == 'textbox':
                self.fill_textbox(key, val, parent)
            elif widget_type == 'textarea':
                self.fill_textarea(key, val, parent)
            elif widget_type == 'password':
                self.fill_password(key, val, parent)
            elif widget_type == 'radio':
                self.check_option(key, val, parent)
            elif widget_type == 'checkbox':
                self.check_option(key, val, parent=parent)
            elif widget_type == 'selectbox':
                self.select('select[name=%s]' % key, val, parent)
            elif widget_type == 'combobox':
                self.select_combobox(
                    key, val, parent, combobox_input=combobox_input)
            elif widget_type == 'add_table_record':
                self.add_table_record(key, val, parent)
            elif widget_type == 'add_table_association':
                self.add_table_associations(key, val, parent)
            elif widget_type == 'multivalued':
                self.fill_multivalued(key, val, parent)
            elif widget_type == 'table':
                self.select_record(val, parent, key)
            # this meta field specifies a function, to extend functionality of
            # field checking
            elif widget_type == 'callback':
                if hasattr(key, '__call__'):
                    key(val)
            self.wait()
            if undo and not hasattr(key, '__call__'):
                self.assert_undo_button(key, True, parent)

    def validate_fields(self, fields, parent=None):
        """
        Validate that fields on a page or dialog have desired values.
        """
        if not fields:
            return
        if not parent:
            parent = self.get_form()

        for field in fields:
            ftype = field[0]
            key = field[1]
            expected = field[2]
            actual = None

            if ftype == 'label':
                actual = self.get_field_text(key, parent)
            elif ftype in ('textbox', 'password', 'combobox'):
                actual = self.get_field_value(key, parent, 'input')
            elif ftype == 'textarea':
                actual = self.get_field_value(key, parent, 'textarea')
            elif ftype == 'radio':
                actual = self.get_field_checked(key, parent)
            elif ftype == 'checkbox':
                actual = self.get_field_checked(key, parent)
            elif ftype == 'multivalued':
                actual = self.get_multivalued_value(key, parent)
            elif ftype == 'table_record':
                if self.has_record(expected, parent, key):
                    actual = expected

            valid = False
            if type(expected) == list:
                valid = type(actual) == list and sorted(expected) == sorted(actual)
            else:
                # compare other values, usually strings:
                valid = actual == expected

            assert valid, "Values don't match. Expected: '%s', Got: '%s'" % (expected, actual)

    def find_record(self, entity, data, facet='search', dummy='XXXXXXX'):
        """
        Test search functionality of search facet.

        1. search for non-existent value and test if result set is empty.
        2. search for specific pkey and test if it's present on the page
        3. reset search page by not using search criteria
        """

        self.assert_facet(entity, facet)

        facet = self.get_facet()
        search_field_s = '.search-filter input[name=filter]'
        key = data.get('pkey')

        self.fill_text(search_field_s, dummy, facet)
        self.action_button_click('find', facet)
        self.wait_for_request(n=2)
        self.assert_record(key, negative=True)

        self.fill_text(search_field_s, key, facet)
        self.action_button_click('find', facet)
        self.wait_for_request(n=2)
        self.assert_record(key)

        self.fill_text(search_field_s, '', facet)
        self.action_button_click('find', facet)
        self.wait_for_request(n=2)

    def add_record(self, entity, data, facet='search', facet_btn='add',
                   dialog_btn='add', add_another_btn='add_and_add_another',
                   delete=False, pre_delete=True, dialog_name='add',
                   navigate=True, combobox_input=None, negative=False):
        """
        Add records.

        When negative=True we are skipping final assertions.

        Expected data format:
        {
            'pkey': 'key',
            add: [
                ('widget_type', 'key', 'value'),
                ('widget_type', 'key2', 'value2'),
            ],
        }
        """
        if type(data) is not list:
            data = [data]

        last_element = data[len(data) - 1]

        pkeys = []

        for record in data:
            pkeys.append(record['pkey'])
        if navigate:
            self.navigate_to_entity(entity, facet)

        # check facet
        self.assert_facet(entity, facet)

        # delete if exists, ie. from previous test fail

        if pre_delete:
            self.delete(entity, data, navigate=False)

        # current row count
        self.wait_for_request(0.5)
        count = len(self.get_rows())

        # open add dialog
        self.assert_no_dialog()
        self.facet_button_click(facet_btn)
        self.assert_dialog(dialog_name)

        for record in data:

            # fill dialog
            self.fill_fields(record['add'], combobox_input=combobox_input)

            btn = dialog_btn

            if record != last_element:
                btn = add_another_btn

            if not dialog_btn:
                return

            self.dialog_button_click(btn)
            self.wait_for_request()
            self.wait_for_request()

            # check expected error/warning/info
            expected = ['error_4304_info']
            dialog_info = self.get_dialog_info()
            if dialog_info and dialog_info['name'] in expected:
                self.dialog_button_click('ok')
                self.wait_for_request()

            if negative:
                return

            # check for error
            self.assert_no_error_dialog()
            self.wait_for_request()
            self.wait_for_request(0.4)

        if dialog_btn == 'add_and_edit':
            page_pkey = self.get_text('.facet-pkey')
            assert record['pkey'] in page_pkey
            # we cannot delete because we are on different page
            return
        elif dialog_btn == add_another_btn:
            # dialog is still open, we cannot check for records on search page
            # or delete the records
            return
        elif dialog_btn == 'cancel':
            return
        # when standard 'add' was used then it will land on search page
        # and we can check if new item was added - table has more rows
        new_count = len(self.get_rows())
        # adjust because of paging
        expected = count + len(data)
        if count == 20:
            expected = 20
        self.assert_row_count(expected, new_count)

        # delete record
        if delete:
            self.delete(entity, data, navigate=False)
            new_count = len(self.get_rows())
            self.assert_row_count(count, new_count)

    def mod_record(self, entity, data, facet='details', facet_btn='save',
                   negative=False):
        """
        Mod record

        Assumes that it is already on details page.
        """

        self.assert_facet(entity, facet)
        # TODO assert pkey
        self.assert_facet_button_enabled(facet_btn, enabled=False)
        self.fill_fields(data['mod'], undo=True)
        self.assert_facet_button_enabled(facet_btn)
        self.facet_button_click(facet_btn)
        self.wait_for_request()
        self.wait_for_request()

        if negative:
            return
        self.assert_facet_button_enabled(facet_btn, enabled=False)

    def basic_crud(self, entity, data,
                   parent_entity=None,
                   details_facet='details',
                   search_facet='search',
                   default_facet='details',
                   add_facet_btn='add',
                   add_dialog_btn='add',
                   add_dialog_name='add',
                   update_btn='save',
                   breadcrumb=None,
                   navigate=True,
                   mod=True,
                   delete=True):
        """
        Basic CRUD operation sequence.

        Expected data format:
        {
            'pkey': 'key',
            'add': [
                ('widget_type', 'key', 'value'),
                ('widget_type', 'key2', 'value2'),
            ],
            'mod': [
                ('widget_type', 'key', 'value'),
                ('widget_type', 'key2', 'value2'),
            ],
        }
        """

        # important for nested entities. Ie. autoumount maps
        if not parent_entity:
            parent_entity = entity

        pkey = data['pkey']

        # 1. Open Search Facet
        if navigate:
            self.navigate_to_entity(parent_entity)
        self.assert_facet(parent_entity, search_facet)
        self.wait_for_request()

        # 2. Add record
        self.add_record(parent_entity, data, facet=search_facet,
                        navigate=False, facet_btn=add_facet_btn,
                        dialog_name=add_dialog_name, dialog_btn=add_dialog_btn)

        self.close_notifications()

        # Find
        self.find_record(parent_entity, data, search_facet)

        # 3. Navigate to details facet
        self.navigate_to_record(pkey)
        self.assert_facet(entity, default_facet)
        self.wait_for_request(0.5)
        if default_facet != details_facet:
            self.switch_to_facet(details_facet)
            self.assert_facet(entity, details_facet)

        self.validate_fields(data.get('add_v'))

        # 4. Mod values
        if mod and data.get('mod'):
            self.mod_record(entity, data, details_facet, update_btn)
            self.validate_fields(data.get('mod_v'))

        self.close_notifications()

        if not breadcrumb:
            self.navigate_to_entity(entity, search_facet)
        else:
            self.navigate_by_breadcrumb(breadcrumb)

        # 5. Delete record
        if delete:
            self.delete_record(pkey, data.get('del'))
            self.close_notifications()

    def add_table_record(self, name, data, parent=None):
        """
        Add record to dnsrecord table, association table and similar
        """
        if not parent:
            parent = self.get_form()
        s = self.get_table_selector(name)
        table = self.find(s, By.CSS_SELECTOR, parent, strict=True)
        s = ".btn[name=%s]" % 'add'
        btn = self.find(s, By.CSS_SELECTOR, table, strict=True)
        btn.click()
        self.wait()
        self.fill_fields(data['fields'])
        self.dialog_button_click('add')
        self.wait_for_request()

    def prepare_associations(
            self, pkeys, facet=None, facet_btn='add', member_pkeys=None,
            confirm_btn='add', search=False):
        """
        Helper function for add_associations and delete_associations
        """
        if facet:
            self.switch_to_facet(facet)

        self.facet_button_click(facet_btn)
        self.wait()
        self.wait_for_request()

        if search is True:
            for key in pkeys:
                search_field_s = '.adder-dialog-top input[name="filter"]'
                self.fill_text(search_field_s, key)
                self._button_click(selector="button[name='find'].btn-default",
                                   parent=None)
                self.wait_for_request()
                self.select_record(key, table_name='available')
                self.button_click('add')
        else:
            for key in pkeys:
                self.select_record(key, table_name='available')
            self.button_click('add')

        self.dialog_button_click(confirm_btn)
        self.wait_for_request()

        if member_pkeys:
            check_pkeys = member_pkeys
        else:
            check_pkeys = pkeys

        return check_pkeys

    def add_associations(
            self, pkeys, facet=None, delete=False, facet_btn='add',
            member_pkeys=None, confirm_btn='add', search=False):
        """
        Add associations
        """
        check_pkeys = self.prepare_associations(
            pkeys, facet, facet_btn, member_pkeys, confirm_btn, search)

        # we need to return if we want to "cancel" to avoid assert record fail
        if confirm_btn == 'cancel':
            return

        for key in check_pkeys:

            self.assert_record(key)
            if delete:
                self.delete_record(key)
                self.assert_record(key, negative=True)

    def delete_associations(
            self, pkeys, facet=None, facet_btn='remove', member_pkeys=None):
        """
        Remove associations
        """
        check_pkeys = self.prepare_associations(
            pkeys, facet, facet_btn, member_pkeys)

        for key in check_pkeys:
            self.assert_record(key, negative=True)

    def add_table_associations(self, table_name, pkeys, parent=False,
                               delete=False, confirm_btn='add',
                               negative=False):
        """
        Add value to table (association|rule|...)
        """
        if not parent:
            parent = self.get_form()

        s = self.get_table_selector(table_name)
        table = self.find(s, By.CSS_SELECTOR, parent, strict=True)

        s = "button[name='%s']" % 'add'
        btn = self.find(s, By.CSS_SELECTOR, table, strict=True)
        btn.click()
        self.wait_for_request(0.4)

        for key in pkeys:
            self.select_record(key, table_name='available')
            self.button_click('add')
            self.wait()

        self.dialog_button_click(confirm_btn)

        if confirm_btn == 'cancel':
            self.assert_record(key, parent, table_name, negative=True)
            return
        self.wait_for_request(n=2)

        if negative:
            return

        for key in pkeys:
            self.assert_record(key, parent, table_name)
        if delete:
            self.delete_record(pkeys, None, parent, table_name)
            for key in pkeys:
                self.assert_record(key, parent, table_name, negative=True)

    def action_list_action(self, name, confirm=True, confirm_btn="ok",
                           parents_css_sel=None):
        """
        Execute action list action
        """
        context = None

        if not parents_css_sel:
            context = self.find(".active-facet .facet-actions",
                                By.CSS_SELECTOR, strict=True)
        else:
            context = self.find(parents_css_sel, By.CSS_SELECTOR,
                                strict=True)

        expand = self.find(".dropdown-toggle", By.CSS_SELECTOR, context,
                           strict=True)
        expand.click()
        action_link = self.find("li[data-name=%s] a" % name, By.CSS_SELECTOR,
                                context, strict=True)
        self.move_to_element_in_page(action_link)
        action_link.click()
        if confirm:
            self.wait(0.5)  # wait for dialog
            self.dialog_button_click(confirm_btn)
        self.wait()

    def action_panel_action(self, panel_name, action):
        """
        Execute action from action panel with given name.
        """
        s = "div[data-name='%s'].action-panel" % panel_name
        s += " a[data-name='%s']" % action
        link = self.find(s, By.CSS_SELECTOR, strict=True)
        link.click()
        self.wait()

    def enable_action(self):
        """
        Execute and test 'enable' action panel action.
        """
        title = self.find('.active-facet div.facet-title', By.CSS_SELECTOR, strict=True)
        self.action_list_action('enable')
        self.wait_for_request(n=2)
        self.assert_no_error_dialog()
        self.assert_class(title, 'disabled', negative=True)

    def disable_action(self):
        """
        Execute and test 'disable' action panel action.
        """
        title = self.find('.active-facet div.facet-title', By.CSS_SELECTOR, strict=True)
        self.action_list_action('disable')
        self.wait_for_request(n=2)
        self.assert_no_error_dialog()
        self.close_notifications()
        self.move_to_element_in_page(title)
        self.assert_class(title, 'disabled')

    def delete_action(self, entity, pkey, action='delete', facet='search'):
        """
        Execute and test 'delete' action panel action.
        """
        self.action_list_action(action)
        self.wait_for_request(n=4)
        self.assert_no_error_dialog()
        self.assert_facet(entity, facet)
        self.assert_record(pkey, negative=True)

    def mod_rule_tables(self, tables, categories, no_categories):
        """
        Test functionality of rule table widgets in a facet
        """
        def get_t_vals(t):
            table = t[0]
            k = t[1]
            e = []
            if len(t) > 2:
                e = t[2]
            return table, k, e

        t_list = [t[0] for t in tables if t[0] not in no_categories]

        # add values
        for t in tables:
            table, keys, _exts = get_t_vals(t)
            # add one by one to test for #3711
            for key in keys:
                self.add_table_associations(table, [key])

        #disable tables
        for cat in categories:
            self.check_option(cat, 'all')

        # update
        self.assert_rule_tables_enabled(t_list, False)
        self.facet_button_click('save')
        self.wait_for_request(n=3, d=0.3)
        self.assert_rule_tables_enabled(t_list, False)

        p = self.get_form()
        # now tables in categories should be empty, check it
        for t in tables:
            table, keys, _exts = get_t_vals(t)
            if table in no_categories:
                # clear the rest
                self.delete_record(keys, None, p, table)
                continue
            for key in keys:
                self.assert_record(key, p, table, negative=True)

        # enable tables
        for cat in categories:
            self.check_option(cat, '')
        self.assert_rule_tables_enabled(t_list, True)
        self.facet_button_click('save')
        self.wait_for_request(n=3, d=0.3)
        self.assert_rule_tables_enabled(t_list, True)

        for t in tables:
            table, keys, _exts = get_t_vals(t)
            # add multiple at once and test table delete button
            self.add_table_associations(table, keys, delete=True)

    def add_sshkey_to_record(self, ssh_keys, pkey, entity='user',
                             navigate=False, save=True):
        """
        Add ssh public key to particular record

        ssh_keys (list): public ssh key(s)
        pkey (str): user/host/idview to add the key to
        entity (str): name of entity where to navigate if navigate=True
        navigate (bool): whether we should navigate to record
        save (bool): whether we should click save after adding a key
        """

        if type(ssh_keys) is not list:
            ssh_keys = [ssh_keys]

        if navigate:
            self.navigate_to_entity(entity)
            self.navigate_to_record(pkey)

        for key in ssh_keys:
            s_add = 'div[name="ipasshpubkey"] button[name="add"]'
            ssh_add_btn = self.find(s_add, By.CSS_SELECTOR, strict=True)
            ssh_add_btn.click()
            self.wait()
            s_text_area = 'textarea.certificate'
            text_area = self.find(s_text_area, By.CSS_SELECTOR, strict=True)
            text_area.send_keys(key)
            self.wait()
            self.dialog_button_click('update')

        # sometimes we do not want to save e.g. in order to test undo buttons
        if save:
            self.facet_button_click('save')

    def delete_record_sshkeys(self, pkey, entity='user', navigate=False):
        """
        Delete all ssh public keys of particular record

        pkey (str): user/host/idview to add the key to
        entity (str): name of entity where to navigate if navigate=True
        navigate (bool): whether we should navigate to record
        """

        if navigate:
            self.navigate_to_entity(entity)
            self.navigate_to_record(pkey)

        ssh_pub = 'div[name="ipasshpubkey"] button[name="remove"]'
        rm_btns = self.find(ssh_pub, By.CSS_SELECTOR, many=True)
        assert rm_btns, 'No SSH keys to be deleted found on current page'

        for btn in rm_btns:
            btn.click()

        self.facet_button_click('save')

    def assert_num_ssh_keys(self, num):
        """
        Assert number of SSH keys we have associated with the user
        """

        s_keys = 'div[name="ipasshpubkey"] .widget[name="value"]'
        ssh_keys = self.find(s_keys, By.CSS_SELECTOR, many=True)

        num_ssh_keys = len(ssh_keys) if not None else 0

        assert num_ssh_keys == num, \
            ('Number of SSH keys does not match. '
             'Expected: {}, Got: {}'.format(num, num_ssh_keys))

    def undo_ssh_keys(self, btn_name='undo'):
        """
        Undo either one SSH key or all of them

        Possible options:
        btn_name='undo'
        btn_name='undo_all'
        """

        s_undo = 'div[name="ipasshpubkey"] button[name="{}"]'.format(btn_name)
        undo = self.find(s_undo, By.CSS_SELECTOR, strict=True)
        undo.click()
        self.wait(0.6)

    def run_cmd_on_ui_host(self, cmd):
        """
        Run "shell" command on the UI system using "admin" user's passwd from
        conf.
        Use only where API does not fit.

        cmd (str): command to run
        """

        login = self.config.get('ipa_admin')
        hostname = self.config.get('ipa_server')
        password = self.config.get('ipa_password')

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=hostname, username=login, password=password)
            ssh.exec_command(cmd)
        except paramiko.AuthenticationException:
            self.skip('Authentication to server {} failed'.format(hostname))
        except paramiko.SSHException as e:
            self.skip('Unable to establish SSH connection: {}'.format(e))
        except Exception as e:
            self.skip('Unable to proceed: {}'.format(e))
        finally:
            ssh.close()

    @dismiss_unexpected_alert
    def has_class(self, el, cls):
        """
        Check if el has CSS class
        """
        class_attr = el.get_attribute("class")
        return bool(class_attr) and cls in class_attr.split()

    def skip(self, reason):
        """
        Skip tests
        """
        raise unittest.SkipTest(reason)

    def assert_text(self, selector, value, parent=None):
        """
        Assert read-only text value in details page or in a form
        """
        text = self.get_text(selector, parent)
        text = text.strip()
        value = value.strip()
        assert text == value, "Invalid value: '%s' Expected: %s" % (text, value)

    def assert_text_field(self, name, value, parent=None, element='label'):
        """
        Assert read-only text value in details page or in a form
        """
        s = "div[name='%s'] %s[name='%s']" % (name, element, name)
        self.assert_text(s, value, parent)

    def assert_empty_value(self, selector, parent=None, negative=False):
        """
        Assert empty value of some field in details page or in a form
        """
        value = self.get_value(selector, parent)

        if negative:
            assert not value == ''
        else:
            assert value == ''

    def assert_no_dialog(self):
        """
        Assert that no dialog is opened
        """
        dialogs = self.get_dialogs()
        assert not dialogs, 'Invalid state: dialog opened'

    def assert_dialog(self, name=None):
        """
        Assert that one dialog is opened or a dialog with given name
        """
        dialogs = self.get_dialogs(name)
        assert len(dialogs) == 1, 'No or more than one dialog opened'

    def assert_no_error_dialog(self):
        """
        Assert that no error dialog is opened
        """
        dialog = self.get_last_error_dialog()
        ok = dialog is None
        if not ok:
            msg = self.find('p', By.CSS_SELECTOR, dialog).text
            assert ok, 'Unexpected error: %s' % msg

    def assert_row_count(self, expected, current):
        """
        Assert that row counts match
        """
        assert expected == current, "Rows don't match. Expected: %d, Got: %d" % (expected, current)

    def assert_button_enabled(self, name, context_selector=None, enabled=True):
        """
        Assert that button is enabled or disabled (expects that element will be
        <button>)
        """
        s = ""
        if context_selector:
            s = context_selector
        s += "button[name=%s]" % name
        facet = self.get_facet()
        btn = self.find(s, By.CSS_SELECTOR, facet, strict=True)
        valid = enabled == btn.is_enabled()
        assert btn.is_displayed(), 'Button is not displayed'
        assert valid, 'Button (%s) has incorrect enabled state (enabled==%s).' % (s, enabled)

    def assert_facet_button_enabled(self, name, enabled=True):
        """
        Assert that facet button is enabled or disabled
        """
        self.assert_button_enabled(name, ".facet-controls ", enabled)

    def assert_table_button_enabled(self, name, table_name, enabled=True):
        """
        Assert that button in table is enabled/disabled
        """
        s = "table[name='%s'] " % table_name
        self.assert_button_enabled(name, s, enabled)

    def assert_facet(self, entity, facet=None):
        """
        Assert that current facet is correct
        """
        info = self.get_facet_info()
        if not facet is None:
            assert info["name"] == facet, "Invalid facet. Expected: %s, Got: %s " % (facet, info["name"])
        assert info["entity"] == entity, "Invalid entity. Expected: %s, Got: %s " % (entity, info["entity"])

    def assert_undo_button(self, field, visible=True, parent=None):
        """
        Assert that undo button is or is not visible
        """
        undos = self.get_undo_buttons(field, parent)
        state = False
        for undo in undos:
            if undo.is_displayed():
                state = True
                break
        if visible:
            assert state, "Undo button not visible. Field: %s" % field
        else:
            assert not state, "Undo button visible. Field: %s" % field

    def assert_visible(self, selector, parent=None, negative=False):
        """
        Assert that element defined by selector is visible
        """
        if not parent:
            parent = self.get_form()
        el = self.find(selector, By.CSS_SELECTOR, parent, strict=True)
        visible = el.is_displayed()
        if negative:
            assert not visible, "Element visible: %s" % selector
        else:
            assert visible, "Element not visible: %s" % selector

    def assert_disabled(self, selector, parent=None, negative=False):
        """
        Assert that element defined by selector is disabled
        """
        if not parent:
            parent = self.get_form()
        self.find(selector, By.CSS_SELECTOR, parent, strict=True)
        dis = self.find(selector+"[disabled]", By.CSS_SELECTOR, parent)
        if negative:
            assert dis is None, "Element is disabled: %s" % selector
        else:
            assert dis, "Element is not disabled: %s" % selector

    def assert_record(self, pkey, parent=None, table_name=None, negative=False):
        """
        Assert that record is in current search table
        """
        has = self.has_record(pkey, parent, table_name)
        has |= self.has_record(pkey.lower(), parent, table_name)
        if negative:
            assert not has, "Record exists when it shouldn't: %s" % pkey
        else:
            assert has, 'Record does not exist: %s' % pkey

    def assert_indirect_record(self, pkey, entity, facet, negative=False, switch=True):
        """
        Switch to indirect facet and assert record.

        Lowers the key by default.
        """
        if switch:
            self.switch_to_facet(facet)
            radio_name = "%s-%s-type-radio" % (entity, facet.replace('_', '-'))
            self.check_option(radio_name, 'indirect')
            self.wait_for_request(n=2)
        key = pkey
        self.assert_record(key, negative=negative)

    def assert_record_value(self, expected, pkeys, column, parent=None,
                            table_name=None):
        """
        Assert that column's value of record defined by pkey equals expected
        value.
        """

        if type(pkeys) is not list:
            pkeys = [pkeys]

        for pkey in pkeys:
            val = self.get_record_value(pkey, column, parent, table_name)
            assert expected == val, ("Invalid value: '%s'. Expected: '%s'."
                                     % (val, expected))

    def assert_class(self, element, cls, negative=False):
        """
        Assert that element has certain class
        """
        valid = self.has_class(element, cls)
        if negative:
            assert not valid, "Element contains unwanted class: %s" % cls
        else:
            assert valid, "Element doesn't contain required class: %s" % cls

    def assert_rule_tables_enabled(self, tables, enabled):
        """
        Assert that rule table is editable - values can be added and removed.
        """
        for table in tables:
            self.assert_table_button_enabled('add', table, enabled)

    def assert_menu_item(self, path, present=True):
        """
        Assert that menu link is not rendered or visible
        """
        s = ".navigation a[href='#%s']" % path
        link = self.find(s, By.CSS_SELECTOR)
        is_present = link is not None and link.is_displayed()
        assert present == is_present, ('Invalid state of navigation item: %s. '
                                       'Presence expected: %s') % (path, str(present))

    def assert_action_panel_action(self, panel_name, action, visible=True, enabled=True):
        """
        Assert that action panel action is visible/hidden, and enabled/disabled

        Enabled is checked only if action is visible.
        """
        s = "div[data-name='%s'].action-panel" % panel_name
        s += " a[data-name='%s']" % action
        link = self.find(s, By.CSS_SELECTOR)

        is_visible = link is not None and link.is_displayed()
        is_enabled = False
        if is_visible:
            is_enabled = not self.has_class(link, 'disabled')

        assert is_visible == visible, ('Invalid visibility of action button: %s. '
                                       'Expected: %s') % (action, str(visible))

        if is_visible:
            assert is_enabled == enabled, ('Invalid enabled state of action button %s. '
                                           'Expected: %s') % (action, str(visible))

    def assert_action_list_action(self, action, visible=True, enabled=True,
                                  parent=None, parents_css_sel=None,
                                  facet_actions=True):
        """
        Assert that action dropdown action is visible/hidden, and enabled/disabled

        Enabled is checked only if action is visible.
        """

        li_s = " li[data-name='%s']" % action

        if not parent:
            parent = self.get_form()

        if facet_actions:
            li_s = ".facet-actions" + li_s
        else:
            li_s = parents_css_sel + li_s

        li = self.find(li_s, By.CSS_SELECTOR, parent)
        link = self.find("a", By.CSS_SELECTOR, li)

        is_visible = li is not None and link is not None
        is_enabled = False

        assert is_visible == visible, ('Invalid visibility of action item: %s. '
                                       'Expected: %s') % (action, str(visible))

        if is_visible:
            is_enabled = not self.has_class(li, 'disabled')
            assert is_enabled == enabled, ('Invalid enabled state of action item %s. '
                                           'Expected: %s') % (action, str(visible))

    def assert_field_validation(self, expect_error, parent=None, field=None):
        """
        Assert for error in field validation
        """

        if not parent:
            parent = self.get_form()

        if field:
            field_s = '.widget[name="{}"]'.format(field)
            parent = self.find(field_s, By.CSS_SELECTOR, context=parent)

        req_field_css = '.help-block[name="error_link"]'

        res = self.find(req_field_css, By.CSS_SELECTOR, context=parent)
        assert expect_error in res.text, \
            'Expected error: {} not found'.format(expect_error)

    def assert_field_validation_required(self, parent=None, field=None):
        self.assert_field_validation('Required field', parent, field)

    def assert_notification(self, type='success', assert_text=None):
        """
        Assert whether we have a notification of particular type

        type: type for assertion
        assert_text: assert particular text when True

        Returns True if selector/text found
        """

        notification_type = 'div.notification-area .alert-{}'.format(type)
        # wait for a half sec for notification to appear
        self.wait(0.5)
        is_present = self.find(notification_type, By.CSS_SELECTOR)
        assert is_present, "Notification not present"
        if assert_text:
            assert assert_text in is_present.text

    def assert_last_error_dialog(self, expected_err, details=False,
                                 dialog_name='error_dialog'):
        """
        Assert error dialog body text or when details=True click on
        'Show details' and assert text there
        """

        err_dialog = self.get_last_error_dialog(dialog_name=dialog_name)

        if details:
            # open "Show details" paragraph
            s = 'a[title="Show details"]'
            details = self.find(s, By.CSS_SELECTOR)
            details.click()

            s = 'ul.error-container li p'
            self.assert_text(s, expected_err, parent=err_dialog)

        else:
            s = '.modal-body div p'
            self.assert_text(s, expected_err, parent=err_dialog)

    def assert_value_checked(self, values, name, negative=False):
        """
        Assert particular value is checked
        """

        if type(values) is not list:
            values = [values]

        checked_values = self.get_field_checked(name)

        for value in values:
            if negative:
                assert value not in checked_values, (
                    '{} checked while it should not be'.format(value)
                )
            else:
                assert value in checked_values, ('{} NOT checked while it '
                                                 'should be'.format(value))
