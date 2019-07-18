#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Test LoginScreen widget and all it's views
"""
import urllib

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_loginscreen as loginscreen

try:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.wait import WebDriverWait
except ImportError:
    pass

import pytest


@pytest.mark.tier1
class TestLoginScreen(UI_driver):

    def setup(self, *args, **kwargs):
        super(TestLoginScreen, self).setup(*args, **kwargs)
        self.init_app()
        self.add_test_user()
        self.logout()

    def teardown(self, *args, **kwargs):
        # log out first
        if (self.logged_in()):
            self.logout()
        else:
            self.load_url(self.get_base_url())
        # log in as administrator
        self.login()
        self.delete_test_user()
        super(TestLoginScreen, self).teardown(*args, **kwargs)

    def delete_test_user(self):
        """
        Delete user for tests
        """
        # User is not logged in
        assert self.logged_in()
        self.navigate_to_entity(loginscreen.ENTITY)
        self.delete_record(loginscreen.PKEY)

    def add_test_user(self):
        """
        Add user for tests
        """
        # User is not logged in
        assert self.logged_in()
        self.add_record(loginscreen.ENTITY, loginscreen.DATA_ITEST_USER,
                        navigate=False)

    def assert_notification(self, type='success', assert_text=None,
                            link_text=None, link_url=None):
        """
        Assert whether we have a notification of particular type
        """

        notification_type = 'div.validation-summary .alert-{}'.format(type)
        # wait for a half sec for notification to appear
        self.wait(0.5)
        is_present = self.find(notification_type, By.CSS_SELECTOR)
        # Notification not present
        assert is_present
        if assert_text:
            assert assert_text in is_present.text

        if link_text and link_url:
            link = self.find_xelement(".//a", is_present)
            # Text on link placed on validation widget
            assert link_text == link.text
            # URL of link placed on validation widget
            assert link_url == link.get_attribute('href')

    def find_xelement(self, expression, parent, strict=True):
        """
        Find element by xpath related to a given parent
        """
        return self.find(expression, By.XPATH, parent, many=False,
                         strict=strict)

    def find_xelements(self, expression, parent, strict=True):
        """
        Find elements by xpath related to the given parent
        """
        return self.find(expression, By.XPATH, parent, many=True,
                         strict=strict)

    def button_click_on_login_screen(self, name):
        """
        Find a button with the given name on LoginScreen widget and
        then click on
        """
        login_screen = self.get_login_screen()
        button = self.find_xelement(".//button[@name='{}']".format(name),
                                    login_screen)
        assert button.is_displayed()
        button.click()

    def get_input_field(self, name, parent):
        """
        Find a input field with the given name and parent
        """
        return self.find_xelement(
            ".//input[@name='{}']".format(name),
            parent
        )

    def load_url(self, url):
        """
        Navigate to Web page and wait for loading of all dependencies.
        """
        self.driver.get(url)
        runner = self
        WebDriverWait(self.driver, 10).until(
            lambda d: runner.files_loaded()
        )

    def relogin_with_new_password(self):
        """
        Log out and then log in using a new password.
        It is need to check a new password
        """
        if (self.logged_in()):
            self.logout()
        else:
            self.load_url(self.get_base_url())
        self.login(loginscreen.PKEY, loginscreen.PASSWD_ITEST_USER_NEW)
        # User is not logged in
        assert self.logged_in()

    def reset_password(self, username=None, current_password=None,
                       new_password=None, link_text=None, link_url=None):
        """
        Reset password with the given one
        """
        login_screen = self.get_login_screen()

        if username is not None:
            username_field = self.get_input_field('username', login_screen)
        cur_pass_field = self.get_input_field('current_password', login_screen)
        new_pass_field = self.get_input_field('new_password', login_screen)
        verify_pass_field = self.get_input_field('verify_password',
                                                 login_screen)
        if username is not None:
            username_field.send_keys(username)
        cur_pass_field.send_keys(current_password)
        new_pass_field.send_keys(new_password)
        verify_pass_field.send_keys(new_password)
        verify_pass_field.send_keys(Keys.RETURN)
        self.wait(0.5)
        self.assert_notification(assert_text='Password change complete',
                                 link_text=link_text, link_url=link_url)

    def get_data_from_form_row(self, form_row):
        """
        Parse data from the form record to a comparable structure
        """
        result = []
        label = self.find_xelement(".//label", form_row)
        assert label.is_displayed()
        result.append(label.get_attribute('name'))
        result.append(label.text)
        req = self.find_xelement("./../..", label)
        result.append(self.has_class(req, 'required'))

        field = self.find_xelement(".//input", form_row)
        # not editable field
        editable = field.is_displayed()
        if not editable:
            field = self.find_xelement(".//p", form_row)

        result.append(editable)
        assert field.is_displayed()
        result.append(field.get_attribute('type'))
        result.append(field.get_attribute('name'))
        if not editable:
            result.append(field.text)
        else:
            result.append(field.get_attribute('value'))
        result.append(field.get_attribute('placeholder'))

        return tuple(result)

    def get_data_from_button(self, button):
        """
        Parse data from the button to a comparable structure
        """
        result = []
        result.append(button.get_attribute('name'))
        result.append(button.get_attribute('title'))

        return tuple(result)

    def assert_form_equals(self, actual_form, expected_form):
        """
        Compare two forms
        """
        assert len(actual_form) == len(expected_form)
        for act_row, exp_row in zip(actual_form, expected_form):
            # structure of rows
            # label_name, label_text,
            # required, editable,
            # input_type, input_name,
            # input_text, placeholder
            assert self.get_data_from_form_row(act_row) == exp_row

    def assert_buttons_equal(self, actual_buttons, expected_buttons):
        """
        Compare button sets
        """
        assert len(actual_buttons) == len(expected_buttons)
        for act_button, exp_button in zip(actual_buttons, expected_buttons):
            assert self.get_data_from_button(act_button) == exp_button

    def assert_validations_equal(self, actual_alerts, expected_alerts):
        """
        Compare validation sets
        """
        assert len(actual_alerts) == len(expected_alerts)
        for act_alert, exp_alert in zip(actual_alerts, expected_alerts):
            assert (act_alert.text,) == exp_alert

    def has_validation(self, parent):
        return self.find_xelement(".//div[@name='validation']", parent,
                                  strict=False)

    def check_elements_of_form(self, form_data):

        login_screen = self.get_login_screen()
        form = self.find_xelement(".//div[@class='form-horizontal']",
                                  login_screen)
        # rows
        form_rows = self.find_xelements(
            ".//div[contains(@class, 'form-group')]", form
        )

        form_rows = [el for el in form_rows if el.is_displayed() and not
                     self.has_validation(el)]
        self.assert_form_equals(form_rows, form_data['rows'])

        # buttons
        buttons = self.find_xelements(".//button", login_screen)
        buttons = [el for el in buttons if el.is_displayed()]
        self.assert_buttons_equal(buttons, form_data['buttons'])

    def check_alerts(self, form_data):
        login_screen = self.get_login_screen()

        # Push the the most rigth button to see the Required fields
        # it should be either 'Reset' or 'Reset and Login' or 'Login' button
        self.button_click_on_login_screen(form_data['buttons'][-1][0])

        alerts = self.find_xelements(
            ".//*[@data-name][contains(@class, 'alert-danger')]", login_screen
        )
        required_msgs = form_data['required_msg']
        self.assert_validations_equal(alerts, required_msgs)

    def load_reset_and_login_view(self):

        self.load()
        assert self.login_screen_visible()
        username = loginscreen.PKEY
        current_password = loginscreen.PASSWD_ITEST_USER

        login_screen = self.get_login_screen()
        username_field = self.get_input_field('username', login_screen)
        cur_pass_field = self.get_input_field('password', login_screen)
        username_field.send_keys(username)
        cur_pass_field.send_keys(current_password)
        cur_pass_field.send_keys(Keys.RETURN)
        self.wait()
        self.assert_notification(
            type='info',
            assert_text=(
                'Your password has expired. Please enter a new password.'
            )
        )

    def check_cancel(self):
        """
        Check 'login' view after a cancel of password reset
        """
        self.button_click_on_login_screen('cancel')
        self.check_elements_of_form(loginscreen.FILLED_LOGIN_FORM)

    @screenshot
    def test_reset_password_view(self):

        self.load_url('/'.join((self.get_base_url(), 'reset_password.html')))
        assert self.login_screen_visible()

        self.check_elements_of_form(loginscreen.RESET_PASSWORD_FORM)
        self.check_alerts(loginscreen.RESET_PASSWORD_FORM)

        username = loginscreen.PKEY
        current_password = loginscreen.PASSWD_ITEST_USER
        new_password = loginscreen.PASSWD_ITEST_USER_NEW
        self.reset_password(username, current_password, new_password)
        self.relogin_with_new_password()

    @screenshot
    def test_reset_password_view_with_redirect(self):

        redir_url = self.get_base_url().lower()
        encoded_redir_url = urllib.parse.urlencode({'url': redir_url})
        target_url = '/'.join((self.get_base_url(), 'reset_password.html?{}'))
        self.load_url(target_url.format(encoded_redir_url))
        assert self.login_screen_visible()

        self.check_elements_of_form(loginscreen.RESET_PASSWORD_FORM)
        self.check_alerts(loginscreen.RESET_PASSWORD_FORM)

        username = loginscreen.PKEY
        current_password = loginscreen.PASSWD_ITEST_USER
        new_password = loginscreen.PASSWD_ITEST_USER_NEW
        self.reset_password(username, current_password, new_password,
                            link_text='Continue to next page',
                            link_url=redir_url,
                            )
        self.relogin_with_new_password()

    @screenshot
    def test_reset_password_view_with_delayed_redirect(self):

        redir_url = self.get_base_url().lower() + '/'
        encoded_redir_url = urllib.parse.urlencode(
            {'url': redir_url, 'delay': 5}
        )
        target_url = '/'.join((self.get_base_url(), 'reset_password.html?{}'))
        self.load_url(target_url.format(encoded_redir_url))
        assert self.login_screen_visible()

        self.check_elements_of_form(loginscreen.RESET_PASSWORD_FORM)
        self.check_alerts(loginscreen.RESET_PASSWORD_FORM)
        username = loginscreen.PKEY
        current_password = loginscreen.PASSWD_ITEST_USER
        new_password = loginscreen.PASSWD_ITEST_USER_NEW
        self.reset_password(username, current_password, new_password,
                            link_text='Continue to next page',
                            link_url=redir_url,
                            )
        self.assert_notification(type='info',
                                 assert_text='You will be redirected in ')
        self.wait(3)
        # check url after start delay timer, but before end
        assert self.driver.current_url != redir_url
        self.wait(5)
        assert self.driver.current_url == redir_url
        self.relogin_with_new_password()

    @screenshot
    def test_reset_password_and_login_view(self):

        self.load_reset_and_login_view()
        self.check_elements_of_form(loginscreen.RESET_AND_LOGIN_FORM)
        self.check_alerts(loginscreen.RESET_AND_LOGIN_FORM)

        # check click on 'Cancel' button
        self.check_cancel()
        self.button_click_on_login_screen('login')
        self.wait_for_request()

        # check if user is not logged
        assert not self.logged_in()
        current_password = loginscreen.PASSWD_ITEST_USER
        new_password = loginscreen.PASSWD_ITEST_USER_NEW
        # username is already here, do not fill up
        self.reset_password(current_password=current_password,
                            new_password=new_password)
        # waiting for auto login process
        self.wait(5)
        assert self.logged_in()
        # check again if new password is valid
        self.relogin_with_new_password()

    @screenshot
    def test_login_view(self):

        self.load()

        # check empty 'login' view
        self.check_elements_of_form(loginscreen.EMPTY_LOGIN_FORM)
        self.check_alerts(loginscreen.EMPTY_LOGIN_FORM)

        # check non empty 'login' view
        login_screen = self.get_login_screen()
        username_field = self.get_input_field('username', login_screen)
        username_field.send_keys(loginscreen.PKEY)
        self.wait(0.5)
        self.check_elements_of_form(loginscreen.LOGIN_FORM)
        self.check_alerts(loginscreen.LOGIN_FORM)
