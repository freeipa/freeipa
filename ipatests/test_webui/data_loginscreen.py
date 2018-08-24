#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

ENTITY = 'user'

PKEY = 'itest-user'
PASSWD_ITEST_USER = '12345678'
PASSWD_ITEST_USER_NEW = '87654321'

# used for add/delete fixture test user
DATA_ITEST_USER = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'uid', PKEY),
        ('textbox', 'givenname', 'itest-user-name'),
        ('textbox', 'sn', 'itest-user-surname'),
        ('password', 'userpassword', PASSWD_ITEST_USER),
        ('password', 'userpassword2', PASSWD_ITEST_USER),
    ]
}

# used for checking login form after click Cancel on 'reset' view
FILLED_LOGIN_FORM = {
    # structure of rows
    # label_name, label_text,
    # required, editable,
    # input_type, input_name,
    # input_text, placeholder
    'rows': [
        ('username', 'Username', True, True, 'text', 'username',
         PKEY, 'Username'),
        ('password', 'Password', True, True, 'password', 'password',
         PASSWD_ITEST_USER, 'Password or Password+One-Time-Password'),
    ],
    # structure of buttons
    # button_name, button_title
    'buttons': [
        ('cert_auth', 'Log in using personal certificate'),
        ('sync', 'Sync OTP Token'),
        ('login', 'Log in'),
    ],
    'required_msg': [
        ('Username: Required field',),
        ('Password: Required field',),
    ],
}

# used for checking 'reset_and_login' view
RESET_AND_LOGIN_FORM = {
    # structure of rows
    # label_name, label_text,
    # required, editable,
    # input_type, input_name,
    # input_text, placeholder
    'rows': [
        ('username_r', 'Username', False, False, None, 'username_r',
         PKEY, None),
        ('current_password', 'Current Password', False, True, 'password',
         'current_password', '', 'Current Password'),
        ('otp', 'OTP', False, True, 'password', 'otp', '',
         'One-Time-Password'),
        ('new_password', 'New Password', True, True, 'password',
         'new_password', '', 'New Password'),
        ('verify_password', 'Verify Password', True, True, 'password',
         'verify_password', '', 'New Password'),
    ],
    # structure of buttons
    # button_name, button_title
    'buttons': [
        ('cancel', 'Cancel'),
        ('reset_and_login', 'Reset Password and Log in'),
    ],
    'required_msg': [
        ('New Password: Required field',),
        ('Verify Password: Required field',),
    ],
}

# used for checking 'reset' view
RESET_PASSWORD_FORM = {
    # structure of rows
    # label_name, label_text,
    # required, editable,
    # input_type, input_name,
    # input_text, placeholder
    'rows': [
        ('username', 'Username', True, True, 'text', 'username', '',
         'Username'),
        ('current_password', 'Current Password', True, True, 'password',
         'current_password', '', 'Current Password'),
        ('otp', 'OTP', False, True, 'password', 'otp', '',
         'One-Time-Password'),
        ('new_password', 'New Password', True, True, 'password',
         'new_password', '', 'New Password'),
        ('verify_password', 'Verify Password', True, True, 'password',
         'verify_password', '', 'New Password'),
    ],
    # structure of buttons
    # button_name, button_title
    'buttons': [
        ('reset', 'Reset Password'),
    ],
    'required_msg': [
        ('Username: Required field',),
        ('Current Password: Required field',),
        ('New Password: Required field',),
        ('Verify Password: Required field',),
    ],
}


# used for checking empty 'login' view
EMPTY_LOGIN_FORM = {
    # structure of rows
    # label_name, label_text,
    # required, editable,
    # input_type, input_name,
    # input_text, placeholder
    'rows': [
        ('username', 'Username', False, True, 'text', 'username', '',
         'Username'),
        ('password', 'Password', False, True, 'password', 'password', '',
         'Password or Password+One-Time-Password'),
    ],
    # structure of buttons
    # button_name, button_title
    'buttons': [
        ('cert_auth', 'Log in using personal certificate'),
        ('sync', 'Sync OTP Token'),
        ('login', 'Log in'),
    ],
    'required_msg': [
        ('Authentication with Kerberos failed',),
    ],
}

# used for checking 'login' view
LOGIN_FORM = {
    # structure of rows
    # label_name, label_text,
    # required, editable,
    # input_type, input_name,
    # input_text, placeholder
    'rows': [
        ('username', 'Username', True, True, 'text', 'username', PKEY,
         'Username'),
        ('password', 'Password', True, True, 'password', 'password', '',
         'Password or Password+One-Time-Password'),
    ],
    # structure of buttons
    # button_name, button_title
    'buttons': [
        ('cert_auth', 'Log in using personal certificate'),
        ('sync', 'Sync OTP Token'),
        ('login', 'Log in'),
    ],
    'required_msg': [
        ('Password: Required field',),
    ],
}
