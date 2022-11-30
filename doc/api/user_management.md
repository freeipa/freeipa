# User Management Examples

This guide provides various examples for performing common tasks related to
user management using IPA's API. 

- [User Management Examples](#user-management-examples)
  - [Adding a user](#adding-a-user)
  - [Finding a user](#finding-a-user)
  - [Showing user information](#showing-user-information)
  - [Modifying a user](#modifying-a-user)
  - [Deleting a user](#deleting-a-user)
  - [Adding a certificate for a user](#adding-a-certificate-for-a-user)
  - [Removing a certificate from a user](#removing-a-certificate-from-a-user)
  - [Disabling a user](#disabling-a-user)
  - [Enabling a user](#enabling-a-user)

## Adding a user

Create a user for John Smith, with `jsmith` as username and OTP as the supported
user authentication.

```python
api.Command.user_add("jsmith", givenname="John", sn="Smith", ipauserauthtype="otp")
```

## Finding a user

Find all users in the `admins` group that match `bob` as search criteria.

```python
api.Command.user_find(criteria="bob", in_group="admins")
```

## Showing user information

Show all available information about the admin user.

```python
api.Command.user_show("admin", all=True)
```

## Modifying a user

Modify a user's email address.

```python
api.Command.user_mod("bob", mail="bob@example.org")
```

## Deleting a user

Delete a user.

```python
api.Command.user_del("bob")
```

The `preserve` option can be used to save this user's entry on deletion. 
This way, the user can undeleted by running the `user_undel` command.


## Adding a certificate for a user

Add a certificate for a user. This certificate must be Base-64 encoded.

```python
args = ["bob"]
kw = {
    "usercertificate": """
      MIICYzCCAcygAwIBAgIBADANBgkqhkiG9w0BAQUFADAuMQswCQYDVQQGEwJVUzEMMAoGA1UEC
      hMDSUJNMREwDwYDVQQLEwhMb2NhbCBDQTAeFw05OTEyMjIwNTAwMDBaFw0wMDEyMjMwNDU5NT
      laMC4xCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNJQk0xETAPBgNVBAsTCExvY2FsIENBMIGfMA0
      GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD2bZEo7xGaX2/0GHkrNFZvlxBou9v1Jmt/PDiTMPve
      8r9FeJAQ0QdvFST/0JPQYD20rH0bimdDLgNdNynmyRoS2S/IInfpmf69iyc2G0TPyRvmHIiOZ
      bdCd+YBHQi1adkj17NDcWj6S14tVurFX73zx0sNoMS79q3tuXKrDsxeuwIDAQABo4GQMIGNME
      sGCVUdDwGG+EIBDQQ+EzxHZW5lcmF0ZWQgYnkgdGhlIFNlY3VyZVdheSBTZWN1cml0eSBTZXJ
      2ZXIgZm9yIE9TLzM5MCAoUkFDRikwDgYDVR0PAQH/BAQDAgAGMA8GA1UdEwEB/wQFMAMBAf8w
      HQYDVR0OBBYEFJ3+ocRyCTJw067dLSwr/nalx6YMMA0GCSqGSIb3DQEBBQUAA4GBAMaQzt+za
      j1GU77yzlr8iiMBXgdQrwsZZWJo5exnAucJAEYQZmOfyLiMD6oYq+ZnfvM0n8G/Y79q8nhwvu
      xpYOnRSAXFp6xSkrIOeZtJMY1h00LKp/JX3Ng1svZ2agE126JHsQ0bhzN5TKsYfbwfTwfjdWA
      Gy6Vf1nYi/rO+ryMO
    """
}

api.Command.user_add_cert(*args, **kw)
```

## Removing a certificate from a user
Remove a certificate from a user. This certificate must be Base-64 encoded.

```python
args = ["bob"]
kw = {
    "usercertificate": """
      MIICYzCCAcygAwIBAgIBADANBgkqhkiG9w0BAQUFADAuMQswCQYDVQQGEwJVUzEMMAoGA1UEC
      hMDSUJNMREwDwYDVQQLEwhMb2NhbCBDQTAeFw05OTEyMjIwNTAwMDBaFw0wMDEyMjMwNDU5NT
      laMC4xCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNJQk0xETAPBgNVBAsTCExvY2FsIENBMIGfMA0
      GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD2bZEo7xGaX2/0GHkrNFZvlxBou9v1Jmt/PDiTMPve
      8r9FeJAQ0QdvFST/0JPQYD20rH0bimdDLgNdNynmyRoS2S/IInfpmf69iyc2G0TPyRvmHIiOZ
      bdCd+YBHQi1adkj17NDcWj6S14tVurFX73zx0sNoMS79q3tuXKrDsxeuwIDAQABo4GQMIGNME
      sGCVUdDwGG+EIBDQQ+EzxHZW5lcmF0ZWQgYnkgdGhlIFNlY3VyZVdheSBTZWN1cml0eSBTZXJ
      2ZXIgZm9yIE9TLzM5MCAoUkFDRikwDgYDVR0PAQH/BAQDAgAGMA8GA1UdEwEB/wQFMAMBAf8w
      HQYDVR0OBBYEFJ3+ocRyCTJw067dLSwr/nalx6YMMA0GCSqGSIb3DQEBBQUAA4GBAMaQzt+za
      j1GU77yzlr8iiMBXgdQrwsZZWJo5exnAucJAEYQZmOfyLiMD6oYq+ZnfvM0n8G/Y79q8nhwvu
      xpYOnRSAXFp6xSkrIOeZtJMY1h00LKp/JX3Ng1svZ2agE126JHsQ0bhzN5TKsYfbwfTwfjdWA
      Gy6Vf1nYi/rO+ryMO
    """
}

api.Command.user_remove_cert(*args, **kw)
```


## Disabling a user

Disable a user account.

```python
api.Command.user_disable("bob")
```

## Enabling a user
Enable a previously disabled user.

```python
api.Command.user_enable("bob")
```
