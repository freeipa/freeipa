Unit 6: Service certificates
================================

You probably noticed that the web service was not hosted over HTTPS,
so there is no TLS-based authentication or confidentiality.  In this
unit, we will issue an X.509 certificate for the web service via
the *Certmonger* program.

Certmonger supports multiple CAs including FreeIPA's CA, and can
generate keys, issue certificate requests, track certificates, and
renew tracked certificates when the expiration time approaches.
Will also use ``mod_ssl`` with Apache.

Issue the service certificate
-----------------------------

Let's start by confirming that the HTTP service does not yet have a
certificate::

  [client]$ ipa service-show HTTP/client.ipademo.local
    Principal name: HTTP/client.ipademo.local@IPADEMO.LOCAL
    Principal alias: HTTP/client.ipademo.local@IPADEMO.LOCAL
    Keytab: True
    Managed by: client.ipademo.local

Enable and start Certmonger::

  [client]$ sudo systemctl enable --now certmonger
  Created symlink /etc/systemd/system/multi-user.target.wants/certmonger.service → /usr/lib/systemd/system/certmonger.service.

Now let's request a certificate.  We will generate keys and store
certificates in the NSS database at ``/etc/httpd/alias``::

  [client]$ sudo ipa-getcert request \
              -f /etc/pki/tls/certs/app.crt \
              -k /etc/pki/tls/private/app.key \
              -K HTTP/client.ipademo.local \
              -D client.ipademo.local
  New signing request "20180603185400" added.

Let's break down some of those command arguments.

``-k <path>``
  Path to private key (Certmonger will generate it)
``-f <path>``
  Path to certificate (where it will be saved after being issued)
``-K <principal>``
  Kerberos service principal; because different kinds of services
  may be accessed at one hostname, this argument tells Certmonger
  which service principal is the subject
``-D <dnsname>``
  Requests the given domain name to appear in the *Subject
  Alternative Name (SAN)* extension; today the *Common Name (CN)*
  field is no longer used by browsers so the SAN value is essential

Another important option is ``-N <subject-name>``.  It defaults to
the system hostname, which in our case (``client.ipademo.local``) is
appropriate.

Let's check the status of our certificate request using the tracking
identifier given in the ``ipa-getcert request`` output::

  [client]$ sudo getcert list -i 20180603185400
  Number of certificates and requests being tracked: 1.
  Request ID '20180603185400':
    status: MONITORING
    stuck: no
    key pair storage: type=FILE,location='/etc/pki/tls/private/app.key'
    certificate: type=FILE,location='/etc/pki/tls/certs/app.crt'
    CA: IPA
    issuer: CN=Certificate Authority,O=IPADEMO.LOCAL
    subject: CN=client.ipademo.local,O=IPADEMO.LOCAL
    expires: 2020-06-03 18:54:00 UTC
    dns: client.ipademo.local
    principal name: HTTP/client.ipademo.local@IPADEMO.LOCAL
    key usage: digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
    eku: id-kp-serverAuth,id-kp-clientAuth
    pre-save command:
    post-save command:
    track: yes
    auto-renew: yes


Confirm that the certificate was issued and that Certmonger is now
``MONITORING`` the certificate and will ``auto-renew`` it when it is
close to expiration.  Now if you run ``ipa service-show``, you will
see a number of attributes related to the certificate, including the
certificate itself.  Can you work out how to save the PEM-encoded
certificate to a file?

Set up TLS for Apache
---------------------

Now we can reconfigure Apache to serve our app over TLS.  Update
``app.conf`` to listen on port 443 and add the SSL directives::

  ...
  Listen 443

  <VirtualHost *:443>
      SSLEngine on
      SSLCertificateFile "/etc/pki/tls/certs/app.crt"
      SSLCertificateKeyFile "/etc/pki/tls/private/app.key"

      ServerName client.ipademo.local
      ...


Restart Apache and make a request to the app over HTTPS::

  [client]$ sudo systemctl restart httpd
  [client]$ curl -u : --negotiate https://client.ipademo.local
  LOGGED IN AS: alice@IPADEMO.LOCAL

  REMOTE_* REQUEST VARIABLES:

    REMOTE_USER: alice@IPADEMO.LOCAL
    REMOTE_USER_GROUP_1: ipausers
    REMOTE_USER_GROUP_2: sysadmin
    REMOTE_USER_GROUP_N: 2
    REMOTE_USER_FIRSTNAME: Alice
    REMOTE_USER_LASTNAME: Alice
    REMOTE_USER_MAIL: alice@ipademo.local
    REMOTE_ADDR: 192.168.33.20
    REMOTE_PORT: 51876


You can now proceed to
`Unit 7: Replica installation <7-replica-install.rst>`_
or
`Unit 8: Sudo rule management <8-sudorule.rst>`_.
Otherwise,
`return to the curriculum overview <workshop.rst#curriculum-overview>`_
to see all the options.
