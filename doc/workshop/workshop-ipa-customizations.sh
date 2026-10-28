#!/bin/bash
sudo systemctl enable haveged
sudo sh -c "echo 'PS1=\"[\u@\h]\\\\$ \"' >> /etc/profile"
sudo sh -c "echo 'PS1=\"[\h]\\\\$ \"' >> /etc/bashrc"
sudo sh -c "echo '192.168.33.10 server.ipademo.local' >> /etc/hosts"
sudo sh -c "echo '192.168.33.11 replica.ipademo.local' >> /etc/hosts"
sudo sh -c "echo '192.168.33.20 client.ipademo.local' >> /etc/hosts"
sudo rm -f /etc/httpd/conf.d/welcome.conf

sudo sh -c "cat >/usr/share/httpd/app.py" <<EOF
def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    remote_user = environ.get('REMOTE_USER')

    if remote_user is not None:
        yield "LOGGED IN AS: {}\n".format(remote_user).encode('utf8')
    else:
        yield b"NOT LOGGED IN\n"

    yield b"\nREMOTE_* REQUEST VARIABLES:\n\n"

    for k, v in environ.items():
        if k.startswith('REMOTE_'):
            yield "  {}: {}\n".format(k, v).encode('utf8')
EOF

sudo sh -c "cat >/etc/httpd/conf.d/app.conf" <<EOF
<VirtualHost *:80>
    ServerName client.ipademo.local
    WSGIScriptAlias / /usr/share/httpd/app.py

    <Directory /usr/share/httpd>
        <Files "app.py">
            Require all granted
        </Files>
    </Directory>
</VirtualHost>
EOF

# Vagrant's "change host name" sets the short host name.  Before
# we repair /etc/hosts (see below) let's reset /etc/hostname to
# the *full* host name
hostname --fqdn > /etc/hostname && hostname -F /etc/hostname

# Vagrant's "change host name" capability for Fedora maps hostname
# to loopback.  We must repair /etc/hosts
sed -ri 's/127\.0\.0\.1\s.*/127.0.0.1 localhost localhost.localdomain/' /etc/hosts
