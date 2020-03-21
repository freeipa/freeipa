#!/bin/bash
sudo dnf install -y freeipa-server freeipa-server-dns sssd-dbus mod_lookup_identity mod_authnz_pam haveged nmap-ncat nano pamtester bash-completion
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
    logged_in = 'REMOTE_USER' in environ

    if logged_in:
        yield "LOGGED IN AS: {}\n".format(environ['REMOTE_USER']).encode('utf8')
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
