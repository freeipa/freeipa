all:
	gcc ipa_pwd_extop.c -I/usr/include -I/usr/include/nss3 -I/usr/include/mozldap -I/usr/include/nspr4 -I/usr/include/fedora-ds -lkrb5 -lmhash -llber -lssl -shared -g -fPIC -DPIC -Wl,-soname -Wl,libipa_pwd_extop.so -o libipa_pwd_extop.so

install:
	cp -f libipa_pwd_extop.so /usr/lib/fedora-ds/plugins/
