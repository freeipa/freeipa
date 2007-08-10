all:
	gcc ipa-memberof.c -I/usr/include/nss3 -I/usr/include/mozldap -I/usr/include/nspr4 -I/usr/include/fedora-ds -I/usr/include -llber -shared -fPIC -DPIC -g -Wl,-soname -Wl,libipa-memberof-plugin.so -o libipa-memberof-plugin.so

install:
	cp -f libipa-memberof-plugin.so /usr/lib/fedora-ds/plugins/
