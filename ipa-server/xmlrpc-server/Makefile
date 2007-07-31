SHAREDIR = $(DESTDIR)/usr/share/ipa/ipaserver
HTTPDIR = $(DESTDIR)/etc/httpd/conf.d/

all: ;

install:
	-mkdir -p $(SHAREDIR)
	install -m 644 *.py $(SHAREDIR)
	install -m 644 ipa.conf $(HTTPDIR)

clean:
	rm -f *~ *.pyc
