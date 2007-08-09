SHAREDIR = $(DESTDIR)/usr/share/ipa/ipaserver

all: ;

install:
	-mkdir -p $(SHAREDIR)
	install -m 644 *.py $(SHAREDIR)
	install -m 644 ipa.conf $(SHAREDIR)/..

clean:
	rm -f *~ *.pyc
