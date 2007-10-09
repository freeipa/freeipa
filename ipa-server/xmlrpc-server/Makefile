include ../Makefile.common

all: ;

install:
	-mkdir -p $(SHAREDIR)
	-mkdir -p $(SHAREDIR)/html
	install -m 644 *.py $(SHAREDIR)/ipaserver
	install -m 644 ipa.conf $(SHAREDIR)
	install -m 644 *.html $(SHAREDIR)/html

clean:
	rm -f *~ *.pyc
