MANDIR = $(DESTDIR)/usr/share/man

MANFILES=\
	ipa-addgroup.1 \
	ipa-adduser.1 \
	ipa-delgroup.1 \
	ipa-deluser.1 \
	ipa-findgroup.1 \
	ipa-finduser.1 \
	ipa-groupmod.1 \
	ipa-passwd.1 \
	ipa-usermod.1
	
all: ;

install:
	mkdir -p $(MANDIR)/man1
	@for i in $(MANFILES) ; do install -m 644 $$i $(MANDIR)/man1 ; gzip $(MANDIR)/man1/$$i ; done

clean:

test:
