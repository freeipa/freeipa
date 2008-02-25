MANDIR = $(DESTDIR)/usr/share/man

MANFILES=\
	ipa-adddelegation.1 \
	ipa-addgroup.1 \
	ipa-addservice.1 \
	ipa-adduser.1 \
	ipa-deldelegation.1 \
	ipa-delgroup.1 \
	ipa-delservice.1 \
	ipa-deluser.1 \
	ipa-findgroup.1 \
	ipa-findservice.1 \
	ipa-finduser.1 \
	ipa-modgroup.1 \
	ipa-listdelegation.1 \
	ipa-lockuser.1 \
	ipa-moddelegation.1 \
	ipa-passwd.1 \
	ipa-pwpolicy.1 \
	ipa-moduser.1 \
	ipa-getkeytab.1

all: ;

install:
	mkdir -p $(MANDIR)/man1
	@for i in $(MANFILES) ; do install -m 644 $$i $(MANDIR)/man1 ; gzip -f $(MANDIR)/man1/$$i ; done

clean:

test:
