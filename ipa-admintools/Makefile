SBINDIR = $(DESTDIR)/usr/sbin

all: ;

install:
	install -m 755 ipa-adduser $(SBINDIR)
	install -m 755 ipa-finduser $(SBINDIR)
	install -m 755 ipa-usermod $(SBINDIR)
	install -m 755 ipa-deluser $(SBINDIR)

clean:
	rm -f *~ *.pyc
