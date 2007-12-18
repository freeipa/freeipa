SBINDIR = $(DESTDIR)/usr/sbin


all: ;

install:
	install -m 755 ipa-addradiusclient $(SBINDIR)
	install -m 755 ipa-radiusclientmod $(SBINDIR)
	install -m 755 ipa-delradiusclient $(SBINDIR)
	install -m 755 ipa-findradiusclient $(SBINDIR)
	install -m 755 ipa-addradiusprofile $(SBINDIR)
	install -m 755 ipa-radiusprofilemod $(SBINDIR)
	install -m 755 ipa-delradiusprofile $(SBINDIR)
	install -m 755 ipa-findradiusprofile $(SBINDIR)

clean:
	rm -f *~ *.pyc

distclean: clean

test:
