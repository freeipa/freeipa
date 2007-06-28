SHAREDIR = $(DESTDIR)/usr/share/ipa

install:
	-mkdir -p $(SHAREDIR)
	install -m 644 *.ldif $(SHAREDIR)
	install -m 644 *.template $(SHAREDIR)

clean:
	rm -f *~
