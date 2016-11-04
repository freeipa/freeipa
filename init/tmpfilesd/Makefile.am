dist_noinst_DATA = 	\
	ipa.conf.in

systemdtmpfiles_DATA = 	\
	ipa.conf

CLEANFILES = $(systemdtmpfiles_DATA)

%: %.in Makefile
	sed -e 's|@localstatedir[@]|$(localstatedir)|g' '$(srcdir)/$@.in' >$@

# create empty directories as needed
# DESTDIR might not be set, in that case default to system root
DESTDIR ?= /
install-data-hook:
	for conf in $(systemdtmpfiles_DATA); do				\
		systemd-tmpfiles --remove --create --boot		\
			--root $(DESTDIR)				\
			$(DESTDIR)$(systemdtmpfilesdir)/$${conf} || :;	\
	done
