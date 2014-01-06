MAINTAINERCLEANFILES = *~ Makefile.in
AM_CPPFLAGS = -I/usr/include/dirsrv

noinst_LTLIBRARIES = librfc.la libotp.la
libotp_la_LIBADD = librfc.la

check_PROGRAMS = t_librfc
TESTS = $(check_PROGRAMS)
t_librfc_LDADD = $(NSPR_LIBS) $(NSS_LIBS) librfc.la
