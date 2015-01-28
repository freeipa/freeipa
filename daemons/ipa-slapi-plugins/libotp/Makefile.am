MAINTAINERCLEANFILES = *~ Makefile.in
PLUGIN_COMMON_DIR = ../common
AM_CPPFLAGS = -I/usr/include/dirsrv		\
	-I$(PLUGIN_COMMON_DIR)

noinst_LTLIBRARIES = libhotp.la libotp.la
libhotp_la_SOURCES = hotp.c hotp.h
libotp_la_SOURCES = otp_config.c otp_config.h otp_token.c otp_token.h
libotp_la_LIBADD = libhotp.la

check_PROGRAMS = t_hotp
TESTS = $(check_PROGRAMS)
t_hotp_LDADD = $(NSPR_LIBS) $(NSS_LIBS) libhotp.la
