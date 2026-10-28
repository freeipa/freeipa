NULL =

PLUGIN_COMMON_DIR = $(srcdir)/../common
AM_CPPFLAGS =							\
	-I$(PLUGIN_COMMON_DIR)					\
	$(DIRSRV_CFLAGS)					\
	$(CRYPTO_CFLAGS)					\
	$(NSPR_CFLAGS)						\
	$(NULL)

noinst_LTLIBRARIES = libhotp.la libotp.la
libhotp_la_SOURCES = hotp.c hotp.h
libotp_la_SOURCES = otp_config.c otp_config.h otp_token.c otp_token.h
libotp_la_LIBADD = libhotp.la $(CRYPTO_LIBS)

check_PROGRAMS = t_hotp
TESTS = $(check_PROGRAMS)
t_hotp_LDADD = libhotp.la $(CRYPTO_LIBS)
