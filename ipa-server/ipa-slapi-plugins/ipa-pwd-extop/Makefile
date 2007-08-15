DIRSRV ?= dirsrv
PREFIX ?= $(DESTDIR)/usr
LIBDIR = $(PREFIX)/lib/$(DIRSRV)/plugins
LIB64DIR ?= $(PREFIX)/lib64/$(DIRSRV)/plugins
SHAREDIR = $(DESTDIR)/usr/share/ipa

SONAME = libipa_pwd_extop.so
LDFLAGS += -lkrb5 -llber -lldap -lmhash -llber -lssl
CFLAGS ?= -Wall -Wshadow -O2
CFLAGS += -I/usr/include/$(DIRSRV) -I/usr/include/nss3 -I/usr/include/mozldap -I/usr/include/nspr4 -fPIC -DPIC

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -Wl,-soname -Wl,$(SONAME) -shared -o $(SONAME)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	-mkdir -p $(LIBDIR)
	if [ -e $(PREFIX)/lib/$(DIRSRV) ]; then \
		install -m 644 $(SONAME) $(LIBDIR); \
	else \
		install -m 644 $(SONAME) $(LIB64DIR); \
	fi	
	install -m 644 *.ldif $(SHAREDIR)

clean:
	rm -f *.o
	rm -f $(SONAME)
	rm -f *~


