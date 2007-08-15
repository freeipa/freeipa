PREFIX ?= $(DESTDIR)/usr
LIBDIR = $(PREFIX)/lib/fedora-ds/plugins
SHAREDIR = $(DESTDIR)/usr/share/ipa

SONAME = libipa-memberof-plugin.so
LDFLAGS += -llber
CFLAGS ?= -Wall -Wshadow -O2
CFLAGS += -I/usr/include/fedora-ds -I/usr/include/nss3 -I/usr/include/mozldap -I/usr/include/nspr4 -fPIC -DPIC

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -Wl,-soname -Wl,$(SONAME) -shared -o $(SONAME)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	-mkdir -p $(LIBDIR)
	install -m 644 $(SONAME) $(LIBDIR)
	install -m 644 *.ldif $(SHAREDIR)

clean:
	rm -f *.o
	rm -f $(SONAME)
	rm -f *~


