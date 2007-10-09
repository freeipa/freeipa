include ../../Makefile.common

SONAME = libipa-dna-plugin.so
LDFLAGS += -llber
CFLAGS += -I/usr/include/$(DIRSRV) -I/usr/include/nss3 -I/usr/include/mozldap -I/usr/include/nspr4 -fPIC -DPIC

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -Wl,-soname -Wl,$(SONAME) -shared -o $(SONAME)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	mkdir -p $(PLUGINDIR); \
	install -m 644 $(SONAME) $(PLUGINDIR); \
	install -m 644 *.ldif $(SHAREDIR)

clean:
	rm -f *.o
	rm -f $(SONAME)
	rm -f *~


