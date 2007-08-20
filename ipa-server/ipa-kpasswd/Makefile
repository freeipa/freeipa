PREFIX ?= $(DESTDIR)/usr
SBIN = $(PREFIX)/sbin
INITDIR = $(DESTDIR)/etc/rc.d/init.d

LDFLAGS +=-lkrb5 -llber -lldap
CFLAGS ?= -g -Wall -Wshadow

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o ipa_kpasswd

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	-mkdir -p $(SBIN)
	install -m 755 ipa_kpasswd $(SBIN)
	-mkdir -p $(INITDIR)
	install -m 755 ipa-kpasswd.init $(INITDIR)/ipa-kpasswd

clean:
	rm -f *.o
	rm -f ipa_kpasswd
	rm -f *~
