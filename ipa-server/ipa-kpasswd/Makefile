PREFIX ?= $(DESTDIR)/usr
SBIN = $(PREFIX)/sbin

LDFLAGS +=-lkrb5 -llber -lldap
CFLAGS ?= -Wall -Wshadow -O2

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o ipa_kpasswd

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	-mkdir -p $(SBIN)
	install -m 755 ipa_kpasswd $(SBIN)

clean:
	rm -f *.o
	rm -f ipa_kpasswd
	rm -f *~