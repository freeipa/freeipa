include ../Makefile.common

LDFLAGS +=-lkrb5 -llber -lldap

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o ipa_kpasswd

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	echo $(SBINDIR)
	-mkdir -p $(SBINDIR)
	install -m 755 ipa_kpasswd $(SBINDIR)
	-mkdir -p $(INITDIR)
	install -m 755 ipa-kpasswd.init $(INITDIR)/ipa-kpasswd

clean:
	rm -f *.o
	rm -f ipa_kpasswd
	rm -f *~
