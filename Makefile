TARGET=lightldapd
CC=gcc
AR=ar
CFLAGS=-Wall -Wextra -fno-strict-aliasing
LDFLAGS=-lev -lpam

.PHONY: all debug clean install debian debclean tidy

all: asn1/LDAP.a
	$(CC) -Iasn1/ $(CFLAGS) $(LDFLAGS) main.c ldap_server.c pam.c nss2ldap.c $^ -o $(TARGET)

asn1/LDAP.a: asn1
	cd asn1 && $(CC) -I. $(CFLAGS) -c *.c
	$(AR) rcs $@ asn1/*.o

asn1:
	mkdir asn1 && ( cd asn1; asn1c -pdu=auto -fcompound-names ../ldap.asn1; rm converter-sample.c )

debug: CFLAGS += -DDEBUG
debug: all

clean:
	rm -rf $(TARGET) asn1/ *~

install:
	if [ -z "$(DESTDIR)" ]; then exit 1; fi
	mkdir -p $(DESTDIR)/usr/sbin
	cp $(TARGET) $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/etc/init.d
	cp $(TARGET).init.d $(DESTDIR)/etc/init.d/$(TARGET)
	mkdir -p $(DESTDIR)/etc/default
	cp $(TARGET).default $(DESTDIR)/etc/default/$(TARGET)

debian:
	dpkg-buildpackage -rfakeroot -I.*

debclean:
	debian/rules clean

tidy:
	# Reformat all code and comments to preferred coding style."
	tidyc -ppi0 -R -C -T '/ev_\w+/' -T '/ldap_\w+/' -T 'ENTRY' *.[ch]

check: CFLAGS += -DDEBUG
check:
	$(CC) $(CFLAGS) $(LDFLAGS) dlist_test.c -o dlist_test
	./dlist_test
