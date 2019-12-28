TARGET=lightldapd
CC=gcc
AR=ar
CFLAGS=-Wall
LDFLAGS=-lev -lpam -lmbedtls -lmbedx509 -lmbedcrypto
SRCS=main.c ldap_server.c nss2ldap.c pam.c ssl.c
TESTS=dlist_test
CHECKS=$(TESTS:_test=_check)

.PHONY: all debug clean install debian debclean tidy check

all: $(TARGET)

$(TARGET): $(SRCS) asn1/LDAP.a
	$(CC) $(CFLAGS) -Iasn1/ -o $(TARGET) $^ $(LDFLAGS)

asn1/LDAP.a: | asn1
	cd asn1 && $(CC) -I. -D_DEFAULT_SOURCE $(CFLAGS) -c *.c
	$(AR) rcs $@ asn1/*.o

asn1:
	mkdir asn1 && ( cd asn1; asn1c -pdu=auto -fcompound-names ../ldap.asn1; rm converter-sample.c )

debug: CFLAGS += -DDEBUG
debug: all

clean:
	rm -rf $(TARGET) $(TESTS) asn1/ *~

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
	tidyc -ppi0 -R -C -T '/(ev|mbedtls|ldap)_\w+/' -T 'ENTRY' *.[ch]

# Note we depend on TESTS to compile them all first.
check: $(TESTS) $(CHECKS)

# Generic rule for compiling tests.
%_test: CFLAGS += -DDEBUG
%_test: %_test.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generic rule for running tests.
%_check: %_test
	@./$< && echo "$<: Passed" >&2;

# Additional dependencies needed for particular tests.
