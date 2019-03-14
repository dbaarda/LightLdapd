TARGET=entente
CC=gcc
AR=ar
CFLAGS=-Wall -Wextra -fno-strict-aliasing
LDFLAGS=-lev -lpam
TYPE_RE='\(ev\|ldap\)_[^ ]\+\|[^ ]\+_t'

.PHONY: all debug clean install debian debclean tidy

all: asn1/LDAP.a
	$(CC) -Iasn1/ $(CFLAGS) $(LDFLAGS) main.c pam.c nss2ldap.c $^ -o $(TARGET)

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
	dpkg-buildpackage -rfakeroot

debclean:
	debian/rules clean

tidy:
	# Tidy code using indent.
	indent -linux -l120 *.c
	# Remove struct prefix from userdefined types.
	sed -i 's/struct \('$(TYPE_RE)' \)/\1/g' *.c
	# Remove space between * and identifier for userdefined types.
	sed -i 's/\([( \t]\('$(TYPE_RE)'\) \*\+\) /\1/g' *.c
