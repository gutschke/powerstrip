USER=$(shell whoami)
DOMAIN=$(shell sed 's/\(domain\|search\).*\s\(\S\+\).*/\2/;t;d' /etc/resolv.conf)
SMTP=$(shell host $(DOMAIN) mx | sed 's/.*is handled by //;t;d' | sort -n | awk 'NR == 1 { print $$2 }')

SERIAL=/dev/serial/by-id/pci-FTDI_FT232R_USB_UART_A40149OW-if00-port0

CPPFLAGS=-Wall -Wextra -Werror -Wno-unused-parameter -D_GNU_SOURCE -DNOIPV6TESTS
CFLAGS=-g -O3 -std=gnu99
LDFLAGS=-lusb
CFGFLAGS=
ifdef USER
CFGFLAGS+= -DemailUser='"$(USER)@$(DOMAIN)"'
ifdef SMTP
CFGFLAGS+= -DmailServer='"$(SMTP)"'
endif
endif
ifdef SERIAL
CFGFLAGS+= -DserialPort='"$(SERIAL)"'
endif

all: powerstrip

clean:
	$(RM) -f powerstrip

powerstrip: powerstrip.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFGFLAGS) $(LDFLAGS) $(XTRA) -o $@ $<
