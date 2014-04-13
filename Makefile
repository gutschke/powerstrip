USER=$(shell whoami)
DOMAIN=$(shell sed 's/\(domain\|search\)[ \t]*\([^ \t]*\).*/\2/;t;d' /etc/resolv.conf)
SERIAL=/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_A40149OW-if00-port0

CPPFLAGS=-Wall -Wextra -Werror -Wno-unused-parameter -D_GNU_SOURCE
CFLAGS=-g -O3 -std=gnu99
LDFLAGS=-lusb
CFGFLAGS=
ifdef USER
CFGFLAGS+= -DemailUser='"$(USER)"'
ifdef DOMAIN
CFGFLAGS+= -DmailServer='"$(DOMAIN)"'
endif
endif
ifdef SERIAL
CFGFLAGS+= -DserialPort='"$(SERIAL)"'
endif

all: powerstrip

clean:
	$(RM) -f powerstrip

powerstrip: powerstrip.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFGFLAGS) $(LDFLAGS) -o $@ $<
