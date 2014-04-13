powerstrip
==========

The powerstrip daemon continuely monitors network connectivity. If the
internet goes down, it tries to power-cycle the networking equipment.

The code currently supports two different types of devices to control
power to external networking equipment. It can talk to a "dumb" USB
powerstrip by turning the power of the USB port off and back on.

Unfortunately, these days, very few USB ports support power cycling. So,
it might be necessary to find a USB hub that supports this command.

Alternatively, it can control a relay card that shows up as a USB serial
port. The relay card expects commands to be sent with 1200 8N1. 'a' turns
the power off, and 'c' turns it back on. '(' enables periodic reporting
of the current status of the relay, and ')' disables reporting.

The source code can easily be modified to support other types of serial
protocols.

The Makefile tries to guess the correct user name and domain name for
sending notifications by e-mail. In all but the most trivial cases, it
probably guesses wrong. So, better provide these arguments on the
command line:

  make USER=username DOMAIN=domain SERIAL=serialport

If you leave USER empty, notifications go to the system log only. If
you leave DOMAIN empty, notifications are sent through the mail server
running on localhost. If SERIAL is empty, USB power control is used
instead of a serial protocol.
