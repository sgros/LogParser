LogParser
=========

Parser writen in Python for Zimbra 8 postfix mail logs (/var/log/maillog on RHEL family).
In the future it will be exanded to other mail formats.

This script is in a very early stages of development. Currently, it is able to read
and parse log files, but nothing more than that.

To run it, just do the following:

./LogParser.py <name of maillog file>

Note that the script is currently able to read xz compressed log file, as well as plain
text version.
