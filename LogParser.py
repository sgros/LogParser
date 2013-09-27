#!/usr/bin/python

import sys
import re
from datetime import datetime, date
import lzma

################################################################################
# Common regular expressions
################################################################################

# Date and a time in a format "Jul  7 03:03:45" or Jun 30 04:02:57"
date_re = "([a-zA-Z]{3}[ ]{1,2}[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})"

# Host name, without domain
hostname_re = "([a-zA-Z0-9_-]+)"

# PID in square brackets
pid_re = "\[([0-9]+)\]"

# IPv4 address
ipv4_re = "([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})"

# Port number
port_re = "([0-9]{1,5})"

# FQDN
fqdn_re = "([a-zA-Z0-9._-]+)"

# FQDN or IP and IP in square brackets
fqdn_or_unknown_and_ipv4_re = "((" + fqdn_re + "|unknown)\[(" + ipv4_re + "|unknown)\])"

# FQDN or IP and IP in square brackets plus port
fqdn_or_unknown_and_ipv4_and_port_re = "(" + fqdn_or_unknown_and_ipv4_re + ":" + port_re + ")"

# Mail address within <>
mail_re = "<([^>]*)>"

# to=<some.mail@address.com>
to_mail_re = "to=" + mail_re

# orig_to=<some.mail@address.com>
orig_to_mail_re = "orig_to=" + mail_re

# from=<some.mail@address.com>
from_mail_re = "from=" + mail_re

# FQDN or IP and IP in square brackets plus port
fqdn_or_unknown_and_ipv4_and_port_re = "(" + fqdn_or_unknown_and_ipv4_re + ":" + port_re + ")"

# relay and its arameter, which can be one of:
# none
# local
# IP[IP]:port
# fqdn[IP]:port
relay_re = "relay=((none)|(local)|" + fqdn_or_unknown_and_ipv4_and_port_re + ")"

# Identifier within helo command
helo_re = "<([^>]*)>"

# Message identifier. In postfix it is a string of uppercase letters and numbers of 11 characters
queueid_re = "([A-Z0-9]{7,12})"

# NOQUEUE or QUEUE id
noqueue_or_queueid_re = "((NOQUEUE)|" + queueid_re + ")"

# 
conn_use_re = "conn_use=([0-9.]+)"

# A single delay value
delay_re = "delay=([0-9.]+)"

# A multiple delay values
delays_re = "delays=([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)"

# DSN status
dsn_re = "dsn=([0-9]\.[0-9]\.[0-9])"

# Status line, when there is no 'queued as' message
status_re = "status=([a-z]+) \((.+)\)"

# UID regular expression
uid_re="uid=([0-9]+)"

# SPAM identifier when dropped by amavis
spam_id_re="id=([0-9-]+)"

################################################################################
# Regular expressions
################################################################################

zimbra8 = [

	# Aug 25 18:28:01 mail postfix/smtpd[25292]: D3B73321AC7: client=93-136-95-83.adsl.net.t-com.hr[93.136.95.83], sasl_method=PLAIN, sasl_username=username
	# Aug 26 10:47:18 mail postfix/smtpd[19002]: B48D5321AC7: client=93-136-195-117.adsl.net.t-com.hr[93.136.195.117], sasl_method=LOGIN, sasl_username=username
	{"name": "smtpd_sasl_login",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": " + queueid_re + ": client=" + fqdn_or_unknown_and_ipv4_re + ", sasl_method=(PLAIN|LOGIN), sasl_username=([a-z0-9A-Z.]+)",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", "", "sasl_method", "username"),
		"smid": "queueid",
		"print": False},

	# Aug 27 12:20:01 mail postfix/smtpd[28312]: warning: SASL authentication failure: Password verification failed
        {"name": "smtpd_sasl_login_failure",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": " + "warning: " + fqdn_or_unknown_and_ipv4_re + ": SASL (LOGIN|PLAIN) authentication failed: authentication failure",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", "", "method"),
		"smid": "PID",
                "print": False},

	# Aug 27 12:20:01 mail postfix/smtpd[28312]: warning: SASL authentication failure: Password verification failed
        {"name": "smtpd_sasl_password_failure",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": " + "warning: SASL authentication failure: Password verification failed$",
		"fields": ("all", "timestamp", "hostname", "PID"),
		"smid": "PID",
                "print": False},

	# Aug 25 03:45:46 mail postfix/smtpd[24044]: Anonymous TLS connection established from mail-ob0-f182.google.com[209.85.214.182]: TLSv1 with cipher ECDHE-RSA-RC4-SHA (128/128 bits)
	{"name": "smtpd_tls_established",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": Anonymous TLS connection established from " + fqdn_or_unknown_and_ipv4_re + ": (.*)$",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", "", "tlscipher"),
		"smid": "PID",
                "print": False},

	# Aug 25 14:40:01 mail postfix/smtpd[23025]: SSL_accept error from unknown[10.10.0.101]: -1
	{"name": "smtpd_ssl_accept_error",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": SSL_accept error from " + fqdn_or_unknown_and_ipv4_re + ": (.*)",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", "", "sslerror"),
		"smid": ("PID"),
		"print": False},

	 # Aug 25 14:40:01 mail postfix/smtpd[23025]: warning: TLS library problem: 23025:error:1408F119:SSL routines:SSL3_GET_RECORD:decryption failed or bad record mac:s3_pkt.c:484:
	{"name": "smtpd_tls_library_error",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": warning: TLS library problem: (.+)",
		"fields": ("all", "timestamp", "hostname", "PID", "tlserror"),
		"smid": "PID",
		"print": False},

	# Sep  9 00:40:15 mail postfix/smtpd[4349]: warning: non-SMTP command from unknown[89.248.172.122]: Content-Type: text/html
	{ "name": "smtpd_command_error",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": warning: non-SMTP command from " + fqdn_or_unknown_and_ipv4_re + ": (.*)$",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", "", "error"),
		"smid": "PID",
		"print": False},

	# Aug 25 03:37:58 mail postfix/smtpd[24044]: connect from guppy.example-domain.com[197.100.0.140]
	{ "name": "smtpd_client_connect",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": connect from " + fqdn_or_unknown_and_ipv4_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", ""),
		"smid": "POSTFIX",
		"print": False},

	# Aug 25 03:37:58 mail postfix/smtpd[24044]: NOQUEUE: filter: RCPT from guppy.example-domain.com[197.100.0.140]: <machine@example.com>: Sender address triggers FILTER smtp-amavis:[127.0.0.1]:10026; from=<machine@example.com> to=<MAILER-DAEMON@mail.example.com> proto=SMTP helo=<example.com>
	# Sep 20 11:24:23 mail postfix/smtpd[30733]: NOQUEUE: filter: VRFY from openemailsurvey.org[178.217.134.26]: <>: Sender address triggers FILTER smtp-amavis:[127.0.0.1]:10026; from=<> to=<test@example.com> proto=ESMTP helo=<openemailsurvey.org>
	{ "name": "smtpd_amavis_10026",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": NOQUEUE: filter: (RCPT|VRFY) from " + fqdn_or_unknown_and_ipv4_re + ": " + mail_re + ": Sender address triggers FILTER smtp-amavis:\[127.0.0.1\]:10026; from=" + mail_re + " to=" + mail_re + " proto=E?SMTP helo=" + helo_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "smtpcommand", "", "clienthostname", "", "clienthostip", "", "", "from", "to", "heloid"),
		"smid": "POSTFIX",
		"print": False},

	# Aug 25 04:03:14 mail postfix/smtpd[24890]: 1B41C321AC7: filter: RCPT from unknown[197.100.1.49]: <arpwatch@monitor1.example-domain.com>: Sender address triggers FILTER smtp-amavis:[127.0.0.1]:10026; from=<arpwatch@monitor1.example-domain.com> to=<nsurname@example.com> proto=ESMTP helo=<monitor1.example-domain.com>
	{ "name": "smtpd_amavis_10026_queueid",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": " + queueid_re + ": filter: RCPT from " + fqdn_or_unknown_and_ipv4_re + ": " + mail_re + ": Sender address triggers FILTER smtp-amavis:\[127.0.0.1\]:10026; from=" + mail_re + " to=" + mail_re + " proto=E?SMTP helo=" + helo_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", "", "from", "", "to", "heloid"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:38:50 mail postfix/smtpd[24044]: NOQUEUE: filter: RCPT from netacc-gpn-4-217-128.pool.telenor.hu[84.224.217.128]: <>: Sender address triggers FILTER smtp-amavis:[127.0.0.1]:10024; from=<> to=<name.surname@example.com> proto=SMTP helo=<84.224.217.128>
	# Sep 20 11:24:23 mail postfix/smtpd[30733]: NOQUEUE: filter: VRFY from openemailsurvey.org[178.217.134.26]: <>: Sender address triggers FILTER smtp-amavis:[127.0.0.1]:10024; from=<> to=<test@example.com> proto=ESMTP helo=<openemailsurvey.org>
	{ "name": "smtpd_amavis_10024",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": NOQUEUE: filter: (RCPT|VRFY) from " + fqdn_or_unknown_and_ipv4_re + ": " + mail_re + ": Sender address triggers FILTER smtp-amavis:\[127.0.0.1\]:10024; from=" + mail_re + " to=" + mail_re + " proto=E?SMTP helo=" + helo_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "smtpcommand", "", "clienthostname", "", "clienthostip", "", "", "from", "to", "heloid"),
		"smid": "newmessage",
		"print": False},

	# Aug 26 07:52:56 mail postfix/smtpd[28574]: 1E378321AC7: filter: RCPT from mxout3.iskon.hr[213.191.128.82]: <s-1@inet.hr>: Sender address triggers FILTER smtp-amavis:[127.0.0.1]:10024; from=<s-1@inet.hr> to=<name.surname@example.com> proto=ESMTP helo=<mxout3.iskon.hr>
	{ "name": "smtpd_amavis_10024_queueid",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": " + queueid_re + ": filter: RCPT from " + fqdn_or_unknown_and_ipv4_re + ": " + mail_re + ": Sender address triggers FILTER smtp-amavis:\[127.0.0.1\]:10024; from=" + mail_re + " to=" + mail_re + " proto=E?SMTP helo=" + helo_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", "", "", "from", "to", "heloid"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:37:58 mail postfix/smtpd[24044]: ACF22321AC7: client=guppy.example-domain.com[197.100.0.140]
	{"name": "smtpd_queueid_identified",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": " + queueid_re + ": client=" + fqdn_or_unknown_and_ipv4_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", ""),
		"smid": "POSTFIX",
		"print": False},

	# Aug 28 16:39:09 mail postfix/smtpd[26747]: warning: Illegal address syntax from unknown[197.100.2.123] in RCPT command: <inga@h.s.p.t.-com>
	# Sep 16 15:38:16 mail postfix/smtpd[22789]: warning: Illegal address syntax from dslb-188-105-211-160.pools.arcor-ip.net[188.105.211.160] in MAIL command: <Keller51f@Torbau_1711+.intern>
	{"name": "smtpd_invalid_syntax",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": warning: Illegal address syntax from " + fqdn_or_unknown_and_ipv4_re + " in (RCPT|MAIL) command: " + mail_re,
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", "", "command", "to"),
		"smid": "PID",
		"print": False},

	# Aug 29 15:16:20 mail postfix/smtpd[5414]: improper command pipelining after QUIT from guppy.example-domain.com[197.100.0.140]:
	# Sep  9 00:40:15 mail postfix/smtpd[4349]: improper command pipelining after DATA from unknown[89.248.172.122]: Content-Type: text/html\r\nFrom: testing@testers.com\r\nTo: csclus.smtp@gmail.com\r\nSubject: virgin - 212
	{"name": "smtpd_improper_pipelining",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": improper command pipelining after (QUIT|DATA) from " + fqdn_or_unknown_and_ipv4_re + ":(.*)$",
		"fields": ("all", "timestamp", "hostname", "PID", "command", "", "clienthostname", "", "clienthostip", "", "error"),
		"smid": "PID",
		"print": False},

	# Aug 25 03:45:02 mail postfix/smtpd[22024]: NOQUEUE: reject: RCPT from 189-47-180-38.dsl.telesp.net.br[189.47.180.38]: 550 5.1.1 <nsurname@example.com>: Recipient address rejected: example.com; from=<nsurname@actgen.in> to=<nsurname@example.com> proto=ESMTP helo=<189-47-180-38.dsl.telesp.net.br>
	{"name": "smtpd_address_rejected",
		"regex":  "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": NOQUEUE: reject: RCPT from " + fqdn_or_unknown_and_ipv4_re + ": 550 5.1.1 " + mail_re + ": Recipient address rejected: " + fqdn_re + "; " + from_mail_re + " " + to_mail_re + " proto=E?SMTP helo=" + helo_re,
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", "", "", "", "from", "to", "heloid"),
		"smid": "PID",
		"print": False},

	# Aug 25 18:03:59 mail postfix/smtpd[24548]: NOQUEUE: reject: RCPT from 1-164-95-121.dynamic.hinet.net[1.164.95.121]: 554 5.7.1 <smtp@k888.tw>: Relay access denied; from=<ffrqfa@hotmail.com> to=<smtp@k888.tw> proto=SMTP helo=<212.92.192.73>
	# Sep 20 11:24:23 mail postfix/smtpd[30733]: NOQUEUE: reject: VRFY from openemailsurvey.org[178.217.134.26]: 554 5.7.1 <test@example.com>: Relay access denied; from=<> to=<test@example.com> proto=ESMTP helo=<openemailsurvey.org>
	{"name": "smtpd_relay_denied",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": NOQUEUE: reject: (VRFY|RCPT) from " + fqdn_or_unknown_and_ipv4_re + ": 554 5.7.1 " + mail_re + ": Relay access denied; " + from_mail_re + " " + to_mail_re + " proto=E?SMTP helo=" + helo_re,
		"fields": ("all", "timestamp", "hostname", "PID", "smtpcommand", "", "clienthostname", "", "clienthostip", "", "", "from", "to", "heloid"),
		"smid": "PID",
		"print": False},

	# This one is strange, how is it possible to not have from field nor HELO id?
	# Sep  1 08:46:14 mail postfix/smtpd[6438]: NOQUEUE: reject: VRFY from unknown[200.170.193.170]: 554 5.7.1 <root>: Relay access denied; to=<root> proto=SMTP
	{"name": "smtpd_relay_denied_strange",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": NOQUEUE: reject: (VRFY|RCPT) from " + fqdn_or_unknown_and_ipv4_re + ": 554 5.7.1 " + mail_re + ": Relay access denied; " + to_mail_re + " proto=E?SMTP$",
		"fields": ("all", "timestamp", "hostname", "PID", "smtpcommand", "", "clienthostname", "", "clienthostip", "", "", "to"),
		"smid": "PID",
		"print": False},

	# Sep  9 09:17:29 mail postfix/smtpd[16004]: NOQUEUE: reject: RCPT from unknown[151.252.231.186]: 504 5.5.2 <u@paccpv>: Recipient address rejected: need fully-qualified address; from=<nsurname@example.com> to=<u@paccpv> proto=ESMTP helo=<[192.168.1.5]>
	{"name": "smtpd_address_rejected",
		"regex":  "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": NOQUEUE: reject: RCPT from " + fqdn_or_unknown_and_ipv4_re + ": 504 5.5.2 " + mail_re + ": Recipient address rejected: need fully-qualified address; " + from_mail_re + " " + to_mail_re + " proto=E?SMTP helo=" + helo_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", "", "", "from", "to", "helo"),
		"smid": "PID",
		"print": False},

	# Aug 26 07:52:56 mail postfix/smtpd[28574]: 1E378321AC7: reject: RCPT from mxout3.iskon.hr[213.191.128.82]: 550 5.1.1 <name.surname@example.com>: Recipient address rejected: example.com; from=<s-1@inet.hr> to=<name.surname@example.com> proto=ESMTP helo=<mxout3.iskon.hr>
	{"name": "smtpd_address_rejected_queueid",
		"regex":  "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": " + queueid_re + ": reject: RCPT from " + fqdn_or_unknown_and_ipv4_re + ": 550 5.1.1 " + mail_re + ": Recipient address rejected: " + fqdn_re + "; " + from_mail_re + " " + to_mail_re + " proto=E?SMTP helo=" + helo_re,
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", "", "", "", "from", "to", "heloid"),
		"smid": "queueid",
		"print": False},

	# Sep  8 15:58:16 mail postfix/smtpd[24133]: 0BD70321AC7: reject: RCPT from unknown[31.217.64.6]: 504 5.5.2 <llel>: Recipient address rejected: need fully-qualified address; from=<nsurname@example.com> to=<llel> proto=ESMTP helo=<[10.209.238.199]>
	{"name": "smtpd_address_rejected_queueid",
		"regex":  "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": " + queueid_re + ": reject: RCPT from " + fqdn_or_unknown_and_ipv4_re + ": 504 5.5.2 " + mail_re + ": Recipient address rejected: need fully-qualified address; " + from_mail_re + " " + to_mail_re + " proto=E?SMTP helo=" + helo_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", "", "", "from", "to", "heloid"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:50:15 mail postfix/smtpd[24044]: warning: hostname 190-177-172-246.speedy.com.ar does not resolve to address 190.177.172.246: Name or service not known
	{"name": "dns_warning",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": warning: hostname " + fqdn_re + " does not resolve to address " + ipv4_re + "(: (.+))?",
		"fields": ("all", "timestamp", "hostname", "PID", "clienthostname", "clienthostip", "", "errormessage"),
		"smid": "PID",
		"print": False},

	# Sep 18 01:32:19 mail postfix/smtpd[1087]: warning: numeric hostname: 190.208.191.182
	{"name": "numeric_hostname_warning",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": warning: numeric hostname: " + ipv4_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "clienthostip"),
		"smid": "PID",
		"print": False},

	# Aug 25 03:37:58 mail postfix/cleanup[6880]: ACF22321AC7: message-id=<AC40A$20130825$03360900@SAS>
	{"name": "messageid_identified",
                "regex": "^" + date_re + " " + hostname_re + " postfix/cleanup" + pid_re + ": " + queueid_re + ": (resent-)?message-id=([^ ]+) ?\n",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "messageid"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:37:58 mail postfix/qmgr[3569]: ACF22321AC7: from=<machine@example.com>, size=744, nrcpt=2 (queue active)
        {"name": "from_identified",
                "regex": "^" + date_re + " " + hostname_re + " postfix/qmgr" + pid_re + ": " + queueid_re + ": from=" + mail_re + ", size=([0-9]+), nrcpt=([0-9]+) \(queue active\)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "from", "size", "nrcpt"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:37:58 mail postfix/smtpd[24044]: disconnect from guppy.example-domain.com[197.100.0.140]
	{"name": "smtpd_client_disconnect",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": disconnect from " + fqdn_or_unknown_and_ipv4_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", ""),
		"smid": "POSTFIX",
		"print": False},

	# Aug 25 03:37:58 mail postfix/dkimmilter/smtpd[28263]: connect from localhost[127.0.0.1]
	{ "name": "dkimmilter_client_connect",
		"regex": "^" + date_re + " " + hostname_re + " postfix/dkimmilter/smtpd" + pid_re + ": connect from " + fqdn_or_unknown_and_ipv4_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", ""),
		"smid": "DKIMMILTER",
		"print": False},

	# Aug 25 03:37:58 mail postfix/dkimmilter/smtpd[28263]: C1FF3321AC9: client=localhost[127.0.0.1]
	{"name": "dkimmilter_queueid_identified",
                "regex": "^" + date_re + " " + hostname_re + " postfix/dkimmilter/smtpd" + pid_re + ": " + queueid_re + ": client=" + fqdn_or_unknown_and_ipv4_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", ""),
		"smid": "DKIMMILTER",
		"print": False},

	# Aug 25 03:37:58 mail postfix/dkimmilter/smtpd[28263]: disconnect from localhost[127.0.0.1]
	{"name": "dkimmilter_client_disconnect",
                "regex": "^" + date_re + " " + hostname_re + " postfix/dkimmilter/smtpd" + pid_re + ": disconnect from " + fqdn_or_unknown_and_ipv4_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", ""),
		"smid": "DKIMMILTER",
		"print": False},

	# Aug 27 13:00:30 mail postfix/smtpd[8384]: warning: milter inet:127.0.0.1:7026: can't read SMFIC_CONNECT reply packet header: Success
	{"name": "smtpd_milter_warning",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": warning: milter inet:" + ipv4_re + ":" + port_re + ": (.+)$",
		"fields": ("all", "timestamp", "hostname", "PID", "hostip", "hostport", "message"),
		"smid": "PID",
		"print": False},

	# Aug 27 23:01:18 mail postfix/cleanup[9931]: warning: milter inet:127.0.0.1:7026: can't read SMFIC_BODYEOB reply packet header: Success
	{"name": "cleanup_milter_warning",
		"regex": "^" + date_re + " " + hostname_re + " postfix/cleanup" + pid_re + ": warning: milter inet:" + ipv4_re + ":" + port_re + ": (.+)$",
		"fields": ("all", "timestamp", "hostname", "PID", "hostip", "hostport", "message"),
		"smid": "PID",
		"print": False},

	# Aug 27 23:01:18 mail postfix/cleanup[9931]: 591F7321ACD: milter-reject: END-OF-MESSAGE from unknown[2.186.157.28]: 4.7.1 Service unavailable - try again later; from=<username@6789.us> to=<username@domain.com> proto=ESMTP helo=<[2.186.157.28]>
	{"name": "cleanup_milter_reject",
		"regex": "^" + date_re + " " + hostname_re + " postfix/cleanup" + pid_re + ": " + queueid_re + ": milter-reject: END-OF-MESSAGE from " + fqdn_or_unknown_and_ipv4_re + ": (.+)",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", "", "errormsg"),
		"smid": "queueid",
		"print": False},

	# Aug 27 13:00:30 mail postfix/smtpd[8384]: NOQUEUE: milter-reject: CONNECT from unknown[unknown]: 451 4.7.1 Service unavailable - try again later; proto=SMTP
	{"name": "smtpd_milter_reject",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": NOQUEUE: milter-reject: CONNECT from " + fqdn_or_unknown_and_ipv4_re + ": (.+)",
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", "", "errormsg"),
		"smid": "PID",
		"print": False},

	# NOTE WELL: The following rule must come BEFORE rule message_bounced since the latter is more general than the former!
	# Aug 25 03:38:53 mail postfix/smtp[8978]: 4A314321AC7: to=<nsurname@example.com>, orig_to=<name.surname@example.com>, relay=127.0.0.1[127.0.0.1]:10024, delay=4, delays=1.9/0/0/2.1, dsn=2.7.0, status=sent (250 2.7.0 Ok, discarded, id=19653-19 - spam)
	{"name": "message_spam_discarded",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": " + queueid_re + ": " + to_mail_re + "(, " + orig_to_mail_re + ")?, " + relay_re + ", " + delay_re + ", " + delays_re + ", " + dsn_re + ", status=sent \(250 2.7.0 Ok, discarded, " + spam_id_re + " - spam\)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to", "", "orig_to", "", "", "", "", "", "relayhostname", "", "relayhostip", "", "relayport", "delay", "delay1", "delay2", "delay3", "delay4", "dsn", "spamid"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:37:58 mail postfix/smtp[5929]: ACF22321AC7: to=<mailarchive@[172.16.1.10]>, relay=127.0.0.1[127.0.0.1]:10026, delay=0.15, delays=0.01/0/0/0.14, dsn=2.0.0, status=sent (250 2.0.0 from MTA(smtp:[127.0.0.1]:10030): 250 2.0.0 Ok: queued as C1FF3321AC9)
	# Aug 26 15:02:35 mail postfix/smtp[1060]: DCA80321ACB: to=<mailarchive@[172.16.1.10]>, relay=127.0.0.1[127.0.0.1]:10026, conn_use=2, delay=0.31, delays=0.04/0/0/0.26, dsn=2.0.0, status=sent (250 2.0.0 from MTA(smtp:[127.0.0.1]:10030): 250 2.0.0 Ok: queued as 24F27321ACC)
	# Aug 25 03:50:18 mail postfix/smtp[13672]: 3A894321AC7: to=<nsurname@example.com>, orig_to=<name.surname@example.com>, relay=127.0.0.1[127.0.0.1]:10024, delay=2, delays=1.4/0/0/0.63, dsn=2.0.0, status=sent (250 2.0.0 from MTA(smtp:[127.0.0.1]:10025): 250 2.0.0 Ok: queued as C4C58321AC9)
	{"name": "message_queued",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": " + queueid_re + ": " + to_mail_re + "(, " + orig_to_mail_re + ")?" + ", " + relay_re + "(, " + conn_use_re + ")?, " + delay_re + ", " + delays_re + ", dsn=2.0.0, status=sent \(.+ queued as " + queueid_re + "\)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to", "", "orig_to", "", "", "", "", "", "relayhostname", "", "relayhostip", "", "relayport", "", "conn_use",  "delay", "delay1", "delay2", "delay3", "delay4", "newqueueid"),
		"smid": "queueid",
		"print": False},

	# Aug 25 18:28:44 mail postfix/smtp[30924]: 24CCC321AC7: to=<n.surname@gmail.com>, relay=gmail-smtp-in.l.google.com[173.194.70.26]:25, delay=1.9, delays=0.09/0/0.35/1.4, dsn=2.0.0, status=sent (250 2.0.0 OK 1377448124 p9si7157489eeu.264 - gsmtp)
	# This RE has to be before message_queued because it is more general!
	{"name": "message_queued_all",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": " + queueid_re + ": " + to_mail_re + "(, " + orig_to_mail_re + ")?" + ", " + relay_re + ", " + delay_re + ", " + delays_re + ", dsn=2.[0-7].0, status=sent \((.+)\)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to", "", "orig_to", "", "", "", "", "", "relayhostname", "", "relayhostip", "", "relayport", "delay", "delay1", "delay2", "delay3", "delay4", "statusmsg"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:37:59 mail postfix/smtp[1494]: 1F4AE321ACA: to=<MAILER-DAEMON@mail.example.com>, relay=none, delay=0.01, delays=0/0/0/0, dsn=5.4.6, status=bounced (mail for mail.example.com loops back to myself)
	{"name": "message_bounced_smtp",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": " + queueid_re + ": " + to_mail_re + ", " + relay_re + ", " + delay_re + ", " + delays_re + ", " + dsn_re + ", status=bounced \((.+)\)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to", "", "", "", "", "", "", "", "", "", "", "delay", "delay1", "delay2", "delay3", "delay4", "dsn", "statusmsg"),
		"smid": "queueid",
		"print": False},

	# Aug 26 09:53:53 mail postfix/error[26803]: 9C467321ACA: to=<nousername@example.com>, relay=none, delay=0.08, delays=0.01/0.07/0/0, dsn=5.0.0, status=bounced (example.com)
	{"name": "message_bounced_error",
		"regex": "^" + date_re + " " + hostname_re + " postfix/error" + pid_re + ": " + queueid_re + ": " + to_mail_re + ", " + relay_re + ", " + delay_re + ", " + delays_re + ", " + dsn_re + ", status=bounced \((.+)\)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to", "relayhostname", "", "", "", "", "", "", "", "", "", "delay", "delay1", "delay2", "delay3", "delay4", "dsn", "statusmsg"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:41:37 mail postfix/smtp[1494]: 70920321AD8: to=<name.surname@example-domain.com>, relay=none, delay=130583, delays=130580/0/3/0, dsn=4.4.1, status=deferred (connect to example-domain.com[192.168.4.9]:25: Connection refused)
	# Aug 28 08:21:36 mail postfix/smtp[23271]: 8511C321AD7: to=<mailarchive@[172.16.1.10]>, relay=172.16.1.10]:25, conn_use=2, delay=419, delays=419/0.02/0/0, dsn=4.3.1, status=deferred (host 172.16.1.10] said: 452 4.3.1 Insufficient system storage (in reply to MAIL FROM command))
	{"name": "message_deferred_smtp",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": " + queueid_re + ": " + to_mail_re + ", " + relay_re + "(, " + conn_use_re + ")?, " + delay_re + ", " + delays_re + ", " + dsn_re + ", status=deferred \((.+)\)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to", "", "", "", "", "", "relayhostname", "", "relayhostip", "", "relayport", "", "conn_use", "delay", "delay1", "delay2", "delay3", "delay4", "dsn", "errormsg"),
		"smid": "queueid",
		"print": False},

	# Aug 26 15:56:36 mail postfix/error[303]: B8582321AD6: to=<name.surname@example-domain.com>, relay=none, delay=432998, delays=432998/0.01/0/0.01, dsn=4.4.1, status=deferred (delivery temporarily suspended: connect to example-domain.com[192.168.4.9]:25: Connection refused)
	{"name": "message_deferred_error",
		"regex": "^" + date_re + " " + hostname_re + " postfix/error" + pid_re + ": " + queueid_re + ": " + to_mail_re + ", " + relay_re + ", " + delay_re + ", " + delays_re + ", " + dsn_re + ", status=deferred \((.+)\)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to", "", "", "", "", "", "", "", "", "", "", "delay", "delay1", "delay2", "delay3", "delay4", "dsn", "statusmsg"),
		"smid": "queueid",
		"print": False},

	# Aug 26 12:19:31 mail postfix/smtp[1664]: 5B972321AC7: host mail-in-a.mx.xnet.hr[83.139.103.70] said: 450 4.3.2 Service currently unavailable (in reply to RCPT TO command)
	{"name": "smtp_unavailable",
		"regex":  "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": " + queueid_re + ": host " + fqdn_or_unknown_and_ipv4_re + " said: (.+)$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "relayhostname", "", "relayhostip", "", "errormsg"),
		"smid": "queueid",
		"print": False},


	# Aug 26 11:43:10 mail postfix/smtp[23009]: 45F5A321AC7: host mta6.am0.yahoodns.net[66.196.118.35] refused to talk to me: 421 4.7.0 [GL01] Message from (212.92.192.73) temporarily deferred - 4.16.50. Please refer to http://postmaster.yahoo.com/errors/postmaster-21.html
	{"name": "message_deferred_spam",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": " + queueid_re + ": host " + fqdn_or_unknown_and_ipv4_re + " refused to talk to me: (.+)",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "relayhostname", "", "relayhostip", "", "errormsg"),
		"smid": "queueid",
                "print": False},

	# Aug 25 03:37:58 mail postfix/qmgr[3569]: ACF22321AC7: removed
	{"name": "message_removed",
		"regex": "^" + date_re + " " + hostname_re + " postfix/qmgr" + pid_re + ": " + queueid_re + ": removed",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid"),
		"smid": "queueid",
		"print": False},

	# Aug 25 11:41:37 mail postfix/qmgr[3569]: 477BB321ACC: from=<nsurname@example.com>, status=expired, returned to sender
	{"name": "message_expired",
		"regex": "^" + date_re + " " + hostname_re + " postfix/qmgr" + pid_re + ": " + queueid_re + ": " + from_mail_re + ", status=expired, returned to sender",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to"),
		"smid": "queueid",
                "print": False},

	# Aug 25 03:37:59 mail postfix/amavisd/smtpd[6894]: connect from localhost[127.0.0.1]
	{ "name": "amavisd_client_connect",
		"regex": "^" + date_re + " " + hostname_re + " postfix/amavisd/smtpd" + pid_re + ": connect from " + fqdn_or_unknown_and_ipv4_re,
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", ""),
		"smid": "AMAVISD",
		"print": False},

	# Aug 25 03:37:59 mail postfix/amavisd/smtpd[6894]: 1CE0D321AC7: client=localhost[127.0.0.1]
	{"name": "amavisd_queueid_identified",
		"regex": "^" + date_re + " " + hostname_re + " postfix/amavisd/smtpd" + pid_re + ": " + queueid_re + ": client=" + fqdn_or_unknown_and_ipv4_re,
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "clienthostname", "", "clienthostip", ""),
		"smid": "AMAVISD",
		"print": False},

	# Aug 25 03:37:59 mail postfix/amavisd/smtpd[6894]: disconnect from localhost[127.0.0.1]
	{"name": "amavisd_client_disconnect",
		"regex": "^" + date_re + " " + hostname_re + " postfix/amavisd/smtpd" + pid_re + ": disconnect from " + fqdn_or_unknown_and_ipv4_re,
		"fields": ("all", "timestamp", "hostname", "PID", "", "clienthostname", "", "clienthostip", ""),
		"smid": "AMAVISD",
		"print": False},

	# Aug 25 03:37:59 mail postfix/bounce[19921]: 1F4AE321ACA: sender non-delivery notification: 21361321ACB
	{"name": "delivery_status_error",
		"regex": "^" + date_re + " " + hostname_re + " postfix/bounce" + pid_re + ": " + queueid_re + ": sender non-delivery notification: " + queueid_re,
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "newqueueid"),
		"smid": "queueid",
		"print": False},

	# Aug 26 09:52:43 mail postfix/bounce[26512]: 8BC4D321ACB: sender delivery status notification: A3603321AC9
	{"name": "delivery_status_success",
		"regex": "^" + date_re + " " + hostname_re + " postfix/bounce" + pid_re + ": " + queueid_re + ": sender delivery status notification: " + queueid_re,
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "newqueueid"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:37:59 mail postfix/lmtp[9246]: 21361321ACB: to=<machine@example.com>, relay=mail.example.com[172.16.20.3]:7025, delay=0.06, delays=0/0/0.01/0.05, dsn=2.1.5, status=sent (250 2.1.5 Delivery OK)
	# Aug 26 17:26:53 mail postfix/lmtp[17391]: D1A22321AD0: to=<nsurname@example.com>, relay=mail.example.com[172.16.20.3]:7025, conn_use=2, delay=0.12, delays=0/0/0/0.11, dsn=2.1.5, status=sent (250 2.1.5 Delivery OK)
	# Aug 27 09:36:41 mail postfix/lmtp[19258]: BE8A0321ACC: to=<nsurname@example.com>, orig_to=<list@example.com>, relay=mail.example.com[172.16.20.3]:7025, delay=0.1, delays=0.01/0/0/0.09, dsn=2.1.5, status=sent (250 2.1.5 Delivery OK)
	{"name": "local_delivery",
		"regex": "^" + date_re + " " + hostname_re + " postfix/lmtp" + pid_re + ": " + queueid_re + ": " + to_mail_re + "(, " + orig_to_mail_re + ")?, " + relay_re + "(, " + conn_use_re + ")?, " + delay_re + ", " + delays_re + ", dsn=2.1.5, status=sent \(250 2.1.5 Delivery OK\)",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "to", "", "orig_to", "", "", "", "", "", "relayhostname", "", "relayhostip", "", "relayport", "", "conn_use", "delay", "delay1", "delay2", "delay3", "delay4"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:38:36 mail postfix/pickup[2268]: 17442321AC9: uid=498 from=<zimbra>
	{"name": "pickup",
		"regex": "^" + date_re + " " + hostname_re + " postfix/pickup" + pid_re + ": " + queueid_re + ": " + uid_re + " " + from_mail_re,
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "uid", "from"),
		"smid": "queueid",
		"print": False},

	# Aug 25 03:41:37 mail postfix/smtp[1494]: connect to example-domain.com[169.254.15.116]:25: No route to host
        {"name": "connect_error_no_route",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": connect to " + fqdn_or_unknown_and_ipv4_and_port_re + ": No route to host",
		"fields": ("all", "timestamp", "hostname", "PID", "", "", "remotehostname", "", "remotehostip", "", "remoteport"),
		"smid": "PID",
		"print": False},

	# Aug 25 03:41:37 mail postfix/smtp[1494]: connect to example-domain.com[192.168.4.8]:25: Connection refused
        {"name": "connect_error_connection_refused",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": connect to " + fqdn_or_unknown_and_ipv4_and_port_re + ": Connection refused",
		"fields": ("all", "timestamp", "hostname", "PID", "", "", "remotehostname", "", "remotehostip", "", "remoteport"),
		"smid": "PID",
		"print": False},

	# Aug 25 04:32:05 mail postfix/smtp[30314]: connect to 24x7onlineseo.com[74.220.199.6]:25: Connection timed out
        {"name": "connect_error_connection_refused",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": connect to " + fqdn_or_unknown_and_ipv4_and_port_re + ": Connection timed out",
		"fields": ("all", "timestamp", "hostname", "PID", "", "", "remotehostname", "", "remotehostip", "", "remoteport"),
		"smid": "PID",
		"print": False},

	# Aug 25 03:43:06 mail postfix/anvil[15611]: statistics: max connection rate 1/60s for (smtp:37.45.32.87) at Aug 25 03:35:52
        {"name": "anvil",
		"regex": "^" + date_re + " " + hostname_re + " postfix/anvil" + pid_re + ": .+$",
		"fields": ("all", "timestamp", "hostname", "PID"),
		"smid": "PID",
		"print": False},

	# Aug 25 04:05:19 mail postfix/scache[25189]: statistics: start interval Aug 25 04:03:15
        {"name": "scache",
		"regex": "^" + date_re + " " + hostname_re + " postfix/scache" + pid_re + ": .+$",
		"fields": ("all", "timestamp", "hostname", "PID"),
		"smid": "PID",
		"print": False},

	# Aug 25 03:57:00 mail postfix/smtpd[22024]: lost connection after HELO from unknown[123.18.191.216]
	# Aug 25 14:01:51 mail postfix/smtpd[24588]: lost connection after RSET from unknown[42.48.197.123]
	# Aug 25 08:22:34 mail postfix/smtpd[18966]: lost connection after AUTH from unknown[219.134.148.119]
	# Aug 25 11:27:42 mail postfix/smtpd[18196]: lost connection after CONNECT from unknown[117.221.217.73]
	# Aug 25 05:38:46 mail postfix/smtpd[24343]: lost connection after RCPT from unknown[181.129.225.240]
	# Aug 25 10:51:27 mail postfix/smtpd[18196]: lost connection after DATA (0 bytes) from unknown[46.100.157.63]
	# Aug 25 14:40:01 mail postfix/smtpd[23025]: lost connection after STARTTLS from unknown[1.1.1.1]
	# Aug 25 15:15:58 mail postfix/smtpd[24337]: timeout after DATA (0 bytes) from unknown[27.110.254.200]
	# Aug 26 17:17:09 mail postfix/smtpd[2587]: lost connection after DATA from unknown[199.180.198.253]
	# Aug 26 12:20:10 mail postfix/smtpd[9252]: lost connection after EHLO from unknown[5.237.23.230]
	# Aug 27 14:01:08 mail postfix/smtpd[25812]: lost connection after MAIL from ppp-115-87-237-91.revip4.asianet.co.th[115.87.237.91]
	# Aug 30 14:07:27 mail postfix/smtpd[19359]: lost connection after UNKNOWN from unknown[87.252.131.132]
	# Sep 17 18:46:33 mail postfix/smtpd[21470]: lost connection after NOOP from 220-253-191-240.dyn.iinet.net.au[220.253.191.240]
	# Sep 25 11:26:30 mail postfix/smtpd[17289]: too many errors after DATA from unknown[14.222.46.38]
	{"name": "smtpd_connection_error",
                "regex": "^" + date_re + " " + hostname_re + " postfix/smtpd" + pid_re + ": (too many errors|lost connection|timeout)" + " after (NOOP|END-OF-MESSAGE|UNKNOWN|MAIL|EHLO|STARTTLS|RSET|CONNECT|AUTH|HELO|RCPT|DATA|DATA \([0-9]+ bytes\)) from " + fqdn_or_unknown_and_ipv4_re,
		"fields": ("all", "timestamp", "hostname", "PID", "error", "state", "", "remotehostname", "", "remotehostip", ""),
		"smid": "PID",
                "print": False},

	# Aug 25 03:56:20 mail postfix/amavisd/smtpd[16299]: timeout after END-OF-MESSAGE from localhost[127.0.0.1]
	{"name": "amavisd_connection_error",
                "regex": "^" + date_re + " " + hostname_re + " postfix/amavisd/smtpd" + pid_re + ": (lost connection|timeout)" + " after (END-OF-MESSAGE|UNKNOWN|MAIL|EHLO|STARTTLS|RSET|CONNECT|AUTH|HELO|RCPT|DATA|DATA \([0-9]+ bytes\)) from " + fqdn_or_unknown_and_ipv4_re,
		"fields": ("all", "timestamp", "hostname", "PID", "error", "state", "", "remotehostname", "", "remotehostip", ""),
		"smid": "PID",
                "print": False},

	# Aug 25 05:14:16 mail postfix/dkimmilter/smtpd[27025]: timeout after END-OF-MESSAGE from localhost[127.0.0.1]
	{"name": "dkimmilter_connection_error",
                "regex": "^" + date_re + " " + hostname_re + " postfix/dkimmilter/smtpd" + pid_re + ": (lost connection|timeout)" + " after (END-OF-MESSAGE|UNKNOWN|MAIL|EHLO|STARTTLS|RSET|CONNECT|AUTH|HELO|RCPT|DATA|DATA \([0-9]+ bytes\)) from " + fqdn_or_unknown_and_ipv4_re,
		"fields": ("all", "timestamp", "hostname", "PID", "error", "state", "", "remotehostname", "", "remotehostip", ""),
		"smid": "PID",
                "print": False},

	# Aug 26 09:37:46 mail postfix/smtp[25848]: D4B65321AC7: enabling PIX workarounds: disable_esmtp delay_dotcrlf for tom.hrt.hr[213.5.56.13]:25
	{"name": "smtp_pix_workarounds",
		"regex": "^" + date_re + " " + hostname_re + " postfix/smtp" + pid_re + ": " + queueid_re + ": enabling PIX workarounds: disable_esmtp delay_dotcrlf for " + fqdn_or_unknown_and_ipv4_and_port_re + "$",
		"fields": ("all", "timestamp", "hostname", "PID", "queueid", "", "", "clienthostname", "", "clienthostip", "", "clientport"),
		"smid": "queueid",
		"print": False},

]

################################################################################
# Exception classes
################################################################################

class LogParserException(Exception): pass

class InternalLogParserException(LogParserException): pass

class UnhandledStateLogParserException(LogParserException): pass

class UnexpectedEventLogParserException(LogParserException): pass

class UnknownCommandLogParserException(LogParserException): pass

################################################################################
# Utility expressions
################################################################################

SMTPD		= "SMTPD"
DKIMMILTER	= "DKIMMILTER"
AMAVISD		= "AMAVISD"
INTERNAL	= "INTERNAL"
LOCAL		= "LOCAL"

CMD_ADDMSG	= "CMD_ADDMSG"
CMD_DELPID	= "CMD_DELPID"
CMD_MESSAGEDONE	= "CMD_MESSAGEDONE"

class MailMessageInstance:
	"""
	This class models mail message's single destination status.
	"""

	INIT			= "INIT"
	MESSAGE_QUEUED		= "MESSAGE_QUEUED"
	LOCALY_DELIVERED	= "LOCALY_DELIVERED"
	MESSAGE_BOUNCED		= "MESSAGE_BOUNCED"
	MESSAGE_SPAM		= "MESSAGE_SPAM"
	MESSAGE_REJECTED	= "MESSAGE_REJECTED"
	MESSAGE_DEFERRED	= "MESSAGE_DEFERRED"
	DSN_ERROR_GENERATED	= "DSN_ERROR_GENERATED"
	AMAVIS_10024		= "AMAVIS_10024"
	AMAVIS_10026		= "AMAVIS_10026"

	# Internal methods

	def _set_newqueueid(self, logRecord):
		if self.newqueueid != None:
			raise UnexpectedEventLogParserException("state: {}, newqueueid already defined: {}, input: {}".format(self.state, self.newqueueid, logRecord["all"]))

		self.newqueueid = logRecord["newqueueid"]

	def _set_relay(self, logRecord):

		if self.relayhostname != None or self.relayhostip != None or self.relayport != None:
			raise UnexpectedEventLogParserException("state: {}, newqueueid already defined: {}, input: {}".format(self.state, self.newqueueid, logRecord["all"]))

		self.relayhostname = logRecord["relayhostname"]
		self.relayhostip = logRecord["relayhostip"]
		self.relayport = logRecord["relayport"]

	# Public methods

	def __init__(self, rcpt_to):
		self.rcpt_to = rcpt_to
		self.state = self.INIT
		self.newqueueid = None
		self.relayhostname = None
		self.relayhostip = None
		self.relayport = None

	def __str__(self):
		return "STATE: {}, TO: {}".format(self.state, self.rcpt_to)

	def process(self, logRecord):

		if self.state == self.INIT:

			if logRecord["regex"]["name"] == "message_queued":
				self._set_newqueueid(logRecord)
				self._set_relay(logRecord)
				self.state = self.MESSAGE_QUEUED

			elif logRecord["regex"]["name"] == "message_queued_all":
				self._set_relay(logRecord)
				self.state = self.MESSAGE_QUEUED

			elif logRecord["regex"]["name"] == "local_delivery":
				self.state = self.LOCALY_DELIVERED

			elif logRecord["regex"]["name"] in ("message_deferred_smtp", "message_deferred_error"):
				self.state = self.MESSAGE_DEFERRED

			elif logRecord["regex"]["name"] in ("message_bounced_smtp", "message_bounced_error"):
				self.state = self.MESSAGE_BOUNCED

			elif logRecord["regex"]["name"] == "message_spam_discarded":
				self.spamid = logRecord["spamid"]
				self.state = self.MESSAGE_SPAM

			elif logRecord["regex"]["name"] == "smtpd_amavis_10026_queueid":
				self.state = self.AMAVIS_10026

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.MESSAGE_QUEUED:

			if logRecord["regex"]["name"] in ("message_queued", "message_queued_all"):
				# It can happen that the same message is queued more than once. This hapens due
				# to redirections, mailing list, etc. In that case it isn't possible to
				# differentiate specific messages as they all have the same log entry.
				# So, we just ignore multiple message_queued events.
				#
				# The better solution would be to check if they are really the same, and
				# raise and exception if they are not!
				pass

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.MESSAGE_BOUNCED:

			raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.AMAVIS_10026:

			if logRecord["regex"]["name"] == "message_queued":
				self._set_newqueueid(logRecord)
				self.relayhostname = logRecord["relayhostname"]
				self.relayhostip = logRecord["relayhostip"]
				self.relayhostip = logRecord["relayport"]
				self.state = self.MESSAGE_QUEUED

			elif logRecord["regex"]["name"] == "smtpd_amavis_10024_queueid":
				self.state = self.AMAVIS_10024

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.AMAVIS_10024:

			if logRecord["regex"]["name"] == "smtpd_address_rejected_queueid":
				self.state = self.MESSAGE_REJECTED

			elif logRecord["regex"]["name"] == "message_queued":
				self._set_newqueueid(logRecord)
				self.relayhostname = logRecord["relayhostname"]
				self.relayhostip = logRecord["relayhostip"]
				self.relayhostip = logRecord["relayport"]
				self.state = self.MESSAGE_QUEUED

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.MESSAGE_REJECTED:
			raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.MESSAGE_DEFERRED:

			if logRecord["regex"]["name"] == "message_queued_all":
				self.relayhostname = logRecord["relayhostname"]
				self.relayhostip = logRecord["relayhostip"]
				self.relayhostip = logRecord["relayport"]
				self.state = self.MESSAGE_QUEUED

			elif logRecord["regex"]["name"] == "message_queued":
				self._set_newqueueid(logRecord)
				self.relayhostname = logRecord["relayhostname"]
				self.relayhostip = logRecord["relayhostip"]
				self.relayhostip = logRecord["relayport"]
				self.state = self.MESSAGE_QUEUED

			elif logRecord["regex"]["name"] in ("message_deferred", "message_deferred_error"):
				pass

			elif logRecord["regex"]["name"] == "message_deferred_smtp":
				pass

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.LOCALY_DELIVERED:

			if logRecord["regex"]["name"] == "local_delivery":
				# The comment, and reason for this if, is the same as for message queued...
				pass

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		else:
			raise UnhandledStateLogParserException("{}".format(self.state))

class MailMessage:
	"""
	This class models mail message's processing through the Zimbra
	system. So, one object of this class is instantiated for every
	message created outside or within the Zimbra system.

	Note that this class models the complete processing of a mail
	message throught the Zimbra system, not only postfix.

	TODO
		State machines should be separated into the one global
		for every mail message, and specific for a certain
		destination address.
	"""

	INIT			= "INIT"
	QUEUEID_IDENTIFIED	= "QUEUEID_IDENTIFIED"
	MESSAGEID_IDENTIFIED	= "MESSAGEID_IDENTIFIED"
	MSGDONE			= "MSGDONE"
	MILTERREJECT		= "MILTERREJECT"

	def __init__(self, source=None, queueid=None, from_to=[],
			clienthostname=None, clienthostip=None):

		if queueid:
			self.state = self.QUEUEID_IDENTIFIED
		else:
			self.state = self.INIT

		self.message = {}

		self.message["source"] = source
		self.message["clienthostname"] = clienthostname
		self.message["clienthostip"] = clienthostip
		self.message["queueid"] = queueid
		self.message["logRecords"] = []

		self.message["instances"] = {}
		for from_address,to_address in from_to:
			self.message["instances"][(to_address, None)] = MailMessageInstance(to_address)
			if self.message.has_key("mail_from"):
				if self.message["mail_from"] != from_address:
					raise UnexpectedEventLogParserException("Expected single from address {}, received different one {}".format(self.message["mail_from"], from_address))
			else:
				self.message["mail_from"] = from_address

		# All log records belonging to a single Queue ID

	def getMessageID(self):
		if self.message.has_key("messageid"):
			return self.message["messageid"]

		return ""

	def process(self, logRecord):

		self.message["logRecords"].append(logRecord)

		if self.state == self.INIT:

			if logRecord["regex"]["name"] == "pickup":
				# We don't take FROM field since Zimbra will add domain and we'll have it later
				self.message["queueid"] = logRecord["queueid"]
				self.state = self.QUEUEID_IDENTIFIED

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.QUEUEID_IDENTIFIED:

			if logRecord["regex"]["name"] == "messageid_identified":
				self.message["messageid"] = logRecord["messageid"]
				self.state = self.MESSAGEID_IDENTIFIED

			elif logRecord["regex"]["name"] == "smtpd_amavis_10024_queueid":
				mail_from = logRecord["from"]
				if self.message.has_key("mail_from"):
					if self.message["mail_from"] != mail_from:
						raise UnexpectedEventLogParserException("Expected single from address {}, received different one {}".format(self.message["mail_from"], from_address))
				else:
					self.message["mail_from"] = mail_from

				if logRecord.has_key("orig_to"):
					raise

				rcpt_to = (logRecord["to"], None)
				if not self.message["instances"].has_key(rcpt_to):
					self.message["instances"][rcpt_to] = MailMessageInstance(rcpt_to)
				self.message["instances"][rcpt_to].process(logRecord)

			elif logRecord["regex"]["name"] == "smtpd_amavis_10026_queueid":
				mail_from = logRecord["from"]
				if self.message.has_key("mail_from"):
					if self.message["mail_from"] != mail_from:
						raise UnexpectedEventLogParserException("Expected single from address {}, received different one {}".format(self.message["mail_from"], from_address))
				else:
					self.message["mail_from"] = mail_from

				if logRecord.has_key("orig_to"):
					raise

				rcpt_to = (logRecord["to"], None)
				if not self.message["instances"].has_key(rcpt_to):
					self.message["instances"][rcpt_to] = MailMessageInstance(rcpt_to)
				self.message["instances"][rcpt_to].process(logRecord)

			elif logRecord["regex"]["name"] == "smtpd_address_rejected_queueid":
				mail_from = logRecord["from"]
				if self.message.has_key("mail_from"):
					if self.message["mail_from"] != mail_from:
						raise UnexpectedEventLogParserException("Expected single from address {}, received different one {}".format(self.message["mail_from"], from_address))
				else:
					self.message["mail_from"] = mail_from

				if logRecord.has_key("orig_to"):
					raise

				rcpt_to = (logRecord["to"], None)
				if not self.message["instances"].has_key(rcpt_to):
					print "DONT HAVE", rcpt_to
					self.message["instances"][rcpt_to] = MailMessageInstance(rcpt_to)
				self.message["instances"][rcpt_to].process(logRecord)

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.MESSAGEID_IDENTIFIED:

			if logRecord["regex"]["name"] == "from_identified":

				# Sanity check if we already have from, otherwise we set new value
				if not self.message.has_key("mail_from"):
					self.message["mail_from"] = logRecord["from"]
				else:
					# This is done to take into account a case when user puts in
					# MAIL FROM command only a user name and then mail server
					# adds domain or host name to form a complete mail address
					#
					# The code is now disabled because it happens that client
					# connects, says its mail address in MAIL FROM: and then
					# qmgr tells the address is something completely different!
					if not logRecord["from"].startswith(self.message["mail_from"]):
						print self.message
						raise UnexpectedEventLogParserException("Expected single from address {}, received different one in input: {}".format(self.message["mail_from"], logRecord["all"]))

			elif logRecord["regex"]["name"] in ("message_deferred_smtp", "message_deferred_error"):

				if logRecord.has_key("orig_to"):
					raise

				to = (logRecord["to"], None)
				if not self.message["instances"].has_key(to):
					self.message["instances"][to] = MailMessageInstance(to)
				self.message["instances"][to].process(logRecord)

			elif logRecord["regex"]["name"] in ("message_bounced_smtp", "message_bounced_error"):

				if logRecord.has_key("orig_to"):
					raise

				to = (logRecord["to"], None)
				if not self.message["instances"].has_key(to):
					self.message["instances"][to] = MailMessageInstance(to)
				self.message["instances"][to].process(logRecord)

			elif logRecord["regex"]["name"] == "message_queued":

				to = (logRecord["to"], logRecord["orig_to"])
				if not self.message["instances"].has_key(to):
					self.message["instances"][to] = MailMessageInstance(to)
				self.message["instances"][to].process(logRecord)

			elif logRecord["regex"]["name"] in ("message_queued_all", "message_spam_discarded", "local_delivery"):

				to = (logRecord["to"], logRecord["orig_to"])
				if not self.message["instances"].has_key(to):
					self.message["instances"][to] = MailMessageInstance(to)
				self.message["instances"][to].process(logRecord)

			elif logRecord["regex"]["name"] == "message_removed":

				self.state = self.MSGDONE
				return CMD_MESSAGEDONE, None

			elif logRecord["regex"]["name"] == "cleanup_milter_reject":

				self.state = self.MILTERREJECT
				return CMD_MESSAGEDONE, None

			elif logRecord["regex"]["name"] == "message_expired":

				if logRecord.has_key("orig_to"):
					raise

				# TODO: Record QueueID from the generated message!

			elif logRecord["regex"]["name"] == "delivery_status_error":

				if logRecord.has_key("orig_to"):
					raise

				# TODO: Record QueueID from the generated message!

			elif logRecord["regex"]["name"] == "delivery_status_success":

				if logRecord.has_key("orig_to"):
					raise

				# TODO: Record QueueID from the generated message!

			elif logRecord["regex"]["name"] == "smtp_unavailable":
				# We don't react to this message since next line will give details about the error message
				pass

			elif logRecord["regex"]["name"] == "message_deferred_spam":
				# This happens with graylisting and when the destination mail server is overloaded.
				# Unfortunatelly, we can not know so easily what destination address caused it
				# without more postprocessing...
				pass

			elif logRecord["regex"]["name"] == "smtp_pix_workarounds":
				pass

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		else:
			raise UnhandledStateLogParserException("{}".format(self.state))

		return None, None

class PostfixProcess():
	"""
	This class models a single postfix smtpd process.

	The key is that this is used to generate MailMessage objects.

	The reason this is done so is to be able to track how long some clients
	were holding connection open.
	"""

	INIT		= "INIT"
	CONNECTED	= "CONNECTED"
	AMAVIS_10026	= "AMAVIS_10026"
	MSGDONE		= "MSGDONE"

	def __init__(self, pid):
		self.reset(pid)

	def reset(self, pid):
		self.pid = pid
		self.state = self.INIT
		self.from_to = []

	def __str__(self):
		return "[POSTFIX {}] STATE: {}, FROMTO: {}".format(self.pid, self.state, self.from_to)

	def process(self, logRecord):

#		print "IN>>> ", self

		if self.state == self.INIT:

			if logRecord["regex"]["name"] == "smtpd_client_connect":
				self.clienthostname = logRecord["clienthostname"]
				self.clienthostip = logRecord["clienthostip"]

				self.state = self.CONNECTED

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.CONNECTED:

			if logRecord["regex"]["name"] == "smtpd_amavis_10026":
				self.from_to.append((logRecord["from"], logRecord["to"]))
				self.state = self.AMAVIS_10026

#			elif logRecord["regex"]["name"] == "smtpd_queueid_identified":
#				self.state = self.MSGDONE
#				print "OUT>>> ", self
#				return CMD_ADDMSG, MailMessage(source=SMTPD, queueid=logRecord["queueid"],
#							clienthostname=self.clienthostname, clienthostip=self.clienthostip)

			elif logRecord["regex"]["name"] == "smtpd_client_disconnect":
				# When the client connects and immediatelly disconnects, then
				# we handle that case with this IF statement.
#				print "OUT>>> ", self
				return CMD_DELPID, None

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.AMAVIS_10026:

			if logRecord["regex"]["name"] == "smtpd_queueid_identified":
				self.state = self.MSGDONE
#				print "OUT>>> ", self
				return CMD_ADDMSG, MailMessage(source=SMTPD, queueid=logRecord["queueid"],
							from_to=self.from_to,
							clienthostname=self.clienthostname, clienthostip=self.clienthostip)

			elif logRecord["regex"]["name"] == "smtpd_amavis_10026":
				self.from_to.append((logRecord["from"], logRecord["to"]))
				self.state = self.AMAVIS_10026

			elif logRecord["regex"]["name"] == "smtpd_client_disconnect":
#				print "OUT>>> ", self
				return CMD_DELPID, None

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.MSGDONE:

			self.reset(self.pid)

			if logRecord["regex"]["name"] == "smtpd_client_disconnect":
#				print "OUT>>> ", self
				return CMD_DELPID, None

			elif logRecord["regex"]["name"] == "smtpd_amavis_10026":
				self.from_to.append((logRecord["from"], logRecord["to"]))
				self.state = self.AMAVIS_10026

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		else:
			raise UnhandledStateLogParserException("{}".format(self.state))

#		print "OUT>>> ", self
		return None, None

class DKIMMilterProcess():
	"""
	This class models a single DKIMMILTER postfix smtpd process.

	The key is that this is used to generate MailMessage objects.
	"""

	INIT		= "INIT"
	CONNECTED	= "CONNECTED"

	def __init__(self, pid):
		self.pid = pid
		self.state = self.INIT

	def __str__(self):
		return "[DKIMMILTER PID: {}] STATE: {}".format(self.pid, self.state)

	def process(self, logRecord):

		if self.state == self.INIT:

			if logRecord["regex"]["name"] == "dkimmilter_client_connect":
				self.state = self.CONNECTED

			elif logRecord["regex"]["name"] == "dkimmilter_client_disconnect":
				return CMD_DELPID, None

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.CONNECTED:

			if logRecord["regex"]["name"] == "dkimmilter_queueid_identified":
				return CMD_ADDMSG, MailMessage(source=DKIMMILTER, queueid=logRecord["queueid"])

			elif logRecord["regex"]["name"] == "dkimmilter_client_disconnect":
				return CMD_DELPID, None

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		else:
			raise UnhandledStateLogParserException("{}".format(self.state))

		return None, None

class AmavisdProcess():
	"""
	This class models a single DKIMMILTER postfix smtpd process.

	The key is that this is used to generate MailMessage objects.
	"""

	INIT		= "INIT"
	CONNECTED	= "CONNECTED"

	def __init__(self, pid):
		self.pid = pid
		self.state = self.INIT

	def __str__(self):
		return "[AMAVISD PID: {}] STATE: {}".format(self.pid, self.state)

	def process(self, logRecord):

		if self.state == self.INIT:

			if logRecord["regex"]["name"] == "amavisd_client_connect":
				self.state = self.CONNECTED

			elif logRecord["regex"]["name"] == "amavisd_queueid_identified":
				# This can happen when logs are broken due to the log rotation.
				# Then, the process started, but it is not catched by the log
				# we have on our disposal.
				self.state = self.CONNECTED
				return CMD_ADDMSG, MailMessage(source=AMAVISD, queueid=logRecord["queueid"])

			elif logRecord["regex"]["name"] == "amavisd_client_disconnect":
				# This can happen due to the same reasons as for the previous
				# IF statement. In this case, we only return delete command.
				return CMD_DELPID, None

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		elif self.state == self.CONNECTED:

			if logRecord["regex"]["name"] == "amavisd_queueid_identified":
				return CMD_ADDMSG, MailMessage(source=AMAVISD, queueid=logRecord["queueid"])

			elif logRecord["regex"]["name"] == "amavisd_client_disconnect":
				return CMD_DELPID, None

			else:
				raise UnexpectedEventLogParserException("state: {}, event: {}, input: {}".format(self.state, logRecord["regex"]["name"], logRecord["all"]))

		else:
			raise UnhandledStateLogParserException("{}".format(self.state))

		return None, None

################################################################################
# Main classes
################################################################################

class ZimbraMailLog():

	def __init__(self):

		self.regex = zimbra8
		for regex in zimbra8:
			regex["cregex"] = re.compile(regex["regex"] + "$")

		# For generators of mail messages
		self.stateProcessPID = {}

		# All the messages with assigned queueid currently being processed
		self.mailMessagesByQueueID = {}

		# All the processed messages
		self.processedMessages = []

	def parseLog(self, fileLikeObject):

		# To count line number
		lineCounter = 0

		logYear = datetime.today().year

		for line in fileLikeObject:
			lineCounter += 1
			if lineCounter % 10000 == 0: print lineCounter 

			for regex in self.regex:
				res = regex["cregex"].match(line)
				if not res:
					continue

				if regex.has_key("print") and regex["print"]:
					print regex["name"]
					print res.group()
					print res.groups()
					print
					sys.exit(1)

				break

			else:
				raise UnexpectedEventLogParserException("LINE({}): {}".format(lineCounter, line))

			# Create dictionary from "fields" data
			parsed_record = {}
			parsed_record["regex"] = regex
			for k,v in zip(regex["fields"], xrange(len(regex["fields"]))):

				# Special processing for timestamp
				if k == "timestamp":
					parsed_record["timestamp"] = datetime.strptime(res.group(v), "%b %d %H:%M:%S").replace(logYear)
				else:
					if len(k): parsed_record[k] = res.group(v)

			if regex["smid"] == "POSTFIX":

				pid = parsed_record["PID"]
				if not self.stateProcessPID.has_key(pid):
					self.stateProcessPID[pid] = PostfixProcess(pid)
				cmd, arg = self.stateProcessPID[pid].process(parsed_record)

				if cmd == CMD_ADDMSG:
					self.mailMessagesByQueueID[parsed_record["queueid"]] = arg
				elif cmd == CMD_DELPID:
					del self.stateProcessPID[pid]
				elif cmd is not None:
					raise UnexpectedEventLogParserException("Unhandled command: {}".format(cmd))

			elif regex["smid"] == "DKIMMILTER":

				pid = parsed_record["PID"]
				if not self.stateProcessPID.has_key(pid):
					self.stateProcessPID[pid] = DKIMMilterProcess(pid)

				cmd, arg = self.stateProcessPID[pid].process(parsed_record)

				if cmd == CMD_ADDMSG:
					self.mailMessagesByQueueID[parsed_record["queueid"]] = arg
				elif cmd == CMD_DELPID:
					del self.stateProcessPID[pid]
				elif cmd is not None:
					raise UnexpectedEventLogParserException("Unhandled command: {}".format(cmd))

			elif regex["smid"] == "AMAVISD":

				pid = parsed_record["PID"]
				if not self.stateProcessPID.has_key(pid):
					self.stateProcessPID[pid] = AmavisdProcess(pid)
				cmd, arg = self.stateProcessPID[pid].process(parsed_record)

				if cmd == CMD_ADDMSG:
					self.mailMessagesByQueueID[parsed_record["queueid"]] = arg
				elif cmd == CMD_DELPID:
					del self.stateProcessPID[pid]
				elif cmd is not None:
					raise UnexpectedEventLogParserException("Unhandled command: {}".format(cmd))

			elif regex["smid"] == "queueid":

				queueid = parsed_record["queueid"]
				if not self.mailMessagesByQueueID.has_key(queueid):

					if regex["name"] == "messageid_identified":
						# It can happen than postfix/cleanup generates a new message in
						# response to some error. So, we handle that case here by
						# creating a new mail message object.
						self.mailMessagesByQueueID[queueid] = MailMessage(INTERNAL, queueid)

					elif regex["name"] == "pickup":
						# This handles localy generated mail messages
						#
						# Note that we don't pass queueid to constructor since we'll call
						# process method a bit later!
						self.mailMessagesByQueueID[queueid] = MailMessage(LOCAL)

					else:
						# This point is reached for messages that arrived before the
						# current log was started. Those messages we ignore for now,
						# but maybe we should collect them too.
						continue
						raise UnexpectedEventLogParserException("Unhandled queueid: {}".format(queueid))

				elif regex["name"] == "messageid_identified":

					# It happens that previous message "dissapeared" and then a new one
					# appears, with different messageid, and being a different message.
					# So to take into account that case, we first check that message id
					# is different (safegard), then we "retire" the old message, and we
					# instatiate a new message.

					if parsed_record["messageid"] == self.mailMessagesByQueueID[queueid].getMessageID():
						raise UnexpectedEventLogParserException("Unhandled queueid: {}".format(queueid))

					self.processedMessages.append(self.mailMessagesByQueueID[queueid])
					self.mailMessagesByQueueID[queueid] = MailMessage(INTERNAL, queueid)

				cmd, arg = self.mailMessagesByQueueID[queueid].process(parsed_record)

				if cmd == CMD_MESSAGEDONE:
					self.processedMessages.append(self.mailMessagesByQueueID[queueid])
					del self.mailMessagesByQueueID[queueid]

				elif cmd is not None:
					raise UnexpectedEventLogParserException("Unhandled command: {}".format(cmd))

	def consolidateMessagesByMessageID(self):
		"""
		The purpose of this method is to generate a list of messages that
		are originating ones, i.e. they came from the outside of the
		system. The consolidation is done using message ID.
		"""

		self.messagesByMessageID = {}
		for msg in self.processedMessages:

			msgid = msg.getMessageID()
			if not self.messagesByMessageID.has_key(msgid):
				self.messagesByMessageID[msgid] = []

			self.messagesByMessageID[msgid].append(msg)

	def dumpMessages(self):

		for msgid,msg in self.messagesByMessageID.items():
			print msg[0].message["queueid"], "from=", msg[0].message["mail_from"], "->", msg[0].message["instances"].keys()

def main(filename):
	mailLog = ZimbraMailLog()

	if filename.endswith(".xz"):
		mailLog.parseLog(lzma.LZMAFile(filename))
	else:
		mailLog.parseLog(open(filename))

	print "Consolidating messages...",
	mailLog.consolidateMessagesByMessageID()
	print ", done."
	mailLog.dumpMessages()

if __name__ == '__main__':
	main(sys.argv[1])
