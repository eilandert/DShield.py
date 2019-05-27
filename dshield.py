#! /usr/bin/env python

# "DShield.py"
# dshield.org Snort, and Linux ipchains/iptables log parser
#
# Parses and mails an ipchains and/or iptables log (from the 
# Linux kernel) for submission to DShield.org to the DShield 
# format. Snort log entries will also be parsed and properly
# submitted
#
# Copyright (c) 2001, 2002 Eelco Lempsink (eelcolempsink@gmx.net)
#               and Andrew R. Jones (arjones@simultan.dyndns.org)
#
# Copyright (c) 2019 Thijs Eilander (eilander@myguard.nl)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See http://www.gnu.org/licenses/gpl.txt or COPYING


import ConfigParser, fileinput, getopt, os, re, smtplib, string, sys, time, tempfile, pwd, locale, email.utils

# import for MySQL module
UseMySQLdb = "1"
try:
    import MySQLdb
    # This is only required by dbwrite()
    import socket
except ImportError:
    UseMySQLdb = "0"

idstr = 'dshield.py v4.0 2019/05/27 Thijs Eilander https://github.com/eilandert/DShield.py'
client = 'DShield.py'
version = '4.0' 

# Is this how one declares global variables in Python?
ipchainsdbid = None
iptablesdbid = None
snortdbid = None

months = {'Jan':'01', 'Feb':'02', 'Mar':'03', 'Apr':'04', 'May':'05', 'Jun':'06', 'Jul':'07', 'Aug':'08', 'Sep':'09', 'Oct':'10', 'Nov':'11', 'Dec':'12'}

# Set the locale to the user's locale settings. The user ought to
# be root, which should be how nearly anything that uses a locale would
# be logged in syslog.
### Locales don't really work for Python < 2.2.
# Eelco: Since we have the hasattr() check, i felt free to re-enable this
# code. If You want to disable it again, go ahead, and i will take that
# as Your word that You will enable it when You feel the time it right.
if hasattr(locale, 'nl_langinfo'):
    locale.setlocale(locale.LC_ALL, '')
    lmonths = {}
    for i in range(1, 13):
        execcode = "lmonths[locale.nl_langinfo(locale.ABMON_%s)] = string.zfill('%s', 2)" % (i, i)
        exec execcode
else:
    lmonths = months


def main():
    "The 'heart' of the program, executes all other functions"

    global options

    # Set everything up.
    options = read_options()
    if UseMySQLdb == "1":
        getdbids()
        if not ipchainsdbid or not iptablesdbid or not snortdbid:
            print "Unrecoverable error. Exiting."
            return
        dbtmpname = tempfile.mktemp()
        dbtmpfp = open(dbtmpname, 'w')
    rtmpname = tempfile.mktemp()
    rtmpfp = open(rtmpname, 'w')

    subject = "FORMAT DSHIELD USERID %s  TZ %s VERSION %s %s" % (options['userid'], options['timez'], client, version)

    time.clock()

    # read and parse the logfile, then close the db temp file
    if UseMySQLdb == "1":
        lines, ignore = parse(rtmpfp, dbtmpfp)
        dbtmpfp.close()
    else:
        lines, ignore = parse(rtmpfp, None)

    # Close immediately, because GPG might need access
    rtmpfp.close()

    # Rotate the used logfile?
    if options['rotate']:
        try:
            os.rename(options['file'], options['rotate'])
            fp = os.open(options['file'], os.O_CREAT, 0600)
            os.close(fp)
            if options['verbose'] != 'no': 
                print "Rotated %s to %s" % (options['file'], options['rotate'])
        except:
            if options['verbose'] != 'no': 
                print "Rotating failed!"

    if lines:
        # Mail and sign the report, and output some info (if desired)
        clocked = time.clock()
        if options['verbose'] != 'no': 
            print "Parsed %d line(s) in %.1f seconds (%.1f lines/s), ignored %d line(s)" % (lines, clocked, lines/clocked, ignore)
        if options['usegpg'] != 'no':
            rtmpnamesig = tempfile.mktemp()
            if sign(rtmpname, rtmpnamesig):
                retval = deliver(subject, rtmpname)
            else:
                retval = deliver(subject, rtmpnamesig)
                os.remove(rtmpnamesig)
        else: 
            retval = deliver(subject, rtmpname)
        if options['verbose'] != 'no' and not retval:
            print "Mailed the report to %s" % options['mailto']
        os.remove(rtmpname)

        # Import into database, if desired
        if UseMySQLdb == "1":
            dbwrite(dbtmpname)
            os.remove(dbtmpname)
    else:
        if options['verbose'] != 'no': 
            print "No lines found, bummer..."


def read_options():
    """Read options from config files and the command line, returns the 
    defaults if no user options are found"""

    global UseMySQLdb

    # Required options
    required = ['file', 'email', 'mailto']

    # Get the year and timezone
    year, month = time.localtime(time.time())[0:2]
    if time.localtime(time.time())[8]:
        timez = -time.altzone / 3600
    else:
        timez = -time.timezone / 3600
    if timez >= 0:
        timez = '+' + string.zfill(timez, 2) + ':00'
    else:
        timez = string.zfill(timez, 3) + ':00'

    # Default options
    # Options with a short equivalent, using the first char
    options = {'file'       : '',
               'year'       : year,
               'smtp'       : 'localhost',
               'userid'     : '0',
               'timez'      : timez,
               'email'      : '',
               'mailto'     : '',
               'copy'       : 'no',
               'obfusc'     : 'no',
               'verbose'    : 'no',
               'rotate'     : '',
               'ignore'     : '',
               'nat'        : '',
               'logprefix'  : 'ACCEPT'}
    # Options without short equivalents
    longoptions = {'tlskey'     : '',
                   'tlscert'    : '',
                   'authname'   : '',
                   'authsecret' : '',
                   'usegpg'     : 'no',
                   'gpgpath'    : 'gpg',
                   'gpgkey'     : '',
                   'gpgpass'    : '',
                   'usedb'      : 'no',
                   'dbuser'     : '',
                   'dbpass'     : '',
                   'dblocation' : '',
                   'ipchains'   : 'yes',
                   'iptables'   : 'yes',
                   'snort'      : 'yes'}

    # Read options from config files
    config = ConfigParser.ConfigParser()

    configfile = 'dshieldpy.conf'
    config.read(['/etc/' + configfile, os.environ['HOME'] + '/' + configfile, configfile])

    for option in options.keys():
        execcode = "if config.defaults().has_key('%s'): options['%s'] = config.defaults()['%s']" % (option, option, option)
        exec execcode
    for option in longoptions.keys():
        execcode = "if config.defaults().has_key('%s'): longoptions['%s'] = config.defaults()['%s']" % (option, option, option)
        exec execcode

    # Read options from command line
    helpstr = 'Usage: ' + sys.argv[0] + ' [OPTIONS]' + """\n
Options:
 * -e, --email  <email>       your email address (as registered at DShield.org)
 * -f, --file   <filename>    the firewall log that must be parsed
 * -m, --mailto <email>       use reports@dshield.org for actual submissions
   -u, --userid <id>          your DShield.org userid (number)\n
   -i, --ignore <ip, ip>      comma seperated list (string) of IPs to ignore
   -l, --logprefix <string>   ignore iptables entries with this string
       --iptables <yes|no>    enable/disable iptables parser
       --ipchains <yes|no>    enable/disable ipchains parser
       --snort <yes|no>       enable/disable snort parser
   -o, --obfusc <p|c>         set to 'partial' or 'complete' for IP obfuscation
   -n, --nat    <ip1-ip2>     translate DST ip1 to ip2, usefull for 'un-natting'\n
   -r, --rotate <filename>    rotate the log to this file
   -t, --timez  <timezone>    your timezone in the format +HH:MM or -HH:MM
   -y, --year   <year>        the current year (since it's not logged) as YYYY
   -c, --copy                 send the report also to yourself (set by --email)\n
   -s, --smtp   <host>        the SMTP server to use
       --tlskey <filename>    private key for SSL/TLS with mail server
       --tlscert <filename>   personal certificate for SSL/TLS with mail
                              server (requires --tlskey)
       --authname <name>      username for authentication to mail server
       --authsecret <secret>  passphrase for authentication to mail server\n
       --usegpg <yes|no>      use GPG to sign submissions
       --gpgpath <path>       path to GPG executable (default=searches PATH)
   -k, --gpgkey <name>        name of GPG key (default=first key in ring)
   -p, --gpgpass <passphrase> passphrase to decrypt GPG key
                              (default=no passphrase)\n
       --usedb <yes|no>       additionally write the results to a database
                              (default=no)
       --dbuser <name>        username for accessing database.
                              (default=Unix username of user running script)
       --dbpass <passwd>      password for connecting to database.
                              (default=empty password)
       --dblocation <loc>     location of database.
                              (default=MySQL local default)\n
   -h, --help                 show this help
   -v, --verbose              show some stats
   -V, --version              show version info\n
A '*' means this option has to be set."""

    optlist, args = getopt.getopt(sys.argv[1:], 'f:y:s:u:t:e:m:co:hVvi:l:r:n:', ['file=', 'year=', 'smtp=', 'userid=', 'timez=', 'email=', 'mailto=', 'copy', 'obfusc=', 'help', 'version', 'verbose', 'ignore=', 'logprefix=', 'rotate=', 'nat=', 'tlskey=', 'tlscert=', 'authname=', 'authsecret=', 'usegpg=', 'gpgpath=', 'gpgkey=', 'gpgpass=', 'usedb=', 'dbuser=', 'dbpass=', 'dblocation=', 'iptables=', 'snort=', 'ipchains='])

    # Parse command line options
    for o, a in optlist:
        if (o == '-c' or o == '--copy'):
            options['copy'] = 'yes'
        elif (o == '-h' or o == '--help'):
            print helpstr
            sys.exit()
        elif (o == '-V' or o == '--version'):
            print client, idstr
            sys.exit()
        elif (o == '-v' or o == '--verbose'):
            options['verbose'] = 'yes'
        else:
            for option in longoptions.keys():
                execcode = "if (o == '--%s'): longoptions['%s'] = a" % (option, option)
                exec execcode
            for option in options.keys():
                execcode = "if (o == '-%s' or o == '--%s'): options['%s'] = a" % (option[0], option, option)
                exec execcode

    # Include the longoptions in options
    options.update(longoptions)    
    
    # Protect the user from his own misconfigurations
    for option in required:
        if not options[option]:
            print "Required option '%s' is not set!" % option
            sys.exit(1)
    if options['tlscert'] and not options['tlskey'] or not options['tlscert'] and options['tlskey']:
        print "One but not both of tlskey and tlscert is set."
        sys.exit(1)
    if options['gpgkey'] or options['gpgpass'] or options['gpgpath'] != 'gpg':
        options['usegpg'] = 'yes'
    if options['authsecret'] and not options['authname']:
        print "authsecret non-empty, but no authname specified."
        sys.exit(1)
    # aj: Here we really ought to be checking that we have sufficient
    #     access to the files, but i'm too lazy for that right now.
    # el: (I suggest to let Python do that kind of error checking)
    # aj: What form would that take? I hope we're not talking about
    #     tracebacks, because i would hardly call that error checking...
    # el: Well, it's not really checking, but the error message is clear
    #     enough, most of the time :) I think it's not worth the effort, so
    #     it's very very low on the priority list, IMHO.
    # Um, i'm sure this can be done better with exec, right? Any takers...?
    if options['tlskey'] and not os.path.exists(options['tlskey']):
        print "File %s does not exist" % (options['tlskey'])
        sys.exit(1)
    if options['tlscert'] and not os.path.exists(options['tlscert']):
        print "File %s does not exist" % (options['tlscert'])
        sys.exit(1)
    if options['gpgpath'] != 'gpg' and not os.path.exists(options['gpgpath']):
        print "File %s does not exist" % (options['gpgpath'])
        sys.exit(1)
    # How's THIS for fast parsing? (Sweet!)
    if options['iptables'] != 'yes' and options['ipchains'] != 'yes' and options['snort'] != 'yes':
        if options['verbose'] != 'no': print "All parsers disabled. Exiting."
        sys.exit(1)

    if options['usedb'] == 'yes':
        if UseMySQLdb == "0" and options['verbose'] != 'no':
            print "Database support requested, but database module not available.\nPlease read README.db in the DShield.py distribution directory.\nContinuing without database support."
    else:
        if UseMySQLdb == "1":
            # Database support available, but not desired.
            UseMySQLdb = "0";
        for opt in ("dbuser", "dbpass", "dblocation"):
            # Does this work with I18N?
            execcode = "if options['%s'] and options['verbose']: print '%s set, but database support not enabled with usedb.'" % (opt, opt)
            exec execcode

    # This option can't be set
    options['month'] = month

    # Return all options
    return options


def deliver(subject, msg):
    "The entire SMTP session happens here"

    # Open the connection and introduce ourselves
    try:
        mailserv = smtplib.SMTP(options['smtp'],'587','reporter.dshield.org')
    except smtplib.SMTPConnectError:
        print "Failure to connect to %s" % (options['smtp'])
        return 1

    # I suppose it's possible that someone out there is still living
    # in the pre-ESMTP dark ages...
    # We're not doing error-checking on helo(). If that doesn't work,
    # the user has bigger problems than not being able to submit a report.
    mailserv.ehlo()
    does_esmtp = mailserv.does_esmtp
    if not does_esmtp: 
        mailserv.helo()

    # Immediately attempt encryption
    # How do we handle errors here? (Let Python do it)
    # NOTE: starttls() was not introduced until Python 2.2, and even in that
    # (or at least in 2.2.1), it has a bug. Thus the check for the sendall
    # attribute in smtplib.SSLFakeSocket. This should be removed later.
    if does_esmtp and mailserv.has_extn('STARTTLS') and hasattr(mailserv, 'starttls'):
        if options['tlskey'] and options['tlscert']:
            mailserv.starttls(options['tlskey'], options['tlscert'])
        else: mailserv.starttls()
        mailserv.ehlo()

    # Authenticate to server, if requested
    if options['authname']:
        if does_esmtp and mailserv.has_extn('AUTH') and hasattr(mailserv, 'login'):
            try:
                mailserv.login(options['authname'], options['authsecret'])
            except smtplib.SMTPAuthenticationError:
                print "Authentication to mail server failed"
            except smtplib.SMTPException:
                print "No suitable authentication method found"
        else:
            if options['verbose'] != 'no':
                print "Option authname set, but mail server does not support"
                print "authentication (SMTP AUTH verb), or Python < 2.2"
                print "is being used."

    # We probably ought to call mailserv.quoteaddr() for both the
    # sender and recipient, but we don't anticipate problems (read:
    # we're too lazy to).

    # Send a copy of the report to ourselves?
    if options['copy'] != 'no':
        header = "From: %s\r\nTo: %s, %s\r\n" % (options['email'], options['mailto'], options['email']) 
    else:
        header = "From: %s\r\nTo: %s\r\n" % (options['email'], options['mailto'])

    header = header + "Subject: %s\r\nUser-Agent: %s %s\r\n" % (subject, client, idstr)        

    # Add time header
    header = header + "Date: %s\r\n\r\n" % email.utils.formatdate(time.time(), localtime=True)

    # RFC 1870 requires us to include all headers and all CRLF pairs in our
    # size calculation, but not all protecting dots, or the EOM dot.
    msgsize = "SIZE=%d" % (os.path.getsize(msg) + len(header) + 1)

    # Inform the mail server of the sender and message size
    if does_esmtp and mailserv.has_extn('SIZE'):
 	code, resp = mailserv.docmd("MAIL FROM: %s %s" % (options['email'], msgsize))
    else:
    	code, resp = mailserv.docmd("MAIL FROM: %s" % (options['email']))
    if code <> 250:
        print "While attempting to send mail from %s, the mail server replied:\n%s" % (options['email'], resp)
        mailserv.quit()
        return 1

    # Tell the mail server to whom we're sending.
    # I would love to check for errors here, but i don't know how.
    code, resp = mailserv.rcpt(options['mailto'])
    if code <> 250:
        print "While attempting to send mail to %s, the mail server replied:\n%s" % (options['mailto'], resp)
        mailserv.quit()
        return 1
    if options['copy'] != 'no':
        code, resp = mailserv.rcpt(options['email'])
        if code <> 250 and options['verbose'] != 'no':
            print "While attempting to send a copy of the report, the mail server replied:\n%s\nContinuing with submission." % (resp)

    # Start the DATA section. We don't quote the message with a dot in
    # front of every line, because we know our data, and we will never
    # have a dot on a line by itself.
    code, resp = mailserv.docmd("DATA")
    if code <> 354:
        print "While attempting to send the report, the mail server replied:\n%s" % (resp)
        mailserv.quit()
        return 1

    try:
        mailserv.send(header)
        fp = open(msg, 'r')
        reportline = fp.readline()
        while reportline:
            mailserv.send(reportline)
            reportline = fp.readline()

        mailserv.send("\r\n.\r\n")
        mailserv.quit()
    except smtplib.SMTPServerDisconnected:
        print "The connection to the mail server was broken during transmission."
        return 1

    return 0


def sign(unsigned, signed):
    "Signs the report if a GPG key is provided"
    if options['verbose'] != 'no': 
        print "Signing report with GPG key %s" % (options['gpgkey'])

    # We don't assume that HOME is set properly. If this is run from cron,
    # HOME is probably wrong.
    # (HOME is used for reading a config file too, apply there too?)
    os.environ['HOME'] = pwd.getpwuid(os.getuid())[5]

    # We do assume the user has set his/her PATH reasonably.
    gpgcommand = '%s --output %s --batch --no-secmem-warning' % (options['gpgpath'], signed)
    if options['gpgkey']: 
        gpgcommand = "%s --default-key '%s'" % (gpgcommand, options['gpgkey'])
    if options['gpgpass']: 
        gpgcommand = '%s --passphrase-fd 0' % (gpgcommand)
    if not os.popen("%s --list-public-keys %s" % (options['gpgpath'], options['mailto'])).close():
        gpgcommand = "%s --armor --encrypt --sign --recipient %s %s" % (gpgcommand, options['mailto'], unsigned)
    else: 
        gpgcommand = '%s --clearsign %s' % (gpgcommand, unsigned)

    gpgpipe = os.popen(gpgcommand, 'w', 0)
    if options['gpgpass']: 
        gpgpipe.write('%s\n' % (options['gpgpass']))

    # Calling close on the pipe waits for GPG to terminate
    if gpgpipe.close():
        print "GPG returned an error"
        if os.path.exists(signed):
            os.remove(signed)
        return 1

    return 0


def testignore(SRC):
    """Tests if this IP address should be ignored. At the moment, this only
    checks the source IP address, but can easily be extended to filter on
    other parameters."""

    if options['ignore']:
        ignore = re.split(r'\s*,\s*', options['ignore'])
        for ip in ignore:
            if string.count(SRC, ip) == 1:
                return 1
    return 0


def report(rtmpfp, dbtmpfp, month, day, ltime, count, SRC, SPT, DST, DPT, PROTO, FLAGS, method):
    "Constructs and mails one line of the report"

    # 'Un-natting' (if set)
    if options['nat']:
        un_nat = re.split(r'\s*,\s*', options['nat'])
        for trans in un_nat:
            from_ip, to_ip = re.split('\s*-\s*', trans)
            if DST == from_ip:
                DST = to_ip
                break

    # Obfuscation?
    obfusc = options['obfusc']
    if (obfusc == 'partial' or obfusc == 'p'):
        DST = re.sub(r'\d+', '10', DST, 1)
    elif (obfusc == 'complete' or obfusc == 'c'):
        DST = '10.0.0.1'

    # Detect the turn of the year
    year = options['year']
    if options['month'] < int(month):
        year = year - 1

    # Write a formatted line to the e-mail output file
    msg = "%s-%s-%s %s %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\r\n" % (year, month, day, ltime, options['timez'], options['userid'], count, SRC, SPT, DST, DPT, PROTO, FLAGS)
    rtmpfp.write(msg)

    if UseMySQLdb == "1":
        # Write a similar formatted line to the database commands file
        if SPT == "???": lSPT = "\\N"
        else: lSPT = SPT;
        if DPT == "???": lDPT = "\\N"
        else: lDPT = DPT
        # Convert to a single byte
        if FLAGS:
            lFLAGS = 0
            if string.find(FLAGS, "W") != -1:
                lFLAGS = lFLAGS + 128
            if string.find(FLAGS, "E") != -1:
                lFLAGS = lFLAGS + 64
            if string.find(FLAGS, "U") != -1:
                lFLAGS = lFLAGS + 32
            if string.find(FLAGS, "A") != -1:
                lFLAGS = lFLAGS + 16
            if string.find(FLAGS, "P") != -1:
                lFLAGS = lFLAGS + 8
            if string.find(FLAGS, "R") != -1:
                lFLAGS = lFLAGS + 4
            if string.find(FLAGS, "S") != -1:
                lFLAGS = lFLAGS + 2
            if string.find(FLAGS, "F") != -1:
                lFLAGS = lFLAGS + 1
        # Too bad socket.inet_aton() won't work for this...
        lSRC1, lSRC2, lSRC3, lSRC4 = string.split(SRC, '.')
        lSRC = (long(lSRC1) << 24) + (long(lSRC2) << 16) + (long(lSRC3) << 8) + long(lSRC4)
        lDST1, lDST2, lDST3, lDST4 = string.split(DST, '.')
        lDST = (long(lDST1) << 24) + (long(lDST2) << 16) + (long(lDST3) << 8) + long(lDST4)
        if PROTO.isdigit():
            lPROTO = int(PROTO)
        else:
            try:
                lPROTO = socket.getprotobyname(PROTO)
            except socket.error:
                # Generally speaking, it is entirely possible that entries
                # will be generated on a machine that has an entry in
                # /etc/protocols for a certain protocol number, but processed
                # on a machine that does not. However, the original reason
                # for adding this is that Netfilter is smart enough to call
                # protocol 50 "ESP", and protocol 51 "AH", but /etc/protocols
                # on Linux calls them "ipv6-crypt" and "ipv6-auth",
                # respectively. While neither one is wrong or right, they
                # don't work together.
                if PROTO.upper() == "ESP":
                    lPROTO = 50
                elif PROTO.upper() == "AH":
                    lPROTO = 51
                else:
                    lPROTO = -1  # Don't write to the database
                    # TODO: What we really ought to do here is change the
                    # database format to accept NULL in the protocol field.
        if method == "ipchains":
            methodid = ipchainsdbid
        elif method == "iptables":
            methodid = iptablesdbid
        else:
            methodid = snortdbid
        if lPROTO != -1:
            # I HAD wanted to avoid such an "if" construction, but ...
            if FLAGS:
                msg = "\\N\t%s-%s-%s %s\t%d\t%s\t%d\t%s\t%d\t%d\t%s\t%s\n" \
                    % (year, month, day, ltime, lSRC, lSPT, lDST, lDPT,
                    lPROTO, lFLAGS, count, methodid)
            else:
                msg = "\\N\t%s-%s-%s %s\t%d\t%s\t%d\t%s\t%d\t\\N\t%s\t%s\n" \
                    % (year, month, day, ltime, lSRC, lSPT, lDST, lDPT,
                    lPROTO, count, methodid)
            dbtmpfp.write(msg)

    return 0


def parse (rtmpfp, dbtmpfp):
    "Parse the logfile."

    # This is set apart for two reasons: First, it was a little too much
    # for main(), and second, we really want to avoid the overhead of an
    # extra function call with lots of parameters for every line of the log.
    # Besides the call to report(). Inlining that would be a little too much.

    count, ignore, lines = 0, 0, 0
    month, day, ltime = ('',) * 3
    SRC, SPT, DST, DPT, PROTO, FLAGS, method = ('',) * 7
    pmonth, pday, pltime = ('',) * 3
    pSRC, pSPT, pDST, pDPT, pPROTO, pFLAGS, pmethod = ('',) * 7

    # Regular expressions that are used many times in the course of a
    # program should be compiled for the sake of efficiency.
    # The first regex will admittedly take a little longer than the former
    # one, but it is also more accurate. It's not impossible that someone
    # could define their log prefix to be something like "BLOCK-IN=HTTP",
    # which could potentially give us an erroneous match in the old code.

    if options['iptables'] != 'no':
        iptre1 = re.compile(r'([A-Za-z]+) +(\d{1,2}) ([0-9:]{8}) [^ ]+ kernel: .{0,32}IN=[^ ]+ OUT=[^ ]* (MAC=[^ ]* )*SRC=([0-9.]+) DST=([0-9.]+).{0,45}PROTO=(.*)$')
        iptre2u = re.compile(r'UDP SPT=(\d+) DPT=(\d+) ')
        iptre2t = re.compile(r'TCP SPT=(\d+) DPT=(\d{1,5}) WINDOW=\d{1,5} RES=0x[0-9A-Fa-f]+ (([A-Z]{3} )*)U')
        iptre2i = re.compile(r'ICMP TYPE=(\d+) CODE=(\d+) ')
    
    if options['ipchains'] != 'no':
        ipcre =  re.compile(r'([A-Za-z]+) +(\d{1,2}) ([0-9:]{8}) [^ ]+ kernel: Packet log: input (DENY|REJECT) \w+ PROTO=(\d+) ([0-9.]+):(\d+) ([0-9.]+):(\d+) ')
    
    if options['snort'] != 'no':
        snortre = re.compile(r'([A-Za-z]+) +(\d{1,2}) ([0-9:]{8}) [^ ]+ snort:[^{]+\{(TCP|UDP)\} ([0-9.]+):(\d+) -> ([0-9.]+):(\d+)$')

    # read and parse the logfile
    if options['verbose'] != 'no': 
        print "Opening %s for reading..." % options['file']
    
    try:
        fp = open(options['file'], 'r')
    except IOError, e:
        print "Error opening %s.\nError returned: %s.\nExiting." % (options['file'], e.strerror)
        sys.exit(1)
    
    while 1:
        # Is there a particular reason why a size is specified here?
        line = fp.readline(300)
        if not line: 
            break
        
        matched, discarded = 0, 0
        
        if options['iptables'] != 'no':
            # The first regex should be enough to guarantee a valid
            # iptables log entry.
            iptmatch1 = iptre1.match(line)
            if iptmatch1: 
                matched = 1
            
            # If we check this in the "if" one level up, we force the
            # other parsers to check accepted lines from iptables.
            if matched and ((options['logprefix'] and not string.count(line, options['logprefix'])) or not options['logprefix']):
                month, day, ltime = iptmatch1.group(1, 2, 3)
                SRC, DST = iptmatch1.group(5, 6)

                iptmatch2u = iptre2u.match(iptmatch1.group(7))
                if iptmatch2u:
                    PROTO, FLAGS = 'UDP', ''
                    SPT, DPT = iptmatch2u.groups()
                else:
                    iptmatch2t = iptre2t.match(iptmatch1.group(7))
                    if iptmatch2t:
                        PROTO = 'TCP'
                        SPT, DPT = iptmatch2t.group(1, 2)
                        # Is there a really elegant one-liner for this?
                        longflags = string.split(iptmatch2t.group(4))
                        FLAGS = ''
                        for flag in longflags:
                            # Explicit congestion notification, baby.
                            # The corresponding flags are CWR and ECE.
                            if flag[0] != 'C' and flag[0] != 'E':
                                FLAGS = FLAGS + flag[0]
                    else:
                        iptmatch2i = iptre2i.match(iptmatch1.group(7))
                        if iptmatch2i:
                            PROTO, FLAGS = 'ICMP', ''
                            SPT, DPT = iptmatch2i.groups()
                        else:
                            # Some other funky protocol. Ports are '???'.
                            PROTO = string.split(iptmatch1.group(7))[0]
                            FLAGS, SPT, DPT = '', '???', '???'

                matched, pmethod = 1, method
                method = 'iptables'
            elif matched:
                discarded = 1
                ignore = ignore + 1
        
        if options['snort'] != 'no' and not matched:
            snortmatch = snortre.match(line)
            if snortmatch:
                month, day, ltime, PROTO, SRC, SPT, DST, DPT = snortmatch.groups()
                matched, pmethod, FLAGS = 1, method, ''
                method = 'snort'
        
        if options['ipchains'] != 'no' and not matched:
            ipcmatch = ipcre.match(line)
            if ipcmatch:
                month, day, ltime, PROTO, SRC, SPT, DST, DPT = ipcmatch.group(1, 2, 3, 5, 6, 7, 8, 9)
                matched, pmethod, FLAGS = 1, method, ''
                method = 'ipchains'

        if matched and not discarded:
            # Check if this is a duplicate
            if month == pmonth and day == pday and ltime == pltime and SRC == pSRC and SPT == pSPT and DST == pDST and DPT == pDPT and PROTO == pPROTO and (FLAGS == pFLAGS or method != pmethod):
                # It wouldn't be cool to report the same attack twice if the
		# attack is reported by two different methods (e.g. iptables
                # and snort).
                if method == pmethod:
                    count = count + 1
                else:
                    ignore = ignore + 1
            else:
                if not testignore(SRC):
                    # This might be the first line
                    if pSRC:
                        if lmonths[pmonth] is not None:
                            pmonth = lmonths[pmonth]
                        else:
                            pmonth = months[pmonth]
                        pday = string.zfill(pday, 2)
                        ignore = ignore + report(rtmpfp, dbtmpfp, pmonth, pday, pltime, count, pSRC, pSPT, pDST, pDPT, pPROTO, pFLAGS, pmethod)
                    count = 1
                    pmonth, pday, pltime, pSRC, pSPT, pDST, pDPT, pPROTO, pFLAGS, pmethod = month, day, ltime, SRC, SPT, DST, DPT, PROTO, FLAGS, method

            lines = lines + 1

    # Get the last line after checking to see if any lines were found
    if pSRC:
        if lmonths[pmonth] is not None:
            pmonth = lmonths[pmonth]
        else:
            pmonth = months[pmonth]
        pday = string.zfill(pday, 2)
        ignore = ignore + report(rtmpfp, dbtmpfp, pmonth, pday, pltime, count, pSRC, pSPT, pDST, pDPT, pPROTO, pFLAGS, pmethod)

    return lines, ignore

def dbopen ():
    "Open the database in a safe way."

    # Prepare connection information
    if options['dblocation'] and options['dblocation'][0] == '/':
        lhost = ''
        lport = 0
        lsocket = options['dblocation']
    elif options['dblocation']:
        lhost, iport = options['dblocation'].split(':')
        if lhost[0].isdigit():
            # This is in dotted quad format. Sanity check.
            try:
                socket.gethostbyaddr(lhost)
            except socket.error:
                print "Invalid IP address specified in dblocation: %s" % (lhost)
                return None
        else:
            # Host name. Let's see if it resolves.
            try:
                socket.gethostbyname(lhost)
            except socket.error:
                print "Invalid hostname specified in dblocation: %s" % (lhost)
                return None
        lsocket = ''
        if not iport:
            # Default MySQL port
            lport = 3306
        elif not iport.isdigit():
            print "Error in specifying port. Must be a number."
            return None
        lport = int(iport)
        if lport < 0 or lport > 65535:
            print "Error in specifying port. Must be between 0 and 65535, inclusive."
            return None
    # If options['dblocation'] == '', then we don't pass any arguments
    # to MySQLdb.connect().

    # This is where it gets really fun. Newer versions (3.23.49+) of MySQL
    # don't allow LOAD DATA LOCAL unless specifically ordered to. This is
    # done for very valid security reasons, but it's a problem for us.
    # Thus, we create a temporary config file for MySQL that tells it
    # to allow LOAD DATA LOCAL, then pass the name of that file to connect().
    # A feature request has been put in to the author of MySQLdb to add
    # the capability to set this in connect(), since it is available in
    # the C API through the mysql_options() function. He might actually
    # do it, too.
    conffilename = tempfile.mktemp()
    conffilefp = open(conffilename, 'w')
    # Ought to do a try/except on the next line
    mycnffp = open("/etc/my.cnf", 'r')
    line = mycnffp.readline()
    while line:
        conffilefp.write(line)
        line = mycnffp.readline()
    mycnffp.close()
    # What we're missing right here is ~/.my.cnf for the user. We may
    # add it for root, but only if someone complains.
    conffilefp.write("\n[client]\nlocal-infile=1")
    conffilefp.close()

    # Connect to the database
    try:
        if not options['dblocation']:
            # MySQLdb doesn't handle specifying empty strings as a way
            # to indicate the defaults in /etc/my.cnf (or ~/.my.cnf)
            myconnect = MySQLdb.connect(user = options['dbuser'], passwd = options['dbpass'], db = "DShieldpy", read_default_file = conffilename)
        else:
            myconnect = MySQLdb.connect(host = lhost, port = lport, unix_socket = lsocket, user = options['dbuser'], passwd = options['dbpass'], db = "DShieldpy", read_default_file = conffilename)
    except MySQLdb.OperationalError, e:
        print "MySQLdb returned the following error:\n%s" % e[1]
        if e[0] == 1044:
            print "This error can be the result of a number of things. Most likey,\n'FLUSH PRIVILEGES' was not run after adding a user. It could also be\nthat the user or the database does not exist. Naturally, it could also be\nthat the given user does not have permission to access the given database."
        os.remove(conffilename)
        return None
    except TypeError, e:
        print "A mistake was probably made in specifying the database location;\nthe following error was returned by MySQL:\n%s" % (e)
        os.remove(conffilename)
        return None

    os.remove(conffilename)
    return myconnect


def getdbids():
    "Populate variables with the IDs of the method names from the database."

    global ipchainsdbid, iptablesdbid, snortdbid

    # Open database
    myconnect = dbopen()
    if not myconnect:
        return
    mycursor = myconnect.cursor()

    # Get the IDs from the "method" table for the various parsing methods
    try:
        mycursor.execute('SELECT id FROM method WHERE name="ipchains";')
        ipchainsdbid = mycursor.fetchone()[0]
        mycursor.execute('SELECT id FROM method WHERE name="iptables";')
        iptablesdbid = mycursor.fetchone()[0]
        mycursor.execute('SELECT id FROM method WHERE name="snort";')
        snortdbid = mycursor.fetchone()[0]
    except Error:
        print "One of the method identifiers (ipchains, iptables, snort) could\nnot be found in the DShield.py database."
        return


def dbwrite (dbtmpname):
    "Import data into the named database."

    # The documentation mentions no exceptions thrown or other error
    # checking mechanisms.

    if options['verbose'] != 'no':
        print "Entering data into database."

    # Open the database
    myconnect = dbopen()
    if not myconnect:
        return
    mycursor = myconnect.cursor()

    # Send our very simple query
    try:
        mycursor.execute("LOAD DATA LOCAL INFILE '%s' INTO TABLE attack" % (dbtmpname))
    except MySQLdb.ProgrammingError, e:
        print "MySQL returned the following error:\n%s" % (e[1])
        return
    except MySQLdb.OperationalError, e:
        print "MySQL returned the following error:\n%s" % (e[1])
        return
    except MySQLdb.Warning, e:
        mo = re.search("Records: (\d+)  Deleted: \d+  Skipped: \d+  Warnings: (\d+)", str(e))
        if (not mo or (mo.group(1) != mo.group(2))) and options['verbose'] != "no":
            print "MySQL returned warning(s):\n%s" % (e)
        # else: This is a bug in MySQL. It has been reported, fixed
        # by Monty himself, and will be in 4.0.3. I assume it will also
        # be in the next 3.23 release, but he didn't say that.
        # Details: When \N is used to indicate NULL when reading
        # data using LOAD DATA [LOCAL] INFILE and the field is labelled
        # as NOT NULL AUTO_INCREMENT (which is typical for ID fields),
        # a warning is generated for every imported line.

    # Clean up
    mycursor.close()
    myconnect.close()


main()
