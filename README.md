# DShield.py
DShield.py is a Python script that can parse Linux ipchains and iptables firewall logs as well as Snort syslog alerts into the DShield format and mail them (to DShield.org)

Comitted to github for archieving purposes. I might pick this one up one day, since the original authors seems to have abandonded it.

I changed some things to make it work on recent linux (see CHANGELOG) and bumped the version number to 4.0



                ... *sigh* documentating sucks :) ...

                            DShield.py
                (http://dshieldpy.sourceforge.net)


{0} Table of Contents
  1. About
  2. Configuring 
  3. Installing
  4. Notes


{1} About

  DShield.py is a Python script that can parse Linux ipchains and
iptables firewall logs as well as Snort syslog alerts into the DShield
format and mail them (to DShield.org)

  If you don't know what DShield is, I suggest you visit http://dshield.org
first... I mean... *now*. And don't forget to get an account :)

  Anyway, back to the script... I wrote the script because I wasn't
satisfied with DShield's default clients (and the Perl script didn't work
'out of the box' and I was too lazy to check what was wrong). None of the
clients converted the logs to the DShield format, although submitting
reports in that format saves DShield.org some load.

  The script uses the modules: ConfigParser, fileinput, getopt, os, re,
smtplib, string, sys, time, tempfile, pwd, locale, and optionally MySQLdb
and socket. If you did a default Python install, you'll have them except
for MySQLdb, but that's only needed if the database functionality is going
to be used. See README.db for details. If you haven't installed Python, do
it now. http://python.org. 

  Furthermore, the script does everything the DShield format wants: it
handles TCP flags for iptables and has optional IP obfuscation (see
http://dshield.org/specs.html for more info) and can ignore certain IPs used
for testing the firewall (for example). It can even sign the submission
with GPG, provided it is given the private key and passphrase (if the key is
passphrase-protected). Be sure to submit the public key to DShield before
using this feature. DShield.py is capable of saving the results of parsing
to a MySQL(TM) database for further data processing. See README.db in the
distribution directory for details.

  ATM, there aren't any known bugs (this line will never change, because I
won't release if I know of any bugs, doh :), of course you can 'ef' with the
settings, submit false, fake or broken logs, break the script or do
something else 'evil', but I don't count those as bugs. The script is open
source anyway, so you can do what you want with it. But when you _really_
use the script and something goes wrong, don't hesitate to submit bugs to me
(dshieldpy@33lc0.net)

  If you want to improve the script, go ahead! But make sure nobody is
working on the same thing, to avoid redundant development.  Check the CVS
(do a cvs checkout, or look at
http://cvs.sourceforge.net/cgi-bin/viewcvs.cgi/dshieldpy/DShield.py/ to see
if the script has been updated lately.


{2} Configuring

  There a few options the script can accept, some of them you'll _have_ to
set, others can be used for some useful *cough* functions. Don't worry about
the long list, because you probably only have to use the first 3 or 4 options.

  Some info about the options:

'email'      Your email address, as known by DShield. Your userid is linked to
             a certain email address and you must use that address for
             submission.

'file'       Set this to the latest _rotated_ version of the logfile the
             firewall uses. It's good to submit every day, so set it to a
             logfile rotated daily (see below for info on setting up
             DShield.py as a cron job). If you want the script to rotate the
             logfile, you must set this to the 'active' logfile. The file may
             grow during parsing, no problem :p

'mailto'     Where the report must be mailed to. To prevent 'broken'
             submissions (I think the script will handle it correct, but
             better safe than sorry :) this isn't set to reports@dshield.org.
             To test whether the script works correctly you can mail the
             report to test@dshield.org or (even better :) to me
             (dshieldpy@33lc0.net)

'userid'     You can leave this set to 0 to submit report anonymously. I
             strongly suggest you get yourself a DShield.org account and
             use the userid of your account.

'rotate'     Set this (to a path and filename) to rotate the logfile after
             it's parsed. I personally think it's better to let some scripts
             handle all your 'rotating' needs, but if you want it this way...
             fine.  Remember that you'll have to point 'file' to the 'active'
             logfile if you use this option.

'ignore'     If you want to test your firewall the problem arises that you'll
             submit _yourself_ to DShield. To avoid this problem you can use
             the 'ignore' option the set a list (or only one) IP to ignore
             'attacks' from. Seperate the list with commas. You can also
             ignore a subnet by setting (for example) '192.168.1.'. This will
             ignore all IPs containing '192.168.1.'. Note the dot at the end
             of the string, otherwise you'll also match 33.192.168.1 for
             example.

'logprefix'  This is an iptables-specific option. Use this to indicate
             what log prefix is used with the iptables LOG pseudo-target
             for accepted packets. If only dropped/rejected packets are
             logged, this option can be ignored.

'ipchains'   These three options disable the parser for the named
'iptables'   programs. Disabling what is not used will bring small
'snort'      performance gains. All are enabled by default.

'nat'        Some people have their NAT 'mangling' DST addresses (to
             192.168.1.2 for example). With this option you can 'un-nat'
             loglines, so they will be accepted by DShield. You can specify
             multiple "from - to" combinations, seperated by commas. For
             example: "192.168.10.2 - 212.121.212.121, 192.168.10.3 -
             232.323.232.323". If you're not really sure what this option is
             about, _don't_ use it!

'tlskey'     An SSL/TLS connection with the mail server will be attempted no
             matter what, if the mail server supports it. This option allows
             the user to specify his/her private key in PEM format, if the
             user has one. This option requires the tlscert option. This
             option is only available if Python 2.2 or newer is being
             used.

'tlscert'    This option specifies the user's personal certificate chain,
             in PEM format. This option requires the tlskey option. This
             option is only available if Python 2.2 or newer is being
             used.

'authname'   Some mail servers support the AUTH SMTP verb, which is to say,
             authentication using a number of different methods, other than
             TLS. Plaintext username/password and MD5 hashes are two examples.
             Specify the username for authentication to the mail server
             with this option. This option is only available if Python 2.2
             or newer is being used.

'authsecret' This is the password to be used with the username specified
             in the authname option. This option requires the authname
             option. SECURITY NOTE: If this option is used, it should
             never be used from the command line (although it is
             available), because the output of ps could allow anyone to
             capture the authentication secret. If it is placed in a
             configuration file, the configuration file should be mode
             600 (readable only by the owner). This option is only
             available if Python 2.2 or newer is being used.

'usegpg'     If specified, sign and encrypt all reports with GPG before
             sending them.

'gpgpath'    The path to the GPG executable. If this is not set, the PATH
             environment variable will be searched. This option implies
             the usegpg option. SECURITY NOTE: This kind of an option
             should always be set to avoid someone placing their trojanized
             executable in a directory specified in PATH.

'gpgkey'     Specifies which key from the keyring to use when signing
             the reports. If not set, the first key will be used. This
             option implies the usegpg option.

'gpgpass'    Sets the passphrase to be used to unlock the GPG key. This
             option implies the usegpg option. SECURITY NOTE: If this
             option is used, it should never be used from the command line
             (although it is available), because the output of ps could
             allow anyone to capture the passphrase. If it is placed in a
             configuration file, the configuration file should be
             readable/writable by no one but the owner (permissions 600).
             It is probably better to create a key without a passphrase,
             specifically for signing DShield submissions.

'usedb'      Instructs DShield.py to insert the results of parsing into
             a MySQL database.

'dbuser'     The username of the MySQL user. If not specified, the Unix
             username of the user running DShield.py is assumed.

'dbpass'     The password for MySQL access. If not specified, a blank
             password is assumed (duh).

'dblocation' Where to find the database. If the first character is "/",
             the database is assumed to be reachable over the Unix
             domain socket with full path specified. Otherwise, this
             option takes the form "hostname[:port]".

'copy'       Sends a copy of the report to yourself. I dunno if this is
             useful, but you can use it for checking or something...
             nevermind, it's a stupid function :)

'verbose'    Be verbose. Prints out some (useful?) information. Set to 'yes'
             or something if you want to use it.

'obfusc'     Use obfuscation to hide your IP address. You can set this to 'p'
             (or 'partial', changes the number before the first dot to 10) or
             'c' (or 'complete', changes the address to 10.0.0.1) to turn it
             on. See http://dshield.org/specs.html for (a little) more info.

'smtp'       The SMTP host to use to mail the report. Since about every Linux
             system has an SMTP server running by default, 'localhost' will do
             the trick. If a port other than the default port 25 is desired,
             simply add a colon and the port number, like this: mailhost:587

'timez'      The timezone to use, like the year, this is also determined
             automatically (using Pythons 'time' module) so you'll only have
             to set it if your system has some weird time settings or if you
             use the script on logfiles from a host in another timezone.

'year'       The program uses the current year by default, set to something
             else to override (only if you have a crappy system or something)

  Of course the script doesn't work properly until you set it up properly.
There are a few ways to do this.

  The best way (in my opinion :) is to make a file called dshieldpy.conf
and place it in /etc. The file looks something like this:

dshieldpy.conf
-----------------
[DEFAULT]

# needed
#email  = you@example.net
#file   = /path/to/logfile
#mailto = reports@dshield.org

# optional
#userid    = 0
#rotate    = /path/to/rotated.logfile
#ignore    = ip.to.ignore.1, ip.to.ignore.2
#nat       = translate.from.dst.ip - translate.to.dst.ip, trans...
#logprefix = ACCEPT

# parsing methods
#iptables = yes
#ipchains = yes
#snort    = yes

# (most) mail options
#tlskey     = /path/to/key.pem
#tlscert    = /path/to/cert.pem
#authname   = you
#authsecret = reallysecretsecret

# GPG signing
#usegpg  = yes
#gpgpath = /path/to/gpg
#gpgkey  = <you@example.com>
#gpgpass = mypassphrase

# Database options
#usedb      = yes
#dbuser     = you
#dbpass     = yourpassword
#dblocation = /var/mysql.sock

# extra (only 'no' disables)
#copy    = no
#verbose = no
# can be p(artial) or c(omplete)
#obfusc  = no

# override? (normally autodetected)
#smtp   = localhost
#timez  = +00:00
#year   = 2002
------------------

  Like I said before: you only _need_ to set the first three options. I
encourage you to get a DShield userid, but I discourage setting 'rotate'. If
you set 'verbose' and run the script as cron job you'll receive daily 'stats'
in your mailbox. (Nice! :)

  Another way is to call the script with some command line options:

$ dshield.py -h
Usage: dshield.py [OPTIONS]

Options:
 * -e, --email  <email>       your email address (as registered at DShield.org)
 * -f, --file   <filename>    the firewall log that must be parsed
 * -m, --mailto <email>       use reports@dshield.org for actual submissions
   -u, --userid <id>          your DShield.org userid (number)

   -i, --ignore <ip, ip>      comma seperated list (string) of IPs to ignore
   -l, --logprefix <string>   ignore iptables entries with this string
       --iptables <yes|no>    enable/disable iptables parser
       --ipchains <yes|no>    enable/disable ipchains parser
       --snort <yes|no>       enable/disable snort parser
   -o, --obfusc <p|c>         set to 'partial' or 'complete' for IP obfuscation
   -n, --nat    <ip1-ip2>     translate DST ip1 to ip2, usefull for 'un-natting'
   -r, --rotate <filename>    rotate the log to this file
   -t, --timez  <timezone>    your timezone in the format +HH:MM or -HH:MM
   -y, --year   <year>        the current year (since it's not logged) as YYYY
   -c, --copy                 send the report also to yourself (set by --email)

   -s, --smtp   <host>        the SMTP server to use
       --tlskey <filename>    private key for SSL/TLS with mail server
       --tlscert <filename>   personal certificate for SSL/TLS with mail
                              server (requires --tlskey)
       --authname <name>      username for authentication to mail server
       --authsecret <secret>  passphrase for authentication to mail server

       --usegpg               use GPG to sign submissions
       --gpgpath <path>       path to GPG executable (default=searches PATH)
   -k, --gpgkey <name>        name of GPG key (default=first key in ring)
   -p, --gpgpass <passphrase> passphrase to decrypt GPG key
                              (default=no passphrase)

       --usedb <yes|no>       additionally write the results to a database
                              (default=no)
       --dbuser <name>        username for accessing database.
                              (default=Unix username of user running script)
       --dbpass <passwd>      password for connecting to database.
                              (default=empty password)
       --dblocation <loc>     location of database.
                              (default=MySQL local default)

   -h, --help                 show this help
   -v, --verbose              show some stats
   -V, --version              show version info

A '*' means this option has to be set.
$

  Please keep in mind that you must use a string when setting the ignore or
nat option. For example...
  $ dshield.py -i ip.to.ignore.1, ip.to.ignore.2
... will only ignore ip.to.ignore.1. Do...
  $ dshield.py -i 'ip.to.ignore.1, ip.to.ignore.2'
... instead. (Yes, you can also use "double quotes")

  A third way to configure DShield.py is to edit the defaults in the source,
but I don't recommend that, because you'll have to edit it again and again
everytime you upgrade.

  Options will be parsed in the following order (the last setting of an
option overwrites any previously parsed settings): /etc/dshieldpy.conf,
$HOME/dshieldpy.conf, dshieldpy.conf (current dir), command line. 

  A note to GPG usage: If GPG is desired, a GPG key for signing must be
generated. Read the GPG documentation for how to do that, but such a command
usually looks like this: "gpg --gen-key". In order to encrypt submissions,
DShield's public keys are required. Get them from
http://www.dshield.org/dshield_public_key.txt then import them into the
public key ring using the following command:
"gpg --import dshield_public_key.txt". If desired, they can also be signed,
but this should not be necessary for encrypting reports.


{3} Installing

  'Installing' the DShield.py script is very easy. Since it is meant for
sysadmins I won't explain everything excessively.

  First make the script executable (probably already is) and place it in
some dir where you'll find it again (/usr/sbin or something)

  Then edit the default config file (dshieldpy.conf as found in this
package) and replace the default settings with your own. Make sure 'file'
points at the first rotated version of the logfile in which the firewall
messages are saved (probably /var/log/syslog.0 or /var/log/messages.0). If
you use the 'rotate' options you'll have to point 'file' at the most recent
(non-rotated) log file.

  Now edit your /etc/crontab. Make sure you know whether your firewall
logfile is rotated daily or weekly (daily is better). Snippet from my
crontab:

-------------
25 12   * * *   root    run-parts --report /etc/cron.daily
47 12   * * 7   root    run-parts --report /etc/cron.weekly
52 12   1 * *   root    run-parts --report /etc/cron.monthly
-------------

  Add a 'special' DShield.py line, since it must run just _after_ (10
minutes?) the logfile is rotated. Since my /var/log/syslog gets rotated
daily, I add the line:

35 12   * * *   root    /usr/sbin/dshield.py

  If you use 'rotate' you can enter any time, because the script itself
rotates the file.

  That should do the (daily) job...


{4} Notes

Please note that a patch needs to be applied to Python if Python 2.2 or
2.2.1 is being used. See README.python for details.

MySQL is a trademark of MySQL AB. http://www.mysql.com/

{X}

$Id: README,v 3.0 2002/09/22 13:46:55 arjones Exp $

{EOF}

