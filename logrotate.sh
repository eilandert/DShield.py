#!/bin/sh

cd /etc/iptables/dshield
./dshield.py




#
# Include something like this in /etc/logrotate.d/syslog
# Make sure logrotate is in the hourly crontab (it's not on ubuntu)

#/var/log/kern.log
#{
#        rotate 24
#        hourly
#        missingok
#        notifempty
#        delaycompress
#        compress
#        postrotate
#                /etc/iptables/dshield/logrotate.sh
#                /usr/lib/rsyslog/rsyslog-rotate
#        endscript
#}


