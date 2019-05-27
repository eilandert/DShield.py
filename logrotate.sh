#!/bin/sh

cd /etc/iptables/dshield
./dshield.py




#
# Include something like this in /etc/logrotate.d/syslog

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
#        endscript
#}


