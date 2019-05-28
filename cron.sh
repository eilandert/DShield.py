#!/bin/sh

cd /etc/iptables/dshield
./dshield.py




#
# Include something like this in /etc/logrotate.d/syslog
# 
# Crontab : 
# 20 * * * * /etc/iptables/dshield/cron.sh
#
# Make sure you process the already rotated log (e.g. kern.log.1)
#


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


