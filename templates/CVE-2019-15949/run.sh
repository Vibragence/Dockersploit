#!/bin/bash

/sbin/service httpd start
/sbin/service mysqld start
/sbin/service crond start
/sbin/service xinetd start
/sbin/service ndo2db start
/sbin/service npcd start
/sbin/service ajaxterm start
/sbin/service nagios start
/usr/local/nagiosxi/scripts/repair_databases.sh

tail -f /usr/local/nagios/var/nagios.log

