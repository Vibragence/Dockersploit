#!/bin/bash -e

mkdir -p /usr/local/nagios/bin
mkdir -p /usr/local/nagios/etc
sed -i "s/\s*make install-init//g" subcomponents/ndoutils/install
sed -i '/grep kernel.msg/,/sysctl -e -p/d' subcomponents/ndoutils/post-install
sed -i '/^cp.*ndo2db\.cfg \/usr\/local\/nagios\/etc/ s/$/\/ndo2db.cfg/' subcomponents/ndoutils/post-install
sed -i '/^cp.*ndomod\.cfg \/usr\/local\/nagios\/etc/ s/$/\/ndomod.cfg/' subcomponents/ndoutils/post-install
chown -R nagios:nagios /usr/local/nagios

