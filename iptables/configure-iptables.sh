#!/bin/bash

# Name         : configure-iptables.sh
#
# Usage        : This script should be placed in /etc/iptables/
#                This script needs to be executable and owned by root
#                e.g.
#                chmod +x restore-iptables.sh
#                chown root:root restore-iptables.sh
#
# Arguments    : None
#
# Description  : This script it used to create and manage firewall rules. 
#
# Notes        : 
#
# Created by   : Wes Young
#
# Reference    : 
#
# Created      : 03/24/2010
#
# Modified     :
#
# Version      : .96

PATH=/sbin:$PATH

# Document IP addresses
# 1.1.1.1 - host.example.com

JOHN_SMITH="1.1.1.1"

LANS="$JOHN_SMITH"
LANS_TCP="22"
LANS_UDP=""

WANS=""
WANS_TCP=""
WANS_UDP=""

DMZS=""
DMZS_TCP=""
DMZS_UDP=""

# stuff we let everything in from
TRUSTED_HOSTS=""

# Broadcasts to drop

DROP_NOLOG_SRC=""
DROP_NOLOG_DST="224.0.0.1"

echo 'Flushing Tables'
iptables -F
iptables -X
iptables -Z

echo 'Setting Default rules to DROP'
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

echo "Setting loopback interface to ACCEPT"
iptables -A INPUT -i lo -j ACCEPT

echo 'Allowing Established Traffic through'
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "Setting up inbound services filter"
iptables -N SERVICES
iptables -F SERVICES

# LAN SERVICES - TCP
for LAN in $LANS; do
 for PORT in $LANS_TCP; do
   echo "ALLOWING TCP SERVICE: $PORT for LAN: $LAN"
   iptables -A SERVICES -p tcp --dport $PORT -s $LAN -m state --state NEW -j ACCEPT
 done
done

# LAN SERVICES - UDP
for LAN in $LANS; do
 for PORT in $LANS_UDP; do
   echo "ALLOWING TCP SERVICE: $PORT for LAN: $LAN"
   iptables -A SERVICES -p udp --dport $PORT -s $LAN -m state --state NEW -j ACCEPT
 done
done

# WAN SERVICES - TCP
for WAN in $WANS; do
 for PORT in $WANS_TCP; do
   echo "ALLOWING TCP PORT: $PORT for WAN: $WAN"
   iptables -A SERVICES -p tcp --dport $PORT -s $WAN -m state --state NEW -j ACCEPT
 done
 for PORT in $WANS_UDP; do
   echo "ALLOWING UDP PORT: $PORT for WAN: $WAN"
   iptables -A SERVICES -p udp --dport $PORT -s $WAN -m state --state NEW -j ACCEPT
 done
done

# DMZ SERVICES - TCP
for DMZ in $DMZS; do
 for PORT in $DMZS_TCP; do
   echo "ALLOWING TCP SERVICE: $PORT for DMZS: $DMZ"
   iptables -A SERVICES -p tcp --dport $PORT -s $DMZ -m state --state NEW -j ACCEPT
 done
done

# DMZ SERVICES - UDP
for DMZ in $DMZS; do
 for PORT in $DMZS_UDP; do
     echo "ALLOWING UDP SERVICE: $PORT for DMZS: $DMZ"
     iptables -A SERVICES -p udp --dport $PORT -s $DMZ -m state --state NEW -j ACCEPT
 done
done

iptables -A INPUT -j SERVICES

echo 'Setting up TRUSTED HOSTS chain'
iptables -N TRUSTED_HOSTS
iptables -F TRUSTED_HOSTS

# TRUSTED HOSTS
for ADDR in $TRUSTED_HOSTS; do
 echo "ALLOWING TRUSTED HOST: $ADDR"
 iptables -A TRUSTED_HOSTS -s $ADDR -j ACCEPT
done

iptables -A INPUT -j TRUSTED_HOSTS

# Drop Broadcasts and such
echo 'Dropping stuff so with NOLOG'
for ADDR in $DROP_NOLOG_DST; do
 echo "Dropping: $ADDR"
 iptables -A INPUT -d $ADDR -j DROP
done

echo 'log what we are about to drop'
iptables -A INPUT -j LOG --log-level 6 --log-prefix '[IPTABLES] dropped '

# Save config to /etc/iptables/iptables.active so it can be loaded
# at reboot
echo 'Saving to /etc/iptables/iptables.active'
/sbin/iptables-save > /etc/iptables/iptables.active

exit