#!/bin/bash
echo "Whitelisting port $1";
iptables -A OUTPUT -p tcp --sport $1 --tcp-flags RST RST -j DROP;
