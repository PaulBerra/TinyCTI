#!/bin/bash
# iptables rules - TinyCTI Export
# Generated: 2025-06-27T21:37:07.235656

# Drop malicious IPs
iptables -A INPUT -s 162.243.103.246 -j DROP
iptables -A FORWARD -s 162.243.103.246 -j DROP
