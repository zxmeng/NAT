#!/bin/bash

VMID="4"                                 # group no.
IP="10.3.1.$(expr ${VMID})"      # public interface
#IP="10.3.1.$(expr ${VMID} \+ 200)"      # public interface
LAN="10.0.${VMID}.0"                    # private LAN network address (without subnet mask)
MASK="24"

if [ -z "${VMID}" ]; then
    echo "[Error]  Please fill in the **VM Group ID**."
    exit
fi

if [ ${UID} -ne 0 ]; then
    echo "[Error]  Please run the script as the **root** user."
    exit
fi

echo ""
echo "Setup iptables for VM Group ID = ${VMID}, Public IP = ${IP}, Internal network = ${LAN}/${MASK}"
echo ""

echo "1" >  /proc/sys/net/ipv4/ip_forward

# clear all routes
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F

# add routes for trapping packets
iptables -t filter -A FORWARD -j NFQUEUE --queue-num 0 -p tcp -s ${LAN}/${MASK} ! -d ${IP} --dport 10000:12000
iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 0 -p tcp -d ${IP} --dport 10000:12000
