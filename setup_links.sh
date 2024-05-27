#!/bin/bash

ip netns add ns1
ip link add ns1-veth type veth peer name ns2-veth
ip link set ns1-veth netns ns1
ip netns exec ns1 ip addr add 192.168.1.1/24 dev ns1-veth
ip addr add 192.168.1.2/24 dev ns2-veth
ip netns exec ns1 ip link set dev ns1-veth up
ip link set dev ns2-veth up


# tcp replay
ip netns exec ns1 tcpreplay -i ns1-veth -t -K smallFlows.pcap 
