iptables -t nat -N C2SINK 2>/dev/null || iptables -t nat -F C2SINK
ip6tables -t nat -N C2SINK 2>/dev/null || ip6tables -t nat -F C2SINK
iptables -t nat -A C2SINK -d 127.0.0.0/8 -p tcp -j REDIRECT --to-ports 8443
iptables -t nat -A C2SINK -d 203.0.113.0/24 -p tcp -j REDIRECT --to-ports 8443
iptables -t nat -A C2SINK -d 198.51.100.10/32 -p tcp -j REDIRECT --to-ports 8443
ip6tables -t nat -A C2SINK -d 2001:db8:c2::/48 -p tcp -j REDIRECT --to-ports 8443
iptables -t nat -C PREROUTING -j C2SINK 2>/dev/null || iptables -t nat -A PREROUTING -j C2SINK
ip6tables -t nat -C PREROUTING -j C2SINK 2>/dev/null || ip6tables -t nat -A PREROUTING -j C2SINK
