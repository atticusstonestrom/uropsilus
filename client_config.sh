ifconfig enp0s3 mtu 3000 up
echo 0 > /proc/sys/net/ipv4/ip_forward
iptables -A OUTPUT -o enp0s3 -t mangle -p tcp -m iprange ! --dst-range 192.168.43.0-192.168.43.255 -j MARK --set-mark 1
echo 201 tunnel.out >> /etc/iproute2/rt_tables
ip rule add fwmark 1 table tunnel.out
ip route add default via 127.0.0.1 dev lo table tunnel.out
ip route flush cache
