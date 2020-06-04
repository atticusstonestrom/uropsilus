ifconfig enp0s3 mtu 1500 up
iptables -D OUTPUT -o enp0s3 -t mangle -p tcp -m iprange ! --dst-range 192.168.43.0-192.168.43.255 -j MARK --set-mark 1
ip rule del fwmark 1 table tunnel.out
ip route del default via 127.0.0.1 dev lo table tunnel.out
ip route flush cache
