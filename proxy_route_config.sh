echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
ifconfig eth0 mtu 3000 up
