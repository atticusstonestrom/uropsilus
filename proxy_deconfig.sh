echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
ifconfig eth0 mtu 1500 up
