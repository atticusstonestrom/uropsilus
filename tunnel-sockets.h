#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include "general.h"
#include "packet-encode.h"
#include "network-structs.h"

//get_random_mac, get_random_ipv4
//ipv6
//get_default_iface

//dhcp
	//turn wifi on (bpf to turn off arp): https://tools.ietf.org/html/rfc2131
//udp ports 67/68
//attacking network protocols

//windows netbios: udp port 137
//network time protocol: udp port 123
//dns lookup: udp port 53

//bluetooth

//wifi:
//https://superuser.com/questions/1478839/why-are-there-no-wireless-switches
//maybe need device driver, like windows
//https://github.com/markqvist/WiPacket
//are 802.11 packets converted to 802.3 packets in monitor mode?
//is arp relevant for wireless networks: https://www.packetnexus.com/docs/arppoison.pdf

//raw ip sockets
//get gateway in /proc/net/route
//https://stackoverflow.com/questions/33231034/whats-the-meaning-of-proc-net-rotue-columns-especially-flags-column
//https://stackoverflow.com/questions/3288065/getting-gateway-to-use-for-a-given-ip-in-ansi-c
//https://unix.stackexchange.com/questions/204260/where-is-routing-table-stored-internally-in-the-linux-kernel
//https://en.wikipedia.org/wiki/Lule%C3%A5_algorithm
//is there gateway or subnet if connected to modem?
//mirai/shodan gateway iot public/private
//https://stackoverflow.com/questions/51409776/how-did-a-computer-knows-where-to-send-the-packet-to-only-with-an-ip-not-mac

//functions to modify route table
	//https://stackoverflow.com/questions/6358431/can-i-read-write-the-routing-table-in-c-without-using-system-command
	//ioctl routes
	//https://stackoverflow.com/questions/548105/default-gateway-in-c-on-linux
//same for iptables?


/*
https://unix.stackexchange.com/questions/232944/device-vs-network-interface-ip-addresses
interface vs device
https://stackoverflow.com/questions/22011725/what-is-interface-in-socket-programming
https://stackoverflow.com/questions/55397673/send-packets-from-a-specific-interface-in-c
https://stackoverflow.com/questions/26278882/manually-specify-which-network-interface-to-send-data
what interface does a socket send from
https://stackoverflow.com/questions/4297356/how-does-a-socket-know-which-network-interface-controller-to-use
https://codingrelic.geekhold.com/2009/10/code-snippet-sobindtodevice.html
which interface does a raw socket listen on
https://stackoverflow.com/questions/13082023/raw-socket-listener*/

//in open_socket should turn the interface *off* promiscuous mode
//https://www.oreilly.com/library/view/linux-device-drivers/0596005903/ch17.html
//SIOCSIFFLAGS, shut down
//https://stackoverflow.com/questions/41678219/how-to-properly-put-network-interface-into-promiscuous-mode-on-linux
//is mreq multicast?
//what is an interface index

//can we use write()? maybe if we bind?

#ifndef RAW_SOCKS
#define RAW_SOCKS

////////////////////////////////////////////////////////////////////////////////////
//sockets
int open_socket() {
	int sockfd;
	if((sockfd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))==-1) {
		fatal("opening socket"); }
	return sockfd; }

void close_socket(int sockfd) {
	close(sockfd); }

//need to handle errors here, maybe use recvfrom() or read()?
int recv_frame(int sockfd, uchar *buffer, uint buffer_len, int flags) {
	return recv(sockfd, buffer, buffer_len, flags); }

int send_frame(int sockfd, int if_index, uchar *packet, uint packet_len) {
	int bytes_written;
	struct sockaddr_ll sall;
	memset(&sall, 0x00, sizeof(sall));
	sall.sll_family=PF_PACKET;
	sall.sll_ifindex=if_index;
	sall.sll_halen=ETHER_ADDR_LEN;
	memcpy(sall.sll_addr, packet+ETHER_ADDR_LEN, ETHER_ADDR_LEN);
	
	if((bytes_written=sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&sall, sizeof(sall)))==-1) {
		close(sockfd);
		fatal("sending frame"); }
	return bytes_written; }

void set_sock_promisc(int sockfd, int if_index)  {
	struct packet_mreq mr;
	memset(&mr, 0x00, sizeof(mr));
	mr.mr_ifindex=if_index;
	mr.mr_type=PACKET_MR_PROMISC;
	if(setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr))==-1) {
		close(sockfd);
		fatal("setting socket to promiscuous mode"); }}

void bind_sock_to_iface(int sockfd, int if_index) {
	struct sockaddr_ll sall;
	memset(&sall, 0x00, sizeof(sall));
	sall.sll_family=PF_PACKET;
	sall.sll_ifindex=if_index;
	sall.sll_protocol=htons(ETH_P_ALL);

	if(bind(sockfd, (struct sockaddr *)&sall, sizeof(sall))==-1) {
		close(sockfd);
		fatal("binding socket to interface"); }}

void set_sock_broadcast(int sockfd, int broadcast_flag) {
	if(setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_flag, sizeof(broadcast_flag))==-1) {
		close(sockfd);
		fatal("setting broadcast socket option"); }}

void set_sock_nonblock(int sockfd) {
	int flags;
	if( (flags=fcntl(sockfd, F_GETFL))==-1 ) {
		close(sockfd);
		fatal("getting socket flags"); }
	if(fcntl(sockfd, F_SETFL, (flags | O_NONBLOCK))==-1) {
		close(sockfd);
		fatal("setting socket to nonblocking mode"); }}

//code_len is number of sock_filters in code
void set_sock_bpf(int sockfd, struct sock_filter *code, int code_len) {
	struct sock_fprog bpf = { .len = code_len, .filter = code };
	uchar buffer[ETHER_FRAME_MAX_LEN];
	int recv_flag;
	if(setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))==-1) {
		close(sockfd);
		fatal("setting bpf"); }
	//clearing socket rx buffer
	recv_flag=1;
	while(recv_flag!=-1) {
		// /dev/null standard stream here?
		recv_flag=recv_frame(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT); }}
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
//devices
short get_interface_flags(char *iface, int sockfd) { //make a print_flags function
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFFLAGS, &ifr)==-1) {
		close(sockfd);
		fatal("getting interface flags"); }
	return ifr.ifr_flags; }

int get_interface_index(char *iface, int sockfd) {
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFINDEX, &ifr)==-1) {
		close(sockfd);
		fatal("getting interface index"); }
	return ifr.ifr_ifindex; }

uchar *get_local_mac(char *iface, int sockfd) { //include iface as argument?
	static __thread uchar local_ether_addr[ETHER_ADDR_LEN];
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr)==-1) {
		close(sockfd);
		fatal("getting local mac address"); }
	memcpy(local_ether_addr, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	return local_ether_addr; }

//get_local_ipv6
uchar *get_local_ipv4(char *iface, int sockfd) {
	static __thread uchar local_ipv4_addr[IPv4_ADDR_LEN];
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFADDR, &ifr)==-1) {
		close(sockfd);
		fatal("getting local ipv4 address"); }
	//memcpy(local_ipv4_addr, &(((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr), IPv4_ADDR_LEN);
	memcpy(local_ipv4_addr, ((uchar *)&(ifr.ifr_addr))+4, IPv4_ADDR_LEN);
	return local_ipv4_addr; }

uchar *get_subnet_mask(char *iface, int sockfd) {
	static __thread uchar local_subnet_mask[IPv4_ADDR_LEN];
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFNETMASK, &ifr)==-1) {
		close(sockfd);
		fatal("getting interface subnet mask"); }
	memcpy(local_subnet_mask, ((uchar *)&(ifr.ifr_addr))+4, IPv4_ADDR_LEN);
	return local_subnet_mask; }

uchar *get_broadcast_addr(char *iface, int sockfd) {
	static __thread uchar local_broadcast_addr[IPv4_ADDR_LEN];
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	if(!(get_interface_flags(iface, sockfd) & IFF_BROADCAST)) {
		close(sockfd);
		fatal("broadcast address not valid"); }
	if(ioctl(sockfd, SIOCGIFBRDADDR, &ifr)==-1) {
		close(sockfd);
		fatal("getting interface broadcast address"); }
	memcpy(local_broadcast_addr, ((uchar *)&(ifr.ifr_addr))+4, IPv4_ADDR_LEN);
	return local_broadcast_addr; }

void set_iface_promisc(char *iface, int sockfd) {
	short if_flags=get_interface_flags(iface, sockfd);
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	ifr.ifr_flags=if_flags | IFF_PROMISC;
	if(ioctl(sockfd, SIOCSIFFLAGS, &ifr)==-1) {
		close(sockfd);
		fatal("setting interface to promiscuous mode"); }}

void set_iface_conserv(char *iface, int sockfd) {
	short if_flags=get_interface_flags(iface, sockfd);
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	ifr.ifr_flags=if_flags & ~IFF_PROMISC;
	if(ioctl(sockfd, SIOCSIFFLAGS, &ifr)==-1) {
		close(sockfd);
		fatal("setting interface off from promiscuous mode"); }}
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
//routing

//https://stackoverflow.com/questions/33231034/whats-the-meaning-of-proc-net-rotue-columns-especially-flags-column
//stores in network order
struct route_table_entry {
	char iface[IFNAMSIZ];
	uint destination;
	uint gateway;
	uint mask; };

#define MAX_TABLE_ENTRY_LEN 100
void read_table_entry(int fd, struct route_table_entry *entry) {
	char buffer[MAX_TABLE_ENTRY_LEN+1];
	char byte;
	int i, j;
	for(i=0; (read(fd, &byte, 1)==1) && (byte!='\n') && (i<sizeof(buffer)); i++) {
		buffer[i]=byte; }
	buffer[i]=0;
	memset(entry->iface, 0x00, sizeof(entry->iface));
	for(i=0; i<IFNAMSIZ && buffer[i]!='\t'; i++) {
		entry->iface[i]=buffer[i]; }
	i++;
	buffer[i+8]=0;
	entry->destination=(uint)strtoul(buffer+i, NULL, 16);
	i+=9;
	buffer[i+8]=0;
	entry->gateway=(uint)strtoul(buffer+i, NULL, 16);
	i+=9;
	j=0;
	for(;j<4;i++) {
		if(buffer[i]=='\t') {
			j++; }}
	buffer[i+8]=0;
	entry->mask=(uint)strtoul(buffer+i, NULL, 16); }
	
uchar *get_gateway_ipv4(char *interface) {
	static __thread uchar gateway_ipv4_addr[IPv4_ADDR_LEN];
	struct route_table_entry entry;
	char byte=0;
	int route_fd=open("/proc/net/route", O_RDONLY);
	
	if(route_fd==-1) {
		fatal("opening /proc/net/route"); }
	while(byte!='\n') {
		read(route_fd, &byte, 1); }
	while(read(route_fd, &byte, 1)==1) {
		if( ('a'<=byte && byte<='z') || ('A'<=byte && byte<='Z') ) {
			lseek(route_fd, -1, SEEK_CUR);
			read_table_entry(route_fd, &entry);
			if(!strcmp(entry.iface, interface) && entry.destination==0) {
				*((uint *)gateway_ipv4_addr)=entry.gateway;
				close(route_fd);
				return gateway_ipv4_addr; }}}
	close(route_fd);
	fatal("getting gateway ipv4 address");
	return NULL; }
	

uchar *get_gateway_mac(char *iface, uchar *gateway_ipv4, int timeout) {
		       //uchar *local_mac, uchar *local_ipv4) {
	static __thread uchar gateway_ether_addr[ETHER_ADDR_LEN];
	uchar request[ETHER_HDR_LEN+ARP_HDR_LEN], reply[ETHER_FRAME_MIN_LEN];
	uchar local_mac[ETHER_ADDR_LEN], local_ipv4[IPv4_ADDR_LEN];
	int sockfd, if_index;
	struct timeval to = { .tv_sec=((timeout>0) ? timeout:5), .tv_usec=0 };
	fd_set readfds;

	sockfd=open_socket();
	if_index=get_interface_index(iface, sockfd);
	bind_sock_to_iface(sockfd, if_index);
	set_sock_nonblock(sockfd);
	
	//if(gateway_ipv4==NULL)

	//if(local_mac==NULL)
	memcpy(local_mac, get_local_mac(iface, sockfd), ETHER_ADDR_LEN);
	memcpy(local_ipv4, get_local_ipv4(iface, sockfd), IPv4_ADDR_LEN);
	
	struct sock_filter bpf_code[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 5, 0x00000806 },
		{ 0x28, 0, 0, 0x00000014 },
		{ 0x15, 0, 3, 0x00000002 },
		{ 0x20, 0, 0, 0x0000001c },
		{ 0x15, 0, 1, htonl( *((uint *) gateway_ipv4) ) },
		{ 0x6, 0, 0, 0xffffffff },
		{ 0x6, 0, 0, 0x00000000 } };
	set_sock_bpf(sockfd, bpf_code, 8);

	memset(request, 0x00, sizeof(request));
	memset(reply, 0x00, sizeof(reply));
	make_arp_packet(request, ETHER_HDR_LEN+ARP_HDR_LEN,
			local_mac, "\xff\xff\xff\xff\xff\xff",
			local_mac, local_ipv4,
			"\xff\xff\xff\xff\xff\xff", gateway_ipv4,
			ARP_OP_REQUEST);
	
	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);
	send_frame(sockfd, if_index, request, ETHER_HDR_LEN+ARP_HDR_LEN);

	//account for select return of -1
	if( (select(sockfd+1, &readfds, NULL, NULL, &to))==0 ) {
		close(sockfd);
		fatal("could not resolve gateway MAC address, timeout"); }
	recv_frame(sockfd, reply, ETHER_FRAME_MIN_LEN, 0);
	memcpy(gateway_ether_addr, ((struct arp_hdr *)(reply+ETHER_HDR_LEN))->arp_src_addr_eth, ETHER_ADDR_LEN);
	return gateway_ether_addr; }
////////////////////////////////////////////////////////////////////////////////////


#endif
