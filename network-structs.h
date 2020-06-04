#ifndef NET_STRUCTS
#define NET_STRUCTS

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

#define PACKET_MAX_LEN 65535
#define ETHER_FRAME_MIN_LEN 64
#define ETHER_FRAME_MAX_LEN 1514

#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_ARP 0x0806
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
struct ether_hdr {
	unsigned char ether_dst_addr[ETHER_ADDR_LEN];
	unsigned char ether_src_addr[ETHER_ADDR_LEN];
	unsigned short ether_type; }
	__attribute__((packed));

//get rid of bit fields
#define IPv4_ADDR_LEN 4
#define IPv4_HDR_LEN 20
#define IPv4_DEFAULT_TOS 0x10 //IPTOS_LOWDELAY
#define IPv4_DEFAULT_TTL 64
#define IPv4_TYPE_ICMP 0x01
#define IPv4_TYPE_TCP 0x06
#define IPv4_TYPE_UDP 0x11
#define IPv4_TYPE_NONE 0xff
struct ipv4_hdr {
	unsigned char ip_hdr_len:4;
	unsigned char ip_v:4;
	unsigned char ip_tos;
	unsigned short ip_len;
	unsigned short ip_id;
	unsigned short ip_frag;
#define IPv4_FRAG_OFFSET_MASK 0x1fff
#define IPv4_FRAG_DF_MASK 0x4000	//don't fragment
#define IPv4_FRAG_MF_MASK 0x2000	//more fragments
	unsigned char ip_ttl;
	unsigned char ip_type;
	unsigned short ip_checksum;
	unsigned char ip_src_addr[IPv4_ADDR_LEN];
	unsigned char ip_dst_addr[IPv4_ADDR_LEN]; }
	__attribute__((packed));

#define PSEUDO_HDR_LEN 12
struct pseudo_hdr {
	unsigned char pseudo_src_addr[IPv4_ADDR_LEN];
	unsigned char pseudo_dst_addr[IPv4_ADDR_LEN];
	unsigned char pseudo_zero;
	unsigned char pseudo_protocol;
	unsigned short pseudo_len; }
	__attribute__((packed));

#define UDP_HDR_LEN 8
struct udp_hdr {
	unsigned short udp_src_port;
	unsigned short udp_dst_port;
	unsigned short udp_len;
	unsigned short udp_checksum; }
	__attribute__((packed));

#define TCP_HDR_MIN_LEN 20
#define TCP_MAX_WINDOW 0xffff //2048?
struct tcp_hdr {
	unsigned short tcp_src_port;
	unsigned short tcp_dst_port;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	unsigned char reserved:4;
	unsigned char tcp_offset:4;
	unsigned char tcp_flags;
#define TCP_FIN	0x01
#define TCP_SYN	0x02
#define TCP_RST	0x04
#define TCP_PSH	0x08
#define TCP_ACK	0x10
#define TCP_URG	0x20
	unsigned short tcp_window;
	unsigned short tcp_checksum;
	unsigned short tcp_urgent; }
	__attribute__((packed));

#define ICMP_HDR_LEN 8	//does not include relevant internet header
#define ICMP_TYPE_REPLY 0
#define ICMP_TYPE_UNREACHABLE 3
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_REQUEST 8
struct icmp_hdr {
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short icmp_checksum;
	union __attribute__((packed)) {
		struct __attribute__((packed)) {
			unsigned char unknown[4]; };
		struct __attribute__((packed)) {
			unsigned char unused1[4]; 
			unsigned short mtu; };
		struct __attribute__((packed)) {
			unsigned char gateway[IPv4_ADDR_LEN]; }; //redirect
		struct __attribute__((packed)) {
			unsigned short id;
			unsigned short seq; }; }
		icmp_options; }
	__attribute__((packed));

#define ARP_HTYPE_ETHER 0x0001
#define ARP_PTYPE_IPv4 0x0800
#define ARP_OP_REQUEST 0x0001
#define ARP_OP_REPLY 0x0002
#define ARP_HDR_LEN 28
struct arp_hdr {
	unsigned short arp_hardware_type;
	unsigned short arp_protocol_type;
	unsigned char arp_hardware_len;
	unsigned char arp_protocol_len;
	unsigned short arp_op;
	unsigned char arp_src_addr_eth[ETHER_ADDR_LEN];
	unsigned char arp_src_addr_ip[IPv4_ADDR_LEN];
	unsigned char arp_dst_addr_eth[ETHER_ADDR_LEN];
	unsigned char arp_dst_addr_ip[IPv4_ADDR_LEN]; }
	__attribute__((packed));

#endif
