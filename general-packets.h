#include "tunnel-general.h"
#include "network-structs.h"

#ifndef GENERAL_PACKETS
#define GENERAL_PACKETS

void encode_eth_hdr(struct ether_hdr *, uchar *, uchar *, ushort);
void encode_pseudo_hdr(struct pseudo_hdr *, uchar *, uchar *, uchar, ushort);
void encode_ipv4_hdr(struct ipv4_hdr *, uchar *, uchar *,
		     uchar, ushort, ushort, ushort, uchar, uchar);
/*void encode_tcp_hdr(struct tcp_hdr *, ushort, ushort,
		    uint, uint, uchar, uchar, ushort,
		    ushort, uchar *);*/
void encode_arp_hdr(struct arp_hdr *, ushort,
		    uchar *, uchar *,
		    uchar *, uchar *);
/*void encode_udp_hdr(struct udp_hdr *, ushort,
		    ushort, ushort, ushort);*/
void encode_icmp_hdr(struct icmp_hdr *, uchar,
		     uchar, ushort, uchar *);

//expects network order, returns host order
ushort checksum(uchar *buffer, int nbytes) {
	uint sum;
	for(sum=0; nbytes>0; nbytes-=2) {
		if(nbytes!=1) {
			sum+=(*buffer++)<<8;
			sum+=*buffer++; }
		else { sum+=(*buffer)<<8; }} //check if this works
	sum=(sum>>16)+(sum & 0xffff);
	sum+=(sum>>16);
	return (ushort)(~sum); }

uint make_arp_packet(uchar *buffer, uint buffer_len,
		     uchar *ether_src, uchar *ether_dst,
		     uchar *arp_src_eth, uchar *arp_src_ip,
		     uchar *arp_dst_eth, uchar *arp_dst_ip, 
		     ushort op) {
	uint packet_len=ETHER_HDR_LEN+ARP_HDR_LEN;
	
	memset(buffer, 0x00, buffer_len);
	
	if(buffer_len<packet_len) {
		fatal("buffer size too small for arp packet"); }
	
	/*if(ether_src==NULL) {
		ether_src=get_mac_addr(DEFAULT_INTERFACE); }*/
	encode_eth_hdr((struct ether_hdr *)(buffer), ether_src, ether_dst, ETHER_TYPE_ARP);
	encode_arp_hdr((struct arp_hdr *)(buffer+ETHER_HDR_LEN), op, arp_src_eth, arp_src_ip, arp_dst_eth, arp_dst_ip);
	//deal with packets being too small; does kernel handle this?
	return packet_len; }

uint make_icmp_packet(uchar *buffer, uint buffer_len, 
		      uchar *ether_src, uchar *ether_dst, 
		      uchar *ip_src, uchar *ip_dst, uchar tos, ushort id, uchar ttl,
		      uchar type, uchar code, uchar *options, 
		      uchar *data, int data_len) {
	uint packet_len=ETHER_HDR_LEN+IPv4_HDR_LEN+ICMP_HDR_LEN+data_len;

	memset(buffer, 0x00, buffer_len);
	if(packet_len>PACKET_MAX_LEN) {
		fatal("requested packet too large"); }
	if(buffer_len<packet_len) {
		fatal("buffer size too small for tcp packet"); }
	
	//deal with fragmentation
	encode_eth_hdr((struct ether_hdr *)(buffer), ether_src, ether_dst, ETHER_TYPE_IPv4);
	encode_ipv4_hdr((struct ipv4_hdr *)(buffer+ETHER_HDR_LEN), ip_src, ip_dst, tos, packet_len-ETHER_HDR_LEN, id, IPv4_FRAG_DF_MASK, ttl, IPv4_TYPE_ICMP);
	encode_icmp_hdr((struct icmp_hdr *)(buffer+ETHER_HDR_LEN+IPv4_HDR_LEN), type, code, 0, options);
	if(data_len) {
		memcpy(buffer+packet_len-data_len, data, data_len); }
	((struct icmp_hdr *)(buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum =
		htons(checksum(buffer+ETHER_HDR_LEN+IPv4_HDR_LEN, ICMP_HDR_LEN+data_len));
	return packet_len; }

void encode_eth_hdr(struct ether_hdr *eh, uchar *src_addr, uchar *dst_addr, ushort type) {
	int i;
	memset((void *)eh, 0x00, ETHER_HDR_LEN);
	memcpy(eh->ether_src_addr, src_addr, ETHER_ADDR_LEN);
	memcpy(eh->ether_dst_addr, dst_addr, ETHER_ADDR_LEN);
	eh->ether_type=htons(type); }

//len is length of tcp header and data in bytes
void encode_pseudo_hdr(struct pseudo_hdr *ph, uchar *src_addr, uchar *dst_addr, uchar type, ushort len) {
	int i;
	memset((void *)ph, 0x00, PSEUDO_HDR_LEN);
	memcpy(ph->pseudo_src_addr, src_addr, IPv4_ADDR_LEN);
	memcpy(ph->pseudo_dst_addr, dst_addr, IPv4_ADDR_LEN);
	ph->pseudo_protocol=type;
	ph->pseudo_len=htons(len); }

//len is length of ip header and data in bytes
void encode_ipv4_hdr(struct ipv4_hdr *iph, uchar *src_addr, uchar *dst_addr,
		     uchar tos, ushort len, ushort id, ushort frag, uchar ttl, uchar type) {
	int i;
	memset((void *)iph, 0x00, IPv4_HDR_LEN);
	iph->ip_hdr_len=(unsigned) IPv4_HDR_LEN/4; //easy to replace with bit mask, shift left
	iph->ip_v=(unsigned) 4;
	iph->ip_tos=tos;
	iph->ip_len=htons(len);
	iph->ip_id=htons(id);
	iph->ip_frag=htons(frag);
	iph->ip_ttl=ttl;
	iph->ip_type=type;
	memcpy(iph->ip_src_addr, src_addr, IPv4_ADDR_LEN);
	memcpy(iph->ip_dst_addr, dst_addr, IPv4_ADDR_LEN);
	iph->ip_checksum=htons(checksum((uchar *)iph, IPv4_HDR_LEN)); }

//offset is size of tcp header in DWORDS
void encode_tcp_hdr(struct tcp_hdr *tcph, ushort src_port, ushort dst_port,
		    uint seq, uint ack, uchar offset, uchar flags, ushort window,
		    ushort csum, uchar *options) {
	uint header_size;
	header_size=4*((uint) offset);
	memset((void *)tcph, 0x00, header_size); //offset type, should use bitmask
	tcph->tcp_src_port=htons(src_port);
	tcph->tcp_dst_port=htons(dst_port);
	tcph->tcp_seq=htonl(seq);
	tcph->tcp_ack=htonl(ack);
	tcph->tcp_offset=offset;
	tcph->tcp_flags=flags;
	tcph->tcp_window=htons(window);
	tcph->tcp_urgent=0;
	tcph->tcp_checksum=htons(csum);
	if(header_size-TCP_HDR_MIN_LEN) {
		memcpy((uchar *)tcph+TCP_HDR_MIN_LEN, options, header_size-TCP_HDR_MIN_LEN); }} //network order is wrong here

void encode_arp_hdr(struct arp_hdr *arph, ushort op,
		    uchar *src_addr_eth, uchar *src_addr_ip,
		    uchar *dst_addr_eth, uchar *dst_addr_ip) {
	int i;
	memset((void *)arph, 0x00, ARP_HDR_LEN);
	arph->arp_hardware_type=htons(ARP_HTYPE_ETHER);
	arph->arp_hardware_len=ETHER_ADDR_LEN;
	arph->arp_protocol_type=htons(ARP_PTYPE_IPv4);
	arph->arp_protocol_len=IPv4_ADDR_LEN;
	arph->arp_op=htons(op);
	memcpy(arph->arp_src_addr_eth, src_addr_eth, ETHER_ADDR_LEN);
	memcpy(arph->arp_dst_addr_eth, dst_addr_eth, ETHER_ADDR_LEN);
	memcpy(arph->arp_src_addr_ip, src_addr_ip, IPv4_ADDR_LEN);
	memcpy(arph->arp_dst_addr_ip, dst_addr_ip, IPv4_ADDR_LEN); }

void encode_icmp_hdr(struct icmp_hdr *icmph, uchar type,
		     uchar code, ushort csum, uchar *options) {
	memset((void *)icmph, 0x00, ICMP_HDR_LEN);
	icmph->icmp_type=type;
	icmph->icmp_code=code;
	icmph->icmp_checksum=htons(csum);
	memcpy(&(icmph->icmp_options), options, 4); }

#endif
