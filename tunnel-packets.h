/////////////////////////
#include "general-packets.h"
#include "tunnel-structs.h"
#include "network-structs.h"
/////////////////////////


#ifndef TUNNEL_PACKETS
#define TUNNEL_PACKETS


/////////////////////////
//shared variables
extern uint private_key;
extern int client_flag;
extern ushort max_tunnel_payload;
extern uchar local_mac[ETHER_HDR_LEN];
extern uchar local_ipv4[IPv4_ADDR_LEN];
extern uchar gateway_mac[ETHER_HDR_LEN];
extern uchar gateway_ipv4[IPv4_ADDR_LEN];
extern uchar icmp_buffer[PACKET_MAX_LEN+ETHER_HDR_LEN];
extern uchar tcp_buffer[PACKET_MAX_LEN+ETHER_HDR_LEN];
extern uchar pseudo_segment[PACKET_MAX_LEN];

extern uchar pkt_src[IPv4_ADDR_LEN];

extern int frag_flag;
/////////////////////////


/////////////////////////
//client variables
extern uchar proxy_addr[IPv4_ADDR_LEN];
/////////////////////////


/////////////////////////
//proxy variables
extern struct client_entry *current_client;
extern struct nat_entry nat_table[MAX_NUM_PORTS];
extern ushort rx_port;
extern ushort tx_port;
/////////////////////////

/////////////////////////
//functions
void encrypt(uchar *data, int data_len, uint key) {
	int i;
	//uint bits[] = { 0xff, 0xff00, 0xff0000, 0xff000000 };
	for(i=0;i<data_len;i++) {
		data[i] ^= key>>(8*(i%4)); }}

void decrypt(uchar *data, int data_len, uint key, uint offset) {
	int i;
	//uint bits[] = { 0xff, 0xff00, 0xff0000, 0xff000000 };
	for(i=0;i<data_len;i++) {
		data[i] ^= key>>(8*((i+offset)%4)); }}

void encode_tunnel_hdr(struct tunnel_hdr *tunnelh, uchar flags, ushort csum) {
	memset((void *)tunnelh, 0x00, TUNNEL_HDR_LEN);
	tunnelh->magic=htons(TUNNEL_MAGIC);
	tunnelh->flags=flags;
	tunnelh->checksum=htons(csum); }

//ip_dst set to proxy_addr on client
void make_tunnel_msg(uchar *ip_dst, uchar flags, ushort echo_id) {
	memset(icmp_buffer, 0x00, TOTAL_HDR_LEN);
	encode_eth_hdr((struct ether_hdr *)icmp_buffer, local_mac, gateway_mac, ETHER_TYPE_IPv4);
	encode_ipv4_hdr((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN),
			local_ipv4, ip_dst,
			IPv4_DEFAULT_TOS, TOTAL_HDR_LEN-ETHER_HDR_LEN, 0, 
			IPv4_FRAG_DF_MASK, IPv4_DEFAULT_TTL, IPv4_TYPE_ICMP);

	((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_type =
		(client_flag ? ICMP_TYPE_REQUEST:ICMP_TYPE_REPLY);
	((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.id=htons(echo_id);
	((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.seq=htons(0);
	
	encode_tunnel_hdr((struct tunnel_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN+ICMP_HDR_LEN), flags, 0);

	((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->checksum =
		htons(checksum(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN, TUNNEL_HDR_LEN));
	((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum =
		htons(checksum(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN, ICMP_HDR_LEN+TUNNEL_HDR_LEN)); }

void replace_mss(struct tcp_hdr *tcph) {
	/*if(4*(tcph->tcp_offset)==TCP_HDR_MIN_LEN) {
		return; }*/
	uchar *options=((uchar *)tcph)+TCP_HDR_MIN_LEN;
	uint options_len=4*(tcph->tcp_offset)-TCP_HDR_MIN_LEN;
	uchar *cursor;
	//(fails to account for tcp options)
	ushort mss=max_tunnel_payload-TUNNEL_HDR_LEN-IPv4_HDR_LEN-TCP_HDR_MIN_LEN;
	for(cursor=options; (*cursor!=0x00)&&((ulong)cursor<(ulong)options+(ulong)options_len); cursor++) {
		if(*cursor==0x02) {
			*(ushort *)(cursor+2)=(ntohs(*(ushort *)(cursor+2))>mss) ? htons(mss):*(ushort *)(cursor+2);
			break; }
		else if(*cursor==0x01) {
			continue; }
		else {
			cursor+=((int) *(cursor+1))-1; }}
	return; }

void tcp_checksum(uint tcp_frame_len) {
	memset(pseudo_segment, 0x00, PSEUDO_HDR_LEN+tcp_frame_len-ETHER_HDR_LEN-IPv4_HDR_LEN);
	((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_checksum=0;
	encode_pseudo_hdr((struct pseudo_hdr *)pseudo_segment,
			  ((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_src_addr,
			  ((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_dst_addr,
			  IPv4_TYPE_TCP, tcp_frame_len-ETHER_HDR_LEN-IPv4_HDR_LEN);
	memcpy(pseudo_segment+PSEUDO_HDR_LEN, tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN, tcp_frame_len-ETHER_HDR_LEN-IPv4_HDR_LEN);
	((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_checksum=
		htons(checksum(pseudo_segment, PSEUDO_HDR_LEN+tcp_frame_len-ETHER_HDR_LEN-IPv4_HDR_LEN)); }

//returns -1 to drop packet
int encode_tunnel_pkt(uint tcp_frame_len, uchar flags, ushort echo_id) {
	////////////////////////////////////////////
	//how to account for unwanted tcp traffic?//
	////////////////////////////////////////////
	uchar *ip_dst;
	if(client_flag) {
		ip_dst=proxy_addr; }
	else {
		rx_port =		//used by proxy only
			ntohs(((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_dst_port);
		if(! *(uint *)(nat_table[rx_port-NAT_TABLE_OFFSET].address) ) {
			return -1; }
		else {
			tx_port=nat_table[rx_port-NAT_TABLE_OFFSET].port; 
			ip_dst=nat_table[rx_port-NAT_TABLE_OFFSET].address;
			//account for NULL ptr return here
			max_tunnel_payload=find_client(ip_dst)->max_tunnel_payload;
			//printf("[debug] ip_dst: %s\n", ipv4_xtoa(ip_dst));
			replace_mss((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN));
			((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_dst_port=htons(tx_port); }}

	frag_flag=0;
	/*if(TOTAL_HDR_LEN+tcp_frame_len-ETHER_HDR_LEN>PACKET_MAX_LEN) {
		return -1; }*/
	if(tcp_frame_len-ETHER_HDR_LEN>max_tunnel_payload) {
		frag_flag=1; }
	
	//memset(icmp_buffer, 0x00, sizeof(icmp_buffer));
	memset(icmp_buffer, 0x00, TOTAL_HDR_LEN+tcp_frame_len-ETHER_HDR_LEN);
	
	encode_eth_hdr((struct ether_hdr *)(icmp_buffer), local_mac, gateway_mac, ETHER_TYPE_IPv4);
	memcpy(icmp_buffer+ETHER_HDR_LEN, tcp_buffer+ETHER_HDR_LEN, IPv4_HDR_LEN);
	if(!client_flag) {
		memcpy(((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_src_addr, local_ipv4, IPv4_ADDR_LEN); }
	memcpy(((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_dst_addr, ip_dst, IPv4_ADDR_LEN);
	((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_len=
		htons(tcp_frame_len-ETHER_HDR_LEN+TOTAL_HDR_LEN-ETHER_HDR_LEN);
	((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_type=IPv4_TYPE_ICMP;
	((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_checksum=0;
	((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_checksum=
		htons(checksum(icmp_buffer+ETHER_HDR_LEN, IPv4_HDR_LEN));
		//(struct ipv4_hdr *)(buffer+ETHER_HDR_LEN)->ip_ttl--;

	((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_type =
		(client_flag ? ICMP_TYPE_REQUEST:ICMP_TYPE_REPLY);
	//((struct icmp_hdr *)(buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_code=0;
	//((struct icmp_hdr *)(buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_csum=htons(0);
	((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.id=htons(echo_id);
	//if(client_flag) account for resend here
	((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.seq=htons(0);

	encode_tunnel_hdr((struct tunnel_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN+ICMP_HDR_LEN), flags, 0);
	memcpy(icmp_buffer+TOTAL_HDR_LEN, tcp_buffer+ETHER_HDR_LEN, tcp_frame_len-ETHER_HDR_LEN);

	encrypt(icmp_buffer+TOTAL_HDR_LEN, tcp_frame_len-ETHER_HDR_LEN, private_key);
	((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->checksum = 
		htons(checksum(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN, TUNNEL_HDR_LEN+tcp_frame_len-ETHER_HDR_LEN));
	((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum =
		htons(checksum(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN, ICMP_HDR_LEN+TUNNEL_HDR_LEN+tcp_frame_len-ETHER_HDR_LEN));
	return TOTAL_HDR_LEN+tcp_frame_len-ETHER_HDR_LEN; }

//do checksum verification at the start of each loop recv
int verify_checksum(uint icmp_frame_len) {
	uint len=icmp_frame_len-TOTAL_HDR_LEN+TUNNEL_HDR_LEN;
	ushort csum=ntohs( ((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->checksum );
	((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->checksum=0;
	if ( csum!=checksum(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN, len) ) {
		return -1; }
	return 0; }

//returns -1 if packet too large
//or if port not found and port table full
int decode_tunnel_pkt(uint icmp_frame_len) {
	if(ETHER_HDR_LEN+icmp_frame_len-TOTAL_HDR_LEN>sizeof(tcp_buffer)) {
		return -1; }
	
	decrypt(icmp_buffer+TOTAL_HDR_LEN, icmp_frame_len-TOTAL_HDR_LEN, private_key, 0);
	rx_port =		//used by proxy only
		ntohs(((struct tcp_hdr *)(icmp_buffer+TOTAL_HDR_LEN+IPv4_HDR_LEN))->tcp_src_port);
	if(!client_flag) {
		if(port_lookup( ((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_src_addr )==-1 ) {
			return -1; }}
		
	
	memset(tcp_buffer, 0x00, ETHER_HDR_LEN+icmp_frame_len-TOTAL_HDR_LEN);
	encode_eth_hdr((struct ether_hdr *)(tcp_buffer), client_flag ? (uchar *)"\x00\x00\x00\x00\x00\x00":local_mac,
		       client_flag ? (uchar *)"\x00\x00\x00\x00\x00\x00":gateway_mac, ETHER_TYPE_IPv4);

	memcpy(tcp_buffer+ETHER_HDR_LEN, icmp_buffer+TOTAL_HDR_LEN, icmp_frame_len-TOTAL_HDR_LEN);
	
	//account for NULL ptr return here
	if(!client_flag) {
		max_tunnel_payload=
			find_client(((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_src_addr)->max_tunnel_payload; }
	replace_mss((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN));
	if(client_flag) {
		memcpy(((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_dst_addr, local_ipv4, IPv4_ADDR_LEN);
		tcp_checksum(icmp_frame_len-TOTAL_HDR_LEN+ETHER_HDR_LEN); }
	else {
		memcpy(((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_src_addr, local_ipv4, IPv4_ADDR_LEN);
		((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_src_port=htons(tx_port);
		tcp_checksum(icmp_frame_len-TOTAL_HDR_LEN+ETHER_HDR_LEN); }
	((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_checksum=0;
	((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_checksum=
		htons(checksum(tcp_buffer+ETHER_HDR_LEN, IPv4_HDR_LEN));
	
	return icmp_frame_len-TOTAL_HDR_LEN+ETHER_HDR_LEN; }
/////////////////////////


#endif
