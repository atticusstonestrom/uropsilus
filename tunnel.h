/////////////////////////
//change the fatals in the packet-encode to int returns instead,
//do appropriate error handling
#include "packet-encode.h"
#include "network-structs.h"
/////////////////////////


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
struct frag_entry {
	struct frag_entry *next;
	ushort id;
	uchar ip_src[IPv4_ADDR_LEN];
	uchar nfrags_left;
	ushort intact_len;
	uchar *packet; };
extern struct frag_entry *frag_table;
/////////////////////////


/////////////////////////
//client variables
extern uchar proxy_addr[IPv4_ADDR_LEN];
/////////////////////////


/////////////////////////
//proxy variables
extern int nports;
#define NAT_TABLE_OFFSET 50000
struct nat_entry {
	uchar address[IPv4_ADDR_LEN];
	ushort port; };
#define MAX_NUM_PORTS 50
extern struct nat_entry nat_table[MAX_NUM_PORTS];

#define MAX_NUM_CLIENTS 5
extern int nclients;
#define MAX_TX_RING_SIZE 512			//client tx ring
struct tx_ring_entry {
	uint packet_len;
	uchar *packet; };
struct client_entry {
	struct client_entry *next;
	uchar address[IPv4_ADDR_LEN];
	uchar tx_ring_start; 
	uchar tx_ring_end; 
	struct tx_ring_entry tx_ring[MAX_TX_RING_SIZE]; };
extern struct client_entry *client_table;
extern ushort rx_port;
extern ushort tx_port;
/////////////////////////


/////////////////////////
//#define TUNNEL_HDR_LEN 8
#define TUNNEL_HDR_LEN 22
#define TUNNEL_MAGIC 0xf1ea
struct tunnel_hdr {
	unsigned short magic;
	unsigned char flags;
#define TUNNEL_SYN 0x01
#define TUNNEL_ACK 0x02
#define TUNNEL_PSH 0x04
#define TUNNEL_MRE 0x08
#define TUNNEL_FIN 0x10
#define TUNNEL_FRG 0x20
	unsigned short frag_offset;
	unsigned short frag_id;
	unsigned short intact_len;
	unsigned char nfrags;
	//unsigned char seq;
	//unsigned short rsv;
	unsigned short checksum;
	unsigned char padding[10]; }
	__attribute__((packed));

#define TOTAL_HDR_LEN (ETHER_HDR_LEN+IPv4_HDR_LEN+ICMP_HDR_LEN+TUNNEL_HDR_LEN)
/////////////////////////


/////////////////////////
//data structures
int find_frag(ushort id, struct frag_entry **to_fill) {
	struct frag_entry *entry=frag_table;
	while(entry!=NULL) {
		if(client_flag) {
			if(entry->id==id) {
				*to_fill=entry;
				return 0; }}
		if(!client_flag) {
			if(entry->id==id && *(uint *)entry->ip_src==*(uint *)pkt_src) {
				*to_fill=entry;
				return 0; }}
		entry=entry->next; }
	//better error handling
	*to_fill=ec_malloc(sizeof(struct frag_entry));
	**to_fill=(struct frag_entry) {
		.next=frag_table,
		.id=0,
		.ip_src={0, 0, 0, 0},
		.nfrags_left=0,
		.intact_len=0,
		.packet=NULL };
	frag_table=*to_fill;
	memset(((uchar *)(*to_fill))+sizeof(struct frag_entry *), 0x00,
	       sizeof(struct frag_entry *)-sizeof(struct frag_entry *));
	return -1; }

void free_frag_entry(struct frag_entry *entry) {
	free(entry->packet);
	struct frag_entry *prev_entry=frag_table;
	if(entry==frag_table) {
		frag_table=entry->next; }
	else {
		while(prev_entry->next!=entry) {
			prev_entry=prev_entry->next; }}
	prev_entry->next=entry->next;
	free(entry); }

//returns -1 if client is not found
//or if client's tx_ring is empty
//returns length of tx entry on success
int pop_tx_entry(uchar *ip_dst, ushort echo_id) {
	struct client_entry *client=client_table;
	uint len;
	while(client!=NULL) {
		if(*(uint *)(client->address)==*(uint *)ip_dst) {
			if(client->tx_ring_end==client->tx_ring_start) {
				break; }
			else {
				//printf("[debug] id %d\n", echo_id);
				len=(client->tx_ring[client->tx_ring_start]).packet_len;
				memcpy(icmp_buffer, (client->tx_ring[client->tx_ring_start]).packet, len);
				free((client->tx_ring[client->tx_ring_start]).packet);
				((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.id=htons(echo_id);
				((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum=0;
				((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum =
					htons(checksum(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN, len-ETHER_HDR_LEN-IPv4_HDR_LEN));
				client->tx_ring_start=(++(client->tx_ring_start)>=MAX_TX_RING_SIZE ? 0:(client->tx_ring_start));
				return len; }}
		else {
			client=client->next; }}
	return -1; }

//returns -1 if client is not found
//or if malloc for packet fails
//returns 0 on success
int push_tx_entry(uint icmp_frame_len) {
	struct client_entry *client=client_table;
	uchar *ip_dst=((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_dst_addr;
	while(client!=NULL) {
		if(*(uint *)(client->address)==*(uint *)ip_dst) {
			if((client->tx_ring_end+1) % MAX_TX_RING_SIZE==client->tx_ring_start) {
				return -1; }
			if( (client->tx_ring[client->tx_ring_end].packet=malloc(icmp_frame_len))==NULL ) {
				return -1; }
			client->tx_ring[client->tx_ring_end].packet_len=icmp_frame_len;
			memcpy(client->tx_ring[client->tx_ring_end].packet, icmp_buffer, icmp_frame_len);
			client->tx_ring_end=(++(client->tx_ring_end)>=MAX_TX_RING_SIZE ? 0:(client->tx_ring_end));
			if(client->tx_ring_end==client->tx_ring_start) {
				client->tx_ring_start=(++(client->tx_ring_start)>=MAX_TX_RING_SIZE ? 0:(client->tx_ring_start)); }
			return 0; }
		else {
			client=client->next; }}
	return -1; }

//returns -1 on malloc error
int add_client(uchar *new_addr) {
	if(nclients>=MAX_NUM_CLIENTS) {
		return -1; }
	struct client_entry *new_client=(struct client_entry *)calloc(1, sizeof(struct client_entry));
	if(new_client==NULL) {
		return -1; }
	memcpy(new_client->address, new_addr, IPv4_ADDR_LEN);
	new_client->next=client_table;
	client_table=new_client;
	return 0; }

//need to free frags in here
void del_client(uchar *ip_addr) {
	struct client_entry *current_client=client_table;
	struct client_entry *prev_client=NULL;
	int i, j=0;
	for(i=0; i<MAX_NUM_PORTS && j<nports; i++) {
		if(*(uint *)(nat_table[i].address)) {
			if(*(uint *)(nat_table[i].address)==*(uint *)ip_addr) {
				memset(&nat_table[i], 0x00, sizeof(struct nat_entry));
				j--;
				nports--; }
			j++; }}
	while(current_client!=NULL) {
		if(*(uint *)(current_client->address)==*(uint *)ip_addr) {
			while(current_client->tx_ring_start!=current_client->tx_ring_end) {
				free((current_client->tx_ring[current_client->tx_ring_start]).packet);
				current_client->tx_ring_start=(++(current_client->tx_ring_start)>=MAX_TX_RING_SIZE ? 0:(current_client->tx_ring_start)); }
			if(current_client==client_table) {
				client_table=current_client->next; }
			else {
				prev_client->next=current_client->next; }
			free(current_client);
			return; }
		else {
			prev_client=current_client;
			current_client=current_client->next; }}}

//need to free frags in here
void free_clients() {
	struct client_entry *current_client=client_table;
	struct client_entry *next_client=NULL;
	while(current_client!=NULL) {
		while(current_client->tx_ring_start!=current_client->tx_ring_end) {
			free((current_client->tx_ring[current_client->tx_ring_start]).packet);
			current_client->tx_ring_start=(++(current_client->tx_ring_start)>=MAX_TX_RING_SIZE ? 0:(current_client->tx_ring_start)); }
		next_client=current_client->next;
		free(current_client);
		current_client=next_client; }}

//fill rx_port before call
//function fills tx_port
int port_lookup(uchar *ip_src) {
	int i, j=0;
	int first_zero = -1;
	for(i=0; i<MAX_NUM_PORTS && j<=nports; i++) {
		if(*(uint *)(nat_table[i].address)==*(uint *)ip_src) {
			j++;
			if(nat_table[i].port==rx_port) {
				tx_port=NAT_TABLE_OFFSET+i;
				return 0; }}
		else if(first_zero<0 && !*(uint *)(nat_table[i].address)) {
			first_zero=i; }}
	if(first_zero>=0) {
		memcpy(nat_table[first_zero].address, ip_src, IPv4_ADDR_LEN);
		nat_table[first_zero].port=rx_port;
		tx_port=NAT_TABLE_OFFSET+first_zero;
		nports++;
		return 0; }
	return -1; }

int delete_port(uchar *ip_src, ushort port) {
	int i;
	for(i=0; i<MAX_NUM_PORTS; i++) {
		if(*(uint *)(nat_table[i].address)==*(uint *)ip_src && nat_table[i].port==port) {
			memset(&nat_table[i], 0x00, sizeof(struct nat_entry));
			nports--;
			return 0; }}
	return -1; }
/////////////////////////


/////////////////////////
//tunnel packets
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
	frag_flag=0;
	/*if(TOTAL_HDR_LEN+tcp_frame_len-ETHER_HDR_LEN>PACKET_MAX_LEN) {
		return -1; }*/
	if(tcp_frame_len-ETHER_HDR_LEN>max_tunnel_payload) {
		frag_flag=1; }
	
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
			//printf("[debug] ip_dst: %s\n", ipv4_xtoa(ip_dst));
			replace_mss((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN));
			((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_dst_port=htons(tx_port); }}
	
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
	encode_eth_hdr((struct ether_hdr *)(tcp_buffer), client_flag ? "\x00\x00\x00\x00\x00\x00":local_mac,
		       client_flag ? "\x00\x00\x00\x00\x00\x00":gateway_mac, ETHER_TYPE_IPv4);

	memcpy(tcp_buffer+ETHER_HDR_LEN, icmp_buffer+TOTAL_HDR_LEN, icmp_frame_len-TOTAL_HDR_LEN);
	
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
