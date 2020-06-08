#include "tunnel-general.h"
#include "network-structs.h"
#include "general-packets.h"

#ifndef TUNNEL_STRUCTS
#define TUNNEL_STRUCTS


/////////////////////////
//shared variables
extern int client_flag;
extern uchar local_mac[ETHER_HDR_LEN];
extern uchar local_ipv4[IPv4_ADDR_LEN];
extern uchar gateway_mac[ETHER_HDR_LEN];
extern uchar gateway_ipv4[IPv4_ADDR_LEN];
extern uchar icmp_buffer[PACKET_MAX_LEN+ETHER_HDR_LEN];
extern uchar tcp_buffer[PACKET_MAX_LEN+ETHER_HDR_LEN];

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

#define MAX_NUM_CLIENTS 10
extern int nclients;
#define MAX_TX_RING_SIZE 64			//client tx ring
struct client_entry {
	struct client_entry *next;
	uchar address[IPv4_ADDR_LEN];
	ushort max_tunnel_payload;
	uchar tx_ring_start; 
	uchar tx_ring_end;
	uchar *tx_ring;
	uint tx_ring_lens[MAX_TX_RING_SIZE]; };
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
	union __attribute__((packed)) {
		unsigned short mtp;
		unsigned short intact_len; };
	unsigned short frag_offset;
	unsigned short frag_id;
	unsigned char nfrags;
	//unsigned char seq;
	//unsigned short rsv;
	unsigned short checksum;
	unsigned char padding[10]; }
	__attribute__((packed));

#define TOTAL_HDR_LEN (ETHER_HDR_LEN+IPv4_HDR_LEN+ICMP_HDR_LEN+TUNNEL_HDR_LEN)
/////////////////////////


/////////////////////////
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
	uint pkt_len;
	uint buf_len;
	while(client!=NULL) {
		if(*(uint *)(client->address)==*(uint *)ip_dst) {
			if(tx_ring_start==tx_ring_end) {
				break; }
			else {
				//printf("[debug] id %d\n", echo_id);
				pkt_len=client->tx_ring_lens[client->tx_ring_start];
				buf_len=TUNNEL_HDR_LEN+client->max_tunnel_payload;
				memcpy(icmp_buffer, tx_ring+tx_ring_start*buf_len, pkt_len);
				((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.id=htons(echo_id);
				((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum=0;
				((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum =
					htons(checksum(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN, len-ETHER_HDR_LEN-IPv4_HDR_LEN));
				client->tx_ring_start=(++(client->tx_ring_start)>=MAX_TX_RING_SIZE ? 0:(client->tx_ring_start));
				return pkt_len; }}
		else {
			client=client->next; }}
	return -1; }

//returns -1 if client is not found
//or if malloc for packet fails
//returns 0 on success
int push_tx_entry(uint icmp_frame_len) {
	struct client_entry *client=client_table;
	uchar *ip_dst=((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_dst_addr;
	uchar *packet;
	while(client!=NULL) {
		if(*(uint *)(client->address)==*(uint *)ip_dst) {
			if((client->tx_ring_end+1) % MAX_TX_RING_SIZE==client->tx_ring_start) {
				return -1; }
			/*if( (client->tx_ring[client->tx_ring_end].packet=malloc(icmp_frame_len))==NULL ) {
				return -1; }*/
			client->tx_ring_lens[client->tx_ring_end]=icmp_frame_len;
			memcpy(client->tx_ring+(TUNNEL_HDR_LEN+client->max_tunnel_payload)*client->tx_ring_end,
			       icmp_buffer, icmp_frame_len);
			client->tx_ring_end=(++(client->tx_ring_end)>=MAX_TX_RING_SIZE ? 0:(client->tx_ring_end));
			if(client->tx_ring_end==client->tx_ring_start) {
				client->tx_ring_start=(++(client->tx_ring_start)>=MAX_TX_RING_SIZE ? 0:(client->tx_ring_start)); }
			return 0; }
		else {
			client=client->next; }}
	return -1; }

//returns -1 on malloc error
int add_client(uchar *new_addr, ushort mtp) {
	if(nclients>=MAX_NUM_CLIENTS) {
		return -1; }
	struct client_entry *new_client=(struct client_entry *)calloc(1, sizeof(struct client_entry));
	if(new_client==NULL) {
		return -1; }
	memcpy(new_client->address, new_addr, IPv4_ADDR_LEN);
	new_client->max_tunnel_payload=mtp;
	new_client->tx_ring=malloc(MAX_TX_RING_SIZE*(TUNNEL_HDR_LEN+mtp));
	if(new_client->tx_ring==NULL) {
		return -1; }
	new_client->next=client_table;
	client_table=new_client;
	return 0; }

struct client_entry *find_client(uchar *ip_addr) {
	struct client_entry *client=client_table;
	while(client!=NULL) {
		if(*(uint *)(client->address)==*(uint *)ip_addr) {
			break; }
		client=client->next; }
	return client; }

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
			free(current_client->tx_ring);
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

#endif
