#include "tunnel-general.h"
#include "general-packets.h"
#include "tunnel-sockets.h"
#include "tunnel-structs.h"
#include "tunnel-packets.h"

#include <time.h>
#include <signal.h>

//#define MAX_PACKET_LEN 9000	//PACKET_MAX_LEN? ETHER_FRAME_MAX_LEN?

/////////////////////////
//shared variables
//cmd line
uint private_key=0xdeadbeef;
int verbose_flag=0;
int refill_timeout=100;
//ushort max_tunnel_payload=996-TUNNEL_HDR_LEN;
ushort max_tunnel_payload=900-TUNNEL_HDR_LEN;
int min_id_buffer=15;
int client_flag=0;
int gateway_flag=0;
char interface[IFNAMSIZ]="eth0";
/////////////////////////

/////////////////////////
//shared variables
uchar local_mac[ETHER_HDR_LEN];
uchar local_ipv4[IPv4_ADDR_LEN];
uchar gateway_mac[ETHER_HDR_LEN];
uchar gateway_ipv4[IPv4_ADDR_LEN];
uchar icmp_buffer[PACKET_MAX_LEN+ETHER_HDR_LEN];
uchar tcp_buffer[PACKET_MAX_LEN+ETHER_HDR_LEN];
uchar pseudo_segment[PACKET_MAX_LEN];

int if_index=-1;
int icmp_sockfd, tcp_sockfd;
fd_set readfds;

ushort pkt_flags;
ushort pkt_id;
uchar pkt_src[IPv4_ADDR_LEN];

int frag_flag;
struct frag_entry *frag_table=NULL;
uchar num_frags;
ushort current_frag_id;
ushort next_frag_id=0;
struct frag_entry *pkt_frag_entry;
ushort offset;
uint frag_len;
/////////////////////////

/////////////////////////
//client variables
uchar proxy_addr[IPv4_ADDR_LEN];
char loopback[IFNAMSIZ]="lo";
int loopback_index=-1;
ushort next_id=0;
ulong last_time;
struct timeval timeout_tv;
struct sockaddr_ll from;
socklen_t fromlen;
/////////////////////////

/////////////////////////
//proxy variables
int nports;
struct nat_entry nat_table[MAX_NUM_PORTS];

int nclients;
struct client_entry *client_table=NULL;

int queue_flag;
ushort rx_port;
ushort tx_port;
/////////////////////////


//problem 1: interface
//problem 2: proxy terminate is all wrong
//problem 3: signal does not return integer
//problem 4: ids expire :/
	//include nids in every proxy-client packet
	//client does not account for undelivered proxy msgs
	//change ring buffer structure – timestamp?
	//some things are not an issue because tcp handles them
//problem 5: easy to ddos, should encrypt checksum
//problem 6: browsh, strava.com breaks it – 65549 packet on loopback. "bad file descriptor"

void terminate(int signo) {
	struct client_entry *client=client_table;
	if(client_flag) {
		printf("closing connection to proxy\n");
		//send fin flag to proxy every five seconds
		//wait for fin-ack response
		//while(1) {
		for(int i=0; i<2; i++) {
			timeout_tv = (struct timeval) { .tv_sec=5, .tv_usec=0 };
			FD_ZERO(&readfds);
			FD_SET(icmp_sockfd, &readfds);
			make_tunnel_msg(proxy_addr, TUNNEL_FIN, next_id);
			printf("\tsending FIN packet, id %d...\n", next_id);
			next_id++;
			send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN);
			if(select(icmp_sockfd+1, &readfds, NULL, NULL, &timeout_tv)) {
				if(FD_ISSET(icmp_sockfd, &readfds)) {
					recv_frame(icmp_sockfd, icmp_buffer, sizeof(icmp_buffer), MSG_DONTWAIT);
					pkt_id=ntohs( ((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.id );
					pkt_flags=((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->flags;
					if(pkt_flags & TUNNEL_FIN) {
						printf("\treceived FIN-ACK packet, id %d\n"
						       "\tclosing connection\n", pkt_id);
						break; }}
				printf("\tno response\n"); }}}
	else if(!client_flag) {
		printf("closing client connections\n");
		while(client!=NULL) {
			//account for not having available IDs
			//wait for response?
			printf("\tsending FIN packet to %s, id %d\n", ipv4_xtoa(client->address), next_id);
			make_tunnel_msg(ipv4_xtoa(client->address), TUNNEL_FIN, next_id);
			next_id++;
			send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN);
			client=client->next; }
		free_clients(); }
	close(icmp_sockfd);
	close(tcp_sockfd);
	exit(0); }

void usage(char *);
void cmdline(int argc, char **argv);

int main(int argc, char **argv) {
	int max_sockfd, i; //select_ret
	int recv_length, send_length;
	
	cmdline(argc, argv);
	
	if(signal(SIGINT, terminate)==SIG_ERR) {
		fatal("setting termination routine"); }
	
	if(client_flag) {
		srand(time(NULL));
		next_id=rand(); }
	
	icmp_sockfd=open_socket();
	if_index=get_interface_index(interface, icmp_sockfd);
	bind_sock_to_iface(icmp_sockfd, if_index);
	set_sock_nonblock(icmp_sockfd);
	
	tcp_sockfd=open_socket();
	if(client_flag) {
		loopback_index=get_interface_index(loopback, tcp_sockfd); }
	bind_sock_to_iface( tcp_sockfd, (client_flag ? loopback_index:if_index) );
	set_sock_nonblock(tcp_sockfd);
	
	memcpy(local_mac, get_local_mac(interface, icmp_sockfd), ETHER_ADDR_LEN);
	memcpy(local_ipv4, get_local_ipv4(interface, icmp_sockfd), IPv4_ADDR_LEN);
	
	//use raw ip sockets!!
	if(!gateway_flag) {
		memcpy(gateway_ipv4, get_gateway_ipv4(interface), IPv4_ADDR_LEN); }
	memcpy(gateway_mac, get_gateway_mac(interface, gateway_ipv4, 0), ETHER_ADDR_LEN);
	
	if(verbose_flag) {
		printf("local ip address:\t%s\n", ipv4_xtoa(local_ipv4));
		printf("local mac address:\t%s\n", ether_xtoa(local_mac));
		printf("gateway ip address:\t%s\n", ipv4_xtoa(gateway_ipv4));
		printf("gateway mac address:\t%s\n", ether_xtoa(gateway_mac)); }

	struct sock_filter icmp_bpf_code[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 7, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 5, 0x00000001 },
		{ 0x30, 0, 0, 0x00000022 },
		{ 0x15, 0, 3, client_flag ? ICMP_TYPE_REPLY:ICMP_TYPE_REQUEST },
		{ 0x28, 0, 0, 0x0000002a },
		{ 0x15, 0, 1, TUNNEL_MAGIC },
		{ 0x06, 0, 0, 0xffffffff },
		{ 0x06, 0, 0, 0x00000000 } };
	set_sock_bpf(icmp_sockfd, icmp_bpf_code, 10);
	
	struct sock_filter client_tcp_bpf_code[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 5, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 3, 0x00000006 },
		{ 0x20, 0, 0, 0x00000020 },
		{ 0x15, 1, 0, ntohs(*(uint *)local_ipv4) },
		{ 0x06, 0, 0, 0xffffffff },
		{ 0x06, 0, 0, 0x00000000 } };
	struct sock_filter proxy_tcp_bpf_code[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 9, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 7, 0x00000006 },
		{ 0x20, 0, 0, 0x0000001a },
		{ 0x15, 5, 0, ntohs(*(uint *)local_ipv4) },
		{ 0x28, 0, 0, 0x00000024 },
		{ 0x25, 0, 3, (NAT_TABLE_OFFSET-1) },
		{ 0x28, 0, 0, 0x00000024 },
		{ 0x35, 1, 0, (NAT_TABLE_OFFSET+MAX_NUM_PORTS+1) },
		{ 0x6, 0, 0, 0xffffffff },
		{ 0x6, 0, 0, 0x00000000 } };			
	set_sock_bpf(tcp_sockfd, (client_flag ? client_tcp_bpf_code:proxy_tcp_bpf_code), (client_flag ? 8:12));

	
	memset(icmp_buffer, 0x00, sizeof(icmp_buffer));
	memset(tcp_buffer, 0x00, sizeof(tcp_buffer));

	if(client_flag) {
		printf("connecting to proxy %s...\n", ipv4_xtoa(proxy_addr)); 
		while(1) {
			timeout_tv = (struct timeval) { .tv_sec=5, .tv_usec=0 };
			FD_ZERO(&readfds);
			FD_SET(icmp_sockfd, &readfds);
			make_tunnel_msg(proxy_addr, TUNNEL_SYN, next_id);
			printf("\tsending SYN packet, id %d...\n", next_id);
			next_id++;
			send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN);
			//nids++;		this is the problem and why we should use ACK
			if(select(icmp_sockfd+1, &readfds, NULL, NULL, &timeout_tv)) {
				if(FD_ISSET(icmp_sockfd, &readfds)) {
					recv_frame(icmp_sockfd, icmp_buffer, sizeof(icmp_buffer), MSG_DONTWAIT);
					pkt_id=ntohs( ((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.id );
					pkt_flags=((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->flags;
					if(pkt_flags & TUNNEL_SYN) {
						printf("\treceived SYN-ACK, id %d\n", pkt_id);
						break; }
					else if(pkt_flags & TUNNEL_FIN) {
						printf("\treceived FIN, id %d\n", pkt_id);
						close(icmp_sockfd);
						close(tcp_sockfd);
						exit(0); }}
				printf("\tno response\n"); }}}
	else if(!client_flag) {
		memset(nat_table, 0x00, sizeof(nat_table));
		printf("listening on interface %s\n", interface); }

	max_sockfd=(icmp_sockfd>=tcp_sockfd) ? icmp_sockfd:tcp_sockfd;
	if(client_flag) {
		timeout_tv = (struct timeval) { .tv_sec=refill_timeout/1000, .tv_usec=1000*(refill_timeout%1000) }; }
	FD_ZERO(&readfds);
	FD_SET(icmp_sockfd, &readfds);
	FD_SET(tcp_sockfd, &readfds);
	last_time=get_ms_time();
	while( select(max_sockfd+1, &readfds, NULL, NULL, client_flag ? &timeout_tv:NULL) != -1) {

		if(client_flag) {
			timeout_tv = (struct timeval) { .tv_sec=refill_timeout/1000, .tv_usec=1000*(refill_timeout%1000) };
			if(get_ms_time()>last_time+refill_timeout) {
				last_time=get_ms_time();
				if(verbose_flag) {
					printf("sending MRE packet to proxy, id %d\n", next_id); }
				make_tunnel_msg(proxy_addr, TUNNEL_MRE, next_id);
				send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN);
				next_id++; }}

		if(FD_ISSET(icmp_sockfd, &readfds)) {
			recv_length=recv_frame(icmp_sockfd, icmp_buffer, sizeof(icmp_buffer), MSG_DONTWAIT);
			pkt_flags=((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->flags;
			memcpy(pkt_src, ((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_src_addr, IPv4_ADDR_LEN);
			pkt_id=ntohs(((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.id);
			
			if(verbose_flag) {
				printf("received %d bytes icmp from %s, id %d...\n", recv_length, ipv4_xtoa(pkt_src), pkt_id); }
			if(verify_checksum(recv_length)!=-1) {
				if(client_flag) {
					//printf("[debug] id %d\n", pkt_id);
					if(pkt_flags & TUNNEL_FIN) {
						printf("connection terminated by proxy\n");
						break; }
					else if(pkt_flags & TUNNEL_FRG) {
						current_frag_id=ntohs(((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->frag_id);
						offset=ntohs(((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->frag_offset);
						if(verbose_flag) {
							printf("\tFRG packet, frag id %d\n", current_frag_id); }
						if(find_frag(current_frag_id, &pkt_frag_entry)==-1) {
							///////////////////////////////////////////////////////////
							//next address
							//memset((void *)pkt_frag_entry, 0x00, sizeof(struct frag_entry));
							///////////////////////////////////////////////////////////
							pkt_frag_entry->id=current_frag_id;
							//memcpy(pkt_frag_entry->ip_src, "\x00\x00\x00\x00", IPv4_ADDR_LEN);
							//better error handling here
							pkt_frag_entry->intact_len=ntohs(((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->intact_len);
							pkt_frag_entry->packet=ec_malloc(pkt_frag_entry->intact_len); 
							memset(pkt_frag_entry->packet, 0x00, pkt_frag_entry->intact_len);
							if(verbose_flag) {
								printf("\tinitialized new fragment table entry, intact length %d\n", pkt_frag_entry->intact_len); }}
						if(!offset) {
							num_frags=((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->nfrags;
							pkt_frag_entry->nfrags_left+=num_frags-1;
							decode_tunnel_pkt(recv_length);
							memcpy(pkt_frag_entry->packet, tcp_buffer, recv_length-TOTAL_HDR_LEN+ETHER_HDR_LEN);
							if(verbose_flag) {
								printf("\tdecoded %d byte fragment header\n", recv_length-TOTAL_HDR_LEN+ETHER_HDR_LEN);
								printf("\tsending %d MRE packets\n", num_frags-1); }
							for(i=0; i<num_frags-1; i++) {
								make_tunnel_msg(proxy_addr, TUNNEL_MRE, 0);
								next_id++;
								send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN); }}
						else if(offset) {
							pkt_frag_entry->nfrags_left--;
							decrypt(icmp_buffer+TOTAL_HDR_LEN, recv_length-TOTAL_HDR_LEN, private_key, offset);
							memcpy(pkt_frag_entry->packet+ETHER_HDR_LEN+offset, icmp_buffer+TOTAL_HDR_LEN, recv_length-TOTAL_HDR_LEN);
							if(verbose_flag) {
								printf("\tadded %d bytes at fragment offset %d\n", recv_length-TOTAL_HDR_LEN, offset); }}
						if(pkt_frag_entry->nfrags_left==0) {
							memcpy(tcp_buffer, pkt_frag_entry->packet, pkt_frag_entry->intact_len);
							tcp_checksum(pkt_frag_entry->intact_len);
							if(verbose_flag) {
								printf("\tno remaining fragments\n"
								       "\tforwarding %d bytes to port %d\n",
								       pkt_frag_entry->intact_len,
								       ntohs( ((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_dst_port )); }
							send_frame(tcp_sockfd, loopback_index, tcp_buffer, pkt_frag_entry->intact_len);
							free_frag_entry(pkt_frag_entry); }
						else {
							if(verbose_flag) {
								printf("\twaiting on %d additional fragments\n", pkt_frag_entry->nfrags_left); }}}

					else if(pkt_flags & TUNNEL_PSH) { 
						if(verbose_flag) {
							printf("\tPSH packet...\n"); }
						send_length=decode_tunnel_pkt(recv_length);
						send_frame(tcp_sockfd, loopback_index, tcp_buffer, send_length);
						if(verbose_flag) {
							printf("\tforwarded %d bytes to port %d\n", send_length,
							       ntohs( ((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_dst_port )); }}}

				else if(!client_flag) {
					if(pkt_flags & TUNNEL_SYN) {
						printf("\tconnection request\n");
						if(add_client(pkt_src)!=-1) {
							make_tunnel_msg(pkt_src, TUNNEL_ACK|TUNNEL_SYN, pkt_id);
							printf("\tadded client, returning SYN-ACK, ");
							send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN);
							printf("id %d\n", pkt_id); }
						else {
							printf("\tunable to connect, returning FIN, \n");
							make_tunnel_msg(pkt_src, TUNNEL_FIN, pkt_id);
							send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN);
							printf("id %d\n", pkt_id); }}
					else if(pkt_flags & TUNNEL_MRE) {
						if(verbose_flag) {
							printf("\tMRE packet\n"); }
						if((send_length=pop_tx_entry(pkt_src, pkt_id))!=-1) {
							if(verbose_flag) {
								printf("\tsending %d bytes icmp, id %d\n", send_length, pkt_id); }
							send_frame(icmp_sockfd, if_index, icmp_buffer, send_length); }}
					else if(pkt_flags & TUNNEL_FIN) {
						printf("\tFIN packet, returning FIN-ACK, ");
						make_tunnel_msg(pkt_src, TUNNEL_FIN|TUNNEL_ACK, pkt_id);
						send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN);
						printf("id %d...\n", pkt_id);
						printf("\tdeleting client\n");
						del_client(pkt_src); }
					else if(pkt_flags & TUNNEL_FRG) {
						current_frag_id=ntohs(((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->frag_id);
						offset=ntohs(((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->frag_offset);
						if(verbose_flag) {
							printf("\tFRG packet, frag id %d\n", current_frag_id); }
						if(find_frag(current_frag_id, &pkt_frag_entry)==-1) {
							///////////////////////////////////////////////////////////
							//next address
							//memset((void *)pkt_frag_entry, 0x00, sizeof(struct frag_entry));
							///////////////////////////////////////////////////////////
							pkt_frag_entry->id=current_frag_id;
							memcpy(pkt_frag_entry->ip_src, pkt_src, IPv4_ADDR_LEN);
							//better error handling here
							pkt_frag_entry->intact_len=ntohs(((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->intact_len);
							pkt_frag_entry->packet=ec_malloc(pkt_frag_entry->intact_len); 
							memset(pkt_frag_entry->packet, 0x00, pkt_frag_entry->intact_len);
							if(verbose_flag) {
								printf("\tinitialized new fragment table entry, intact length %d\n", pkt_frag_entry->intact_len); }}
						if(!offset) {
							pkt_frag_entry->nfrags_left+=((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->nfrags-1;
							decode_tunnel_pkt(recv_length);
							memcpy(pkt_frag_entry->packet, tcp_buffer, recv_length-TOTAL_HDR_LEN+ETHER_HDR_LEN);
							if(verbose_flag) {
								printf("\tdecoded %d byte fragment header\n", recv_length-TOTAL_HDR_LEN+ETHER_HDR_LEN);
								printf("\tclient sent from port %d\n", rx_port); }}
							//send nfrags-1 MRE packets, nids++,
							/*for(i=0; i<((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->nfrags-1; i++) {
								make_tunnel_msg(proxy_addr, TUNNEL_MRE);
								send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN);
								nids++; }} //messes up icmp buffer, that's okay*/
						else if(offset) {
							pkt_frag_entry->nfrags_left--;
							decrypt(icmp_buffer+TOTAL_HDR_LEN, recv_length-TOTAL_HDR_LEN, private_key, offset);
							memcpy(pkt_frag_entry->packet+ETHER_HDR_LEN+offset, icmp_buffer+TOTAL_HDR_LEN, recv_length-TOTAL_HDR_LEN);
							if(verbose_flag) {
								printf("\tadded %d bytes at fragment offset %d\n", recv_length-TOTAL_HDR_LEN, offset); }}
						if(pkt_frag_entry->nfrags_left==0) {
							memcpy(tcp_buffer, pkt_frag_entry->packet, pkt_frag_entry->intact_len);
							tcp_checksum(pkt_frag_entry->intact_len);
							if(verbose_flag) {
								printf("\tno remaining fragments\n"
								       "\tforwarding %d bytes to %s from port %d\n",
								       pkt_frag_entry->intact_len,
								       ipv4_xtoa( ((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_dst_addr ),
								       tx_port); }
							send_frame(tcp_sockfd, if_index, tcp_buffer, pkt_frag_entry->intact_len);
							free_frag_entry(pkt_frag_entry); }
						else {
							if(verbose_flag) {
								printf("\twaiting on %d additional fragments\n", pkt_frag_entry->nfrags_left); }}
						if((send_length=pop_tx_entry(pkt_src, pkt_id))!=-1) {
							if(verbose_flag) {
								printf("\tsending %d bytes icmp, id %d\n", send_length, pkt_id); }
							send_frame(icmp_sockfd, if_index, icmp_buffer, send_length); }}
					
					else if(pkt_flags & TUNNEL_PSH) {
						if(verbose_flag) {
							printf("\tPSH packet...\n"
							       "\tadding id %d\n", pkt_id); }
						
						send_length=decode_tunnel_pkt(recv_length);
						if(send_length!=-1) {
							if(verbose_flag) {
								printf("\tclient sent from port %d\n", rx_port); }
							send_frame(tcp_sockfd, if_index, tcp_buffer, send_length);
							if(verbose_flag) {
								printf("\tforwarded to %s from port %d\n", 
									   ipv4_xtoa( ((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_dst_addr ), 
									   tx_port); }}
						else {
							if(verbose_flag) {
								printf("\terror decoding packet, discarded\n"); }}
						if((send_length=pop_tx_entry(pkt_src, pkt_id))!=-1) {
							if(verbose_flag) {
								printf("\tsending %d bytes icmp, id %d\n", send_length, pkt_id); }
							send_frame(icmp_sockfd, if_index, icmp_buffer, send_length); }}}}
			else if(verbose_flag) {
				printf("\twrong checksum, discarded packet\n"); }}
			

		if(FD_ISSET(tcp_sockfd, &readfds)) {
			//recv_length=recv_frame(tcp_sockfd, tcp_buffer, sizeof(tcp_buffer), 0);
			recv_length=recvfrom(tcp_sockfd, tcp_buffer, sizeof(tcp_buffer), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
			memcpy(pkt_src, ((struct ipv4_hdr *)(tcp_buffer+ETHER_HDR_LEN))->ip_src_addr, IPv4_ADDR_LEN);
			
			/*if(verbose_flag) {
				printf("received %d bytes tcp from %s...\n", recv_length, ipv4_xtoa(pkt_src));
				printf("\tsource port: %d, destination port: %d...\n", 
				       ntohs(((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_src_port),
				       ntohs(((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_dst_port)); }*/
			//https://stackoverflow.com/questions/17194844/packetsocket-opened-on-loopback-device-receives-all-the-packets-twice-how-to-fi
			if(client_flag && from.sll_pkttype==PACKET_OUTGOING) {
				if(verbose_flag) {
					printf("received %d bytes tcp on loopback\n", recv_length);
					printf("\tsource port: %d, destination port: %d...\n", 
					       ntohs(((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_src_port),
					       ntohs(((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_dst_port)); }
				if((send_length=encode_tunnel_pkt(recv_length, TUNNEL_PSH, next_id))!=-1) {
					if(!frag_flag) {
						if(verbose_flag) {
							printf("\tsending %d bytes icmp to proxy, id %d\n", send_length, next_id); }
						send_frame(icmp_sockfd, if_index, icmp_buffer, send_length);
						next_id++; }
					else if(frag_flag) {
						num_frags=(send_length-TOTAL_HDR_LEN+(max_tunnel_payload-1))/max_tunnel_payload;
						if(verbose_flag) {
							printf("\tfragmentation required, %d fragments\n", num_frags);
							printf("\tsending with frag id %d\n", next_frag_id); }
						((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->flags=TUNNEL_FRG;
						((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->frag_id=htons(next_frag_id++);
						((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->nfrags=num_frags;
						((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->intact_len=htons(recv_length);
						offset=0;
						while(offset+TOTAL_HDR_LEN<send_length) {
							((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->frag_offset=htons(offset);
							frag_len=(send_length-TOTAL_HDR_LEN-offset>max_tunnel_payload) ? \
								 max_tunnel_payload:(send_length-TOTAL_HDR_LEN-offset);
							((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_len=
								htons(TOTAL_HDR_LEN-ETHER_HDR_LEN+frag_len);
							((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_checksum=0;
							((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_checksum=
								htons(checksum(icmp_buffer+ETHER_HDR_LEN, IPv4_HDR_LEN));
							if(offset) {
								memcpy(icmp_buffer+TOTAL_HDR_LEN, icmp_buffer+TOTAL_HDR_LEN+offset, frag_len); }
							((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->checksum=0;
							((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->checksum=
								htons(checksum(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN, TUNNEL_HDR_LEN+frag_len));
							((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_options.id=
								htons(next_id);
							((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum=0;
							((struct icmp_hdr *)(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->icmp_checksum=
								htons(checksum(icmp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN,
									       ICMP_HDR_LEN+TUNNEL_HDR_LEN+frag_len));
							send_frame(icmp_sockfd, if_index, icmp_buffer, TOTAL_HDR_LEN+frag_len);
							if(verbose_flag) {
								printf("\t\tsent frag: %d bytes, id %d\n", frag_len, next_id); }
							next_id++;
							offset+=frag_len; }}}
				else {
					if(verbose_flag) {
						printf("\tpacket dropped\n"); }}}
			else if(!client_flag) {
				if(verbose_flag) {
					printf("received %d bytes tcp from %s...\n", recv_length, ipv4_xtoa(pkt_src));
					printf("\tsource port: %d, destination port: %d...\n", 
					       ntohs(((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_src_port),
					       ntohs(((struct tcp_hdr *)(tcp_buffer+ETHER_HDR_LEN+IPv4_HDR_LEN))->tcp_dst_port)); }
				if((send_length=encode_tunnel_pkt(recv_length, TUNNEL_PSH, 0))!=-1) {
					if(frag_flag) {
						num_frags=(send_length-TOTAL_HDR_LEN+(max_tunnel_payload-1))/max_tunnel_payload;
						if(verbose_flag) {
							printf("\tfragmentation required, %d fragments\n", num_frags);
							printf("\tqueueing with frag id %d\n", next_frag_id); }
						((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->flags=TUNNEL_FRG;
						((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->frag_id=htons(next_frag_id++);
						((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->nfrags=num_frags;
						((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->intact_len=htons(recv_length);
						offset=0;
						while(offset+TOTAL_HDR_LEN<send_length) {
							((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->frag_offset=htons(offset);
							frag_len=(send_length-TOTAL_HDR_LEN-offset>max_tunnel_payload) ? \
								 max_tunnel_payload:(send_length-TOTAL_HDR_LEN-offset);
							((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_len=
								htons(TOTAL_HDR_LEN-ETHER_HDR_LEN+frag_len);
							((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_checksum=0;
							((struct ipv4_hdr *)(icmp_buffer+ETHER_HDR_LEN))->ip_checksum=
								htons(checksum(icmp_buffer+ETHER_HDR_LEN, IPv4_HDR_LEN));
							if(offset) {
								memcpy(icmp_buffer+TOTAL_HDR_LEN, icmp_buffer+TOTAL_HDR_LEN+offset, frag_len); }
							((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->checksum=0;
							((struct tunnel_hdr *)(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN))->checksum=
								htons(checksum(icmp_buffer+TOTAL_HDR_LEN-TUNNEL_HDR_LEN, TUNNEL_HDR_LEN+frag_len));
							if(verbose_flag) {
								printf("\t\tqueueing frag: %d bytes\n", frag_len); }
							push_tx_entry(TOTAL_HDR_LEN+frag_len);
							offset+=frag_len; }}
					else {
						if(verbose_flag) {
							printf("\tqueueing %d bytes\n", send_length); }
						push_tx_entry(send_length); }}
				else {
					if(verbose_flag) {
						printf("\tpacket dropped\n"); }}}}

		FD_ZERO(&readfds);
		FD_SET(icmp_sockfd, &readfds);
		FD_SET(tcp_sockfd, &readfds); }
	
	if(!client_flag) {
		free_clients(); }
	close(icmp_sockfd);
	close(tcp_sockfd); }

void usage(char *arg) {
	printf("sniffer usage:\n"
	       "\tclient:\t%s -p <proxy address> [options]\n"
	       "\tproxy:\t%s [options]\n", arg, arg);
	printf("\noptions:\n"
	       "\t-h\t\tdisplay this information\n"
	       "\t-v\t\tverbose output\n"
	       "\t-k <key>\tset private key, default is 0x%x\n"
	       "\t-g <gateway>\tgateway ip address\n"
	       "\t-i <interface>\tdevice for remote communication, default is '%s'\n"
	       "\t-m <max ping>\tmaximum allowed data in ping messsage, default is %d\n"
	       "\n"
	       "\t-t <timeout>\ttime before id refill in ms, default is %d\t[client only]\n"
	       "\t-l <loopback>\tloopback device name, default is '%s'\t\t[client only]\n"
	       "\t-p <proxy>\tipv4 address of proxy\t\t\t\t[client only]\n"
	       "\n",
	       private_key, interface, max_tunnel_payload+TUNNEL_HDR_LEN, refill_timeout, loopback);
	exit(0); }

//only catches wrong options, not stray arguments
void cmdline(int argc, char **argv) {
	char *options="k:m:g:t:l:p:i:hv?";
	int opt;
	while((opt=getopt(argc, argv, options)) != -1) {
		switch (opt) {
			case 'h':
			case '?':
			default:
				usage(argv[0]);
				break;
			case 'v':
				verbose_flag=1;
				break;
			case 't':
				refill_timeout=atoi(optarg);
				break;
			case 'k':
				private_key=atoi(optarg);
				break;
			case 'm':
				max_tunnel_payload=atoi(optarg)-TUNNEL_HDR_LEN;
				break;
			case 'g':
				gateway_flag=1;
				if(strlen(optarg)<IPv4_ADDR_LEN_ASCII) {
					memcpy(gateway_ipv4, ipv4_atox(optarg), IPv4_ADDR_LEN); }
				else {
					fatal("gateway address too long"); }
				break;
			case 'p':
				client_flag=1;
				if(strlen(optarg)<IPv4_ADDR_LEN_ASCII) {
					memcpy(proxy_addr, ipv4_atox(optarg), IPv4_ADDR_LEN); }
				else {
					fatal("proxy address too long"); }
				break;
			case 'l':
				if(strlen(optarg)<IFNAMSIZ) {
					memset(loopback, 0x00, IFNAMSIZ);
					memcpy(loopback, optarg, strlen(optarg)); }
				else {
					fatal("loopback name too long"); }
				break;
			case 'i':
				if(strlen(optarg)<IFNAMSIZ) {
					memset(interface, 0x00, IFNAMSIZ);
					memcpy(interface, optarg, strlen(optarg)); }
				else {
					fatal("interface name too long"); }
				break; }}}
