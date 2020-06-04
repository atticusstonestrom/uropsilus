#include <arpa/inet.h> //remove later
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#ifndef TUNNEL_GENERAL
#define TUNNEL_GENERAL

void fatal(char *message) {
	char error_message[100];
	strcpy(error_message, "[!!] Fatal Error ");
	strncat(error_message, message, 83);
	perror(error_message);
	exit(-1); }

void *ec_malloc(unsigned int size) {
	void *ptr;
	ptr=malloc(size);
	if(ptr==NULL) {
		fatal("in ec_malloc() on memory allocation"); }
	return ptr; }

ulong get_ms_time() {
	struct timespec current_time;
	clock_gettime(CLOCK_MONOTONIC, &current_time);
	return 1000*(current_time.tv_sec)+(current_time.tv_nsec/1000000); }

////////////////////////////////////////////////////////////////////////////////////////////
//careful with static here, cannot call function recursively
//warning: no error checking or sanitization; check inet_addr
#define ETHER_ADDR_LEN_ASCII 18
#ifndef ETHER_ADDR_LEN
	#define ETHER_ADDR_LEN 6
#endif

unsigned char char_to_hex(unsigned char c) {
	if('0'<=c && c<='9') { 
		return c-'0'; }
	else if('a'<=c && c<='f') { 
		return c-'a'+10; }
	else if('A'<=c && c<='F') { 
		return c-'A'+10; }
	return -1; }

unsigned char *ether_atox(unsigned char *ascii_addr) {
	static __thread unsigned char hex_addr[ETHER_ADDR_LEN];
	int i;
	for(i=0; i<ETHER_ADDR_LEN; i++) {
		hex_addr[i]=16*char_to_hex(ascii_addr[3*i])+char_to_hex(ascii_addr[3*i+1]); }
	return hex_addr; }

char *ether_xtoa(unsigned char *hex_addr) {
	static __thread unsigned char ascii_addr[ETHER_ADDR_LEN_ASCII];
	snprintf(ascii_addr, ETHER_ADDR_LEN_ASCII, "%02x:%02x:%02x:%02x:%02x:%02x",
		 hex_addr[0], hex_addr[1], hex_addr[2], hex_addr[3], hex_addr[4], hex_addr[5]);
	return ascii_addr; }
////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////
//careful with static here, cannot call function recursively
//warning: no error checking or sanitization
#define IPv4_ADDR_LEN_ASCII 16
#ifndef IPv4_ADDR_LEN
	#define IPv4_ADDR_LEN 4
#endif

unsigned char *ipv4_atox(unsigned char *ascii_addr) {
	static __thread unsigned char hex_addr[IPv4_ADDR_LEN];
	*((unsigned int *)hex_addr)=inet_addr(ascii_addr);
	return hex_addr; }

char *ipv4_xtoa(unsigned char *hex_addr) {
	static __thread char ascii_addr[IPv4_ADDR_LEN_ASCII];
	snprintf(ascii_addr, IPv4_ADDR_LEN_ASCII, "%d.%d.%d.%d",
		 hex_addr[0], hex_addr[1], hex_addr[2], hex_addr[3]);
	return ascii_addr; }
////////////////////////////////////////////////////////////////////////////////////////////

void dump(const unsigned char *data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;
	for(i=0; i<length; i++) {
		byte=data_buffer[i];
		printf("%02x ", data_buffer[i]);
    if(((i%16)==15) || (i==length-1)) {
			for(j=0; j<15-(i%16); j++) {
				printf("   "); }
			printf("| ");
			for(j=(i-(i%16)); j<=i; j++) {
				byte=data_buffer[j];
				if((byte>31) && (byte<127)) {
					printf("%c", byte); }
				else {
					printf("."); }}
			printf("\n"); }}}

#endif
