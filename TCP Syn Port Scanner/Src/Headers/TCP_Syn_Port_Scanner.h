/*
 ============================================================================
 Name        : TCP Syn Port Scanner.h
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Header file
 ============================================================================
*/

#ifndef HEADERS_TCP_SYN_PORT_SCANNER_H_
#define HEADERS_TCP_SYN_PORT_SCANNER_H_

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<errno.h>
#include<pthread.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<time.h>
#include<unistd.h>
#include<fcntl.h>
#include <curl/curl.h>
#define LIBSSH_STATIC 1
#include<libssh2.h>
#include<libssh2_sftp.h>
#include <sys/types.h>
#include <ctype.h>

#pragma GCC diagnostic ignored "-Wformat-truncation"

#define TRUE 1
#define FALSE 0
#define HRED "\e[0;91m"
#define HGREEN "\e[0;92m"
#define HBLUE "\e[0;94m"
#define HYELLOW "\e[0;93m"
#define BLUE "\e[0;34m"
#define CYAN "\e[0;36m"
#define WHITE "\e[0;37m"
#define DEFAULT "\e[0m"
#define CANT_PORTS 5000
#define PACKET_FORWARDING_LIMIT 5
#define BUFFER_RECV_MSG 10240
#define PATH_TO_RESOURCES "/home/lucho/git/TCP Syn Port Scanner/TCP Syn Port Scanner/Src/Resources/"
#define BRUTE_FORCE_DELAY 100000
#define BRUTE_FORCE_TIMEOUT 3

static const long RETURN_OK;

struct pseudo_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

typedef struct message{
	char descrip[128];
	char msg[128];
}Message;

struct in_addr dest_ip;

int hack_port_80(in_addr_t ip, int port);
int hack_port_21(in_addr_t ip, int port);
int hack_port_22(in_addr_t ip, int port);
int create_SSH_handshake_session(LIBSSH2_SESSION **session, in_addr_t ip, int port);
int hack_port_23(in_addr_t ip, int port);
int hack_port(in_addr_t ip, int port);
void cert_grabbing(char url[50]);
int open_file(char *fileName, FILE **f);
void show_error(char *errMsg);
void * receive_ack( void *ptr );
void process_packet(unsigned char* , int);
unsigned short csum(unsigned short * , int );
char * hostname_to_ip(char * );
void get_local_ip (char *);
int start_sniffer();

#endif /* HEADERS_TCP_SYN_PORT_SCANNER_H_ */
