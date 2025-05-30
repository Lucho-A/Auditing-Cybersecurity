/*
 ============================================================================
 Name        : Auditing-Cybersecurity.h
 Author      : L.
 Version     : 1.0.0
 Copyright   : GNU General Public License v3.0
 Description : Header file
 ============================================================================
*/

#ifndef AUDITING_CYBERSECURITY_H_
#define AUDITING_CYBERSECURITY_H_

#include <stdio.h>
#include <pcap.h>
#include <stdbool.h>
#include <openssl/ssl.h>

#include "libs/libOCL/libOllama-C-lient.h"

// #define LIBSSH_STATIC 1

#define PROGRAM_NAME 					"Auditing-Cybersecurity"
#define PROGRAM_MAJOR_VERSION			"1"
#define PROGRAM_MINOR_VERSION			"3"
#define PROGRAM_MICRO_VERSION			"2"
#define PROGRAM_VERSION					PROGRAM_MAJOR_VERSION"."PROGRAM_MINOR_VERSION"."PROGRAM_MICRO_VERSION

#define ALL_PORTS						65536
#define MAX_PORTS_TO_SCAN	 			5001
//#define MAX_VIEW_PORTS					15
#define PACKET_FORWARDING_LIMIT 		1
#define SEND_PACKET_DELAY_US 			500000
#define SEND_PACKET_PER_PORT_DELAY_US	0
#define BRUTE_FORCE_DELAY_US 			100000
#define BRUTE_FORCE_TIMEOUT 			3
#define CURL_TIMEOUT					10L
#define SOCKET_CONNECT_TIMEOUT_S		10
#define SOCKET_RECV_TIMEOUT_S			10
#define SOCKET_SEND_TIMEOUT_S			10
#define SSH_TIMEOUT_MS					10000
#define SSL_TIMEOUT_S					10
#define SNIFFING_THREAD_DELAY_US		10000000
#define ARP_DISCOVER_TIMEOUT_S			2
#define ARP_DISCOVER_DELAY_US			30000000
#define MAX_THREADS						5000

#define	BUFFER_SIZE_16B					16
#define	BUFFER_SIZE_32B					32
#define	BUFFER_SIZE_128B				128
#define BUFFER_SIZE_256B				256
#define BUFFER_SIZE_512B				512
#define BUFFER_SIZE_1K					1024
#define BUFFER_SIZE_2K					(1024*2)
#define BUFFER_SIZE_8K					(1024*8)
#define	BUFFER_SIZE_16K					(1024*16)
#define	BUFFER_SIZE_128K				(1024*128)

#define RETURN_ERROR 					-1
#define RETURN_OK 						0
#define RETURN_CLOSE					1

#define PRINT_DEBUG_MSG 				printf("\n%sWTF???%s\n",C_HRED,C_DEFAULT);
#define PRINT_RESET 					printf("%s\n",C_DEFAULT);

#define C_HCYAN 						"\e[0;96m"
#define C_CYAN 							"\e[0;36m"
#define C_HGREEN 						"\e[0;92m"
#define C_HYELLOW 						"\e[0;93m"
#define C_HRED 							"\e[0;91m"
#define C_HWHITE 						"\e[0;97m"
#define C_WHITE 						"\e[0;37m"
#define C_HBLACK 						"\e[0;90m"
#define C_DEFAULT 						"\e[0m"
#define C_STRIKE						"\e[0;9m"

#define REMOVE_LINE						"\r\033[2K"

enum programVersion{
	UPDATED=1,
	OUT_OF_DATE=2,
	UNDER_TESTING=3
};

enum errors{
	EXIT_PROGRAM=-100,
	SOCKET_CREATION_ERROR,
	SOCKET_CONNECTION_TIMEOUT_ERROR,
	SOCKET_CONNECTION_ERROR,
	SOCKET_CONNECTION_CLOSED_ERROR,
	SOCKET_SETOPT_ERROR,
	SOCKET_SELECT_ERROR,
	SENDING_PACKETS_ERROR,
	SENDING_PACKETS_TO_ERROR,
	GETADDRINFO_ERROR,
	MALLOC_ERROR,
	REALLOC_ERROR,
	RECEIVING_PACKETS_ERROR,
	RECEIVING_PACKETS_TO_ERROR,
	ZERO_BYTES_RECV_ERROR,
	DEVICE_NOT_FOUND_ERROR,
	DEVICE_MAC_NOT_FOUND_ERROR,
	DEVICE_NOT_ETHERNET_ERROR,
	DEVICE_OPENING_ERROR,
	SSH_INIT_ERROR,
	SSH_HANDSHAKE_ERROR,
	SSH_SOCKET_DISCONNECTION_ERROR,
	SSL_CONTEXT_ERROR,
	SSL_CONNECTION_ERROR,
	SSL_FD_ERROR,
	SSL_CONNECT_ERROR,
	UNKNOW_CONNECTION_ERROR,
	POLLIN_ERROR,
	GETSOCKNAME_ERROR,
	INET_NTOP_ERROR,
	HOSTNAME_TO_IP_ERROR,
	OPENING_PORT_FILE_ERROR,
	OPENING_FILE_ERROR,
	OPENING_SETTING_FILE_ERROR,
	THREAD_CREATION_ERROR,
	FTP_CONNECTION_ERROR,
	FTP_ERROR,
	MYSQL_CONNECTION_ERROR,
	SMB_CONTEXT_CREATION_ERROR,
	OLLAMA_SERVER_UNAVAILABLE,
	SOCKS5_USERPASS_NEGOTIATION_ERROR,
	SOCKS5_CONVERTING_IP_ERROR,
	SOCKS5_CONNECTION_ERROR
};

enum msgLevels{
	ERROR_MESSAGE=-5,
	INFO_MESSAGE,
	WARNING_MESSAGE,
	CRITICAL_MESSAGE,
	RESULT_MESSAGE,
	OK_MESSAGE
};

enum activitiesTypes{
	ANY_BANNER_GRABBING=1,
	ANY_DOS_SYN_FLOOD_ATTACK,
	ANY_NMAP_VULNER_SCAN,
	ANY_CODE_RED,
	ANY_SEARCH_MSF,
	ANY_RUN_MSF,
	ANY_SEARCH_NMAP,
	ANY_RUN_NMAP,
	ANY_SQL_MAP,
	ANY_ARP_SNIFFING,
	HTTP_HEADER_BANNER_GRABBING,
	HTTP_TLS_GRABBING,
	HTTP_HEADER_GRABBING,
	HTTP_METHODS_ALLOWED_GRABBING,
	HTTP_SERVER_RESP_SPOOFED_HEADERS,
	HTTP_GET_WEBPAGES,
	HTTP_OTHERS,
	SSH_FINGER_PRINTING,
	SSH_USER_ENUM,
	SSH_BFA,
	SSH_RUN_JUNIPER_BACKDOOR,
	DNS_DIG,
	DNS_BANNER,
	DNS_ZONE_TRANSFER,
	DNS_ENUM,
	FTP_BANNER_GRABBING,
	FTP_BFA,
	FTP_ANONYMOUS,
	SMB_BANNER_GRABBING,
	SMB_ETERNAL_BLUE,
	SMB_BFA,
	MYSQL_BANNER_GRABBING,
	MYSQL_BFA,
	SMTP_BANNER_GRABBING,
	SMTP_ENUMERATION,
	SMTP_RELAY,
	SMTP_BFA,
	IMAP_BFA,
	LDAP_BFA,
	POP3_BFA,
	ORACLE_BFA,
	POSTGRES_BFA,
	MSSQL_BFA,
	MSSQL_SHELL,
	OTHERS_SHOW_OPENED_PORTS,
	OTHERS_SHOW_FILTERED_PORTS,
	OTHERS_INTERACTIVE,
	OTHERS_SYSTEM_CALL,
	OTHERS_TRACEROUTE,
	OTHERS_ARP_DISCOVER,
	OTHERS_ARP_DISCOVER_D,
	OTHERS_ARP_DISCOVER_MAC,
	OTHERS_SHOW_ACTIVIIES,
	OTHERS_WHOIS,
	OTHERS_SEARCH_CVE,
	OTHERS_EXIT
};

static const long RETURN_THREAD_OK;

struct BfaInfo{
	char **usernames;
	char **passwords;
	double totalUsernames;
	double totalPasswords;
};

struct ThreadInfo{
	int threadID;
	int totalThreads;
	int service;
};

struct LastestError{
	int errorType;
	int err;
	int sslErr;
	char errorAditionalDescription[BUFFER_SIZE_256B];
	bool blocked;
};

struct ToRInfo{
	char *ip;
	int port;
};

struct OllamaInfo{
	char *ip;
	char *port;
	char *model;
	char *numCtx;
	char *maxHistoryCtx;
	char *temp;
};

struct Settings{
	struct OllamaInfo oi;
	struct ToRInfo ti;
};

extern OCl *ocl;
extern struct Settings settings;
extern bool canceledBySignal;
extern bool cancelCurrentProcess;
extern bool discover;
extern bool sniffing;
extern struct ServerTarget target;
extern struct NetworkInfo networkInfo;
extern int portUnderHacking;
extern struct LastestError lastActivityError;
extern pcap_t *arpHandle;
extern char *resourcesLocation;
extern long int sendPacketPerPortDelayUs;
extern 	SSL_CTX *sslCtx;

int scan_init();
int scan_ports();
int hack_port_request();

int error_handling(int);
int set_last_activity_error(int, char const *);
int open_file(char *, char *, FILE **);
int open_file_str(char *, char *, FILE **, char ***);
int show_message(char *, int , int , int , bool, bool, bool);
char * get_readline(char *, bool);
int format_strings_from_files(char *, char *);
void show_intro(char *, char *);
void show_intro_banner();
void show_options();
void show_help(char *);
int system_call(char *);
int request_quantity_threads(int);
char ask_tor_service();
int read_usernames_and_password_files(struct BfaInfo *, char *, char *);
void free_char_double_pointer(char ***, size_t);

#endif /* AUDITING_CYBERSECURITY_H_ */
