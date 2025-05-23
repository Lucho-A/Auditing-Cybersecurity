
#ifndef OTHERS_NETWORKING_H_
#define OTHERS_NETWORKING_H_

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdbool.h>

enum ifStatuses{
	IF_SELECTING_NOT_SUPPORTED=-5,
	IF_TOR
};

enum portStatuses{
	PORT_FILTERED=0,
	PORT_OPENED,
	PORT_CLOSED,
	PORT_UNKNOWN
};

enum connTypes{
	UNKNOWN_CONN_TYPE=-1,
	SOCKET_CONN_TYPE,
	SSL_CONN_TYPE,
	SSH_CONN_TYPE
};

struct PseudoHeader{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

struct Port{
	int portStatus;
	char serviceName[255];
	char operatingSystem[255];
	int connectionType;
};

struct ServerTarget{
	struct in_addr targetIp;
	char strTargetIp[255];
	char strTargetURL[255];
	char strHostname[255];
	int cantPortsToScan;
	struct Port *ports;
};

struct NetworkInfo{
	char interfaceName[255];
	char interfaceIp[20];
	char *interfaceMac;
	char interfaceMacHex[6];
	struct in_addr netMask;
	struct in_addr netBroadcast;
	u_int mask;
	u_int net;
	int internetAccess;
	char publicIp[16];
};

int init_networking();
void ip_to_hostname(char *, char *);
char* hostname_to_ip(char *);
unsigned short csum(unsigned short *,int);
int create_socket_conn(int *, struct in_addr, int);
int send_msg_to_server(int *, struct in_addr, char *, int, int, char *, long int, unsigned char **, long int,long int, bool);
int get_port_index(int);
char * get_ttl_description(int);
void show_opened_ports();
void show_filtered_ports();
int update();
int checking_updates();
int check_ollama_server_status();
void clean_ssl(SSL *);

#endif /* OTHERS_NETWORKING_H_ */
