/*
 * networking.h
 *
 *  Created on: 14 sep. 2023
 *      Author: luch-l
 */

#ifndef OTHERS_NETWORKING_H_
#define OTHERS_NETWORKING_H_

#include <netinet/tcp.h>
#include <netinet/in.h>

enum portStatuses{
	PORT_FILTERED=0,
	PORT_OPENED,
	PORT_CLOSED
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
	int portNumber;
	int portStatus;
	char serviceName[50];
	char operatingSystem[50];
	int connectionType;
};

struct ServerTarget{
	struct in_addr targetIp;
	char strTargetIp[50];
	char strTargetURL[50];
	char strHostname[50];
	int cantPortsToScan;
	struct Port *portsToScan;
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
};

int init_networking();
void ip_to_hostname(char *, char *);
char* hostname_to_ip(char *);
unsigned short csum(unsigned short *,int);
int send_msg_to_server(struct in_addr , char *, int , int , char *, char **, long int, long int);
int send_payloaded_msg_to_server(int *, char *, char *, int );
int get_port_index(int);
void show_opened_ports();
int create_socket_conn(int *socketConn);
int update();
int check_updates();

#endif /* OTHERS_NETWORKING_H_ */