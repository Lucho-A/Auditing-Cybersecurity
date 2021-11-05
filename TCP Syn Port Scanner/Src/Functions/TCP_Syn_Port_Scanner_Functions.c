/*
 ============================================================================
 Name        : TCP Syn Port Scanner Functions.c
 Author      : L.
 Version     : 1.0.3
 Copyright   : GNU General Public License v3.0
 Description : Port Scanner in C, Ansi-style
 ============================================================================
*/

#include "TCP_Syn_Port_Scanner.h"

unsigned short csum(unsigned short *ptr,int nbytes){
	register long sum;
	unsigned short oddbyte;
	register short r;
	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	r=(short)~sum;
	return(r);
}


char* hostname_to_ip(char * hostname){
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
	if ( (he = gethostbyname( hostname ) ) == NULL){
		//herror("gethostbyname");
		return NULL;
	}
	addr_list = (struct in_addr **) he->h_addr_list;
	for(i = 0; addr_list[i] != NULL; i++){
		return inet_ntoa(*addr_list[i]) ;
	}
	return NULL;
}


void get_local_ip ( char * buffer){
	int sock = socket ( AF_INET, SOCK_DGRAM, 0);
	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;
	struct sockaddr_in serv;
	memset( &serv, 0, sizeof(serv) );
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons( dns_port );
	int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
	if(err!=0){
		printf("Error en connect\n");
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);
	if(err!=0){
		printf("Error en getsockname\n");
		exit(EXIT_FAILURE);
	}
	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
	if(p==NULL){
		printf("Error en inet_ntop\n");
		exit(EXIT_FAILURE);
	}
	close(sock);
}


