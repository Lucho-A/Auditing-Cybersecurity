/*
 ============================================================================
 Name        : TCP Syn Port Scanner Functions.c
 Author      : L.
 Version     : 1.0.4
 Copyright   : GNU General Public License v3.0
 Description : Port Scanner in C, Ansi-style
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int send_msg(in_addr_t ip, int port, char **msgResp) {
	int sk=socket(AF_INET,SOCK_STREAM, 0);
	if(sk<0){
		printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port=htons(port);
	serverAddress.sin_addr.s_addr= ip;
	if(connect(sk, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0){
		printf("Send message connection error\n");
		return -1;
	}
	if(fcntl(sk, F_SETFL, fcntl(sk, F_GETFL) | O_NONBLOCK) < 0) {
		printf("fcntl (no blocking set) error\n");
		return -3;
	}
	char *message = "GET \n";
	char serverResp[1024];
	int cont=0;
	if(send(sk , message , strlen(message) , 0) < 0){
		printf("Send message error\n");
		return -2;
	}
	while(cont<3){
		recv(sk, &serverResp, sizeof(serverResp),0);
		sleep(1);
		cont++;
	}

	close(sk);
	*msgResp=serverResp;
	return 0;
}

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
	if((he = gethostbyname( hostname ) ) == NULL) return NULL;
	addr_list = (struct in_addr **) he->h_addr_list;
	for(i = 0; addr_list[i] != NULL; i++) return inet_ntoa(*addr_list[i]);
	return NULL;
}

void get_local_ip (char * buffer){
	int sk = socket (AF_INET, SOCK_DGRAM, 0);
	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;
	struct sockaddr_in serv;
	memset(&serv, 0, sizeof(serv));
	serv.sin_family=AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port=htons(dns_port);
	int resp=connect(sk,(const struct sockaddr*) &serv,sizeof(serv));
	if(resp!=0){
		printf("connect() error\n");
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	resp = getsockname(sk, (struct sockaddr*) &name, &namelen);
	if(resp!=0){
		printf("getsockname() error\n");
		exit(EXIT_FAILURE);
	}
	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
	if(p==NULL){
		printf("inet_ntop() error\n");
		exit(EXIT_FAILURE);
	}
	close(sk);
}


