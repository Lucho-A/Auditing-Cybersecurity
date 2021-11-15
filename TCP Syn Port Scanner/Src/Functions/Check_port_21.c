/*
 ============================================================================
 Name        : Check_port_80.c
 Author      : L.
 Version     : 1.0.4
 Copyright   : GNU General Public License v3.0
 Description : Check Port 21
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int check_port_21(in_addr_t ip, int port){
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
		printf("Send message connection error. Error message: %s (%d)\n", strerror(errno),errno);
		return -1;
	}
	fd_set read_fd_set;
	FD_ZERO(&read_fd_set);
	FD_SET((unsigned int)sk, &read_fd_set);
	char serverResp[BUFFER_RECV_MSG]={'\0'};
	char message[500]="";
	struct timeval timeout;
	printf("%s",HBLUE);
	printf("\nTrying anonymous login...\n");
	printf("%s",BLUE);
	snprintf(message,sizeof(message),"\nUSER anonymous\nPASS anonymous\n");
	int bytesTransmm=0;
	bytesTransmm=send(sk, message, strlen(message), MSG_NOSIGNAL);
	if(bytesTransmm < 0) printf("Send message error: %s\n", strerror(errno));
	do{
		FD_ZERO(&read_fd_set);
		FD_SET((unsigned int)sk, &read_fd_set);
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		select(sk+1, &read_fd_set, NULL, NULL, &timeout);
		if (!(FD_ISSET(sk, &read_fd_set))) break;
		int bytesReciv=recv(sk, serverResp, sizeof(serverResp),0);
		if(bytesReciv==0) break;
		printf("%s",BLUE);
		if(bytesReciv>0) printf("\n%s\n\n",serverResp);
	}while(TRUE);
	char *logSuccess="Login successful";
	if(strstr(serverResp, logSuccess) != NULL){
		printf("%s",HRED);
		printf("******************\n");
		printf("Service Vulnerable\n");
		printf("******************\n\n");
	}
	memset(serverResp,'\0',sizeof(serverResp));
	close(sk);
	return 0;
}
