/*
 ============================================================================
 Name        : Check_port_80.c
 Author      : L.
 Version     : 1.0.4
 Copyright   : GNU General Public License v3.0
 Description : Check Port 80
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int check_port_80(in_addr_t ip, int port){
	Message messages[5]={{
			.descrip="",
			.msg=""}};
	snprintf(messages[0].descrip,sizeof(messages[0].descrip),"%s","\nSearching for /...\n");
	snprintf(messages[0].msg,sizeof(messages[0].msg),"%s","GET / HTTP/1.1\r\n\r\n");
	snprintf(messages[1].descrip,sizeof(messages[1].descrip),"%s","\nSearching for index.html...\n");
	snprintf(messages[1].msg,sizeof(messages[1].msg),"%s","GET /index.html HTTP/1.1\r\n\r\n");
	snprintf(messages[2].descrip,sizeof(messages[2].descrip),"%s","\nSearching for default.html...\n");
	snprintf(messages[2].msg,sizeof(messages[2].msg),"%s","GET /default.html HTTP/1.1\r\n\r\\n");
	snprintf(messages[3].descrip,sizeof(messages[3].descrip),"%s","\nSearching for robots.txt...\n");
	snprintf(messages[3].msg,sizeof(messages[3].msg),"%s","GET /robots.txt HTTP/1.1\r\n\r\\n");
	snprintf(messages[4].descrip,sizeof(messages[4].descrip),"%s","\nSearching for sitemap.xlm...\n");
	snprintf(messages[4].msg,sizeof(messages[4].msg),"%s","GET /sitemap.xlm HTTP/1.1\r\n\r\\n");
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
	struct timeval timeout;
	for(int i=0;i<5;i++){
		printf("%s",HBLUE);
		printf("\n%s\n",messages[i].descrip);
		int bytesTransmm=0;
		bytesTransmm=send(sk, messages[i].msg, strlen(messages[i].msg), MSG_NOSIGNAL);
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
		memset(serverResp,'\0',sizeof(serverResp));
	}
	close(sk);
	return 0;
}
