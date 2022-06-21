/*
 ============================================================================
 Name        : TCP Syn Port Scanner Functions.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Port Grabbing
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int bannerHeaderFound=FALSE;

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata){
	if(strstr(buffer,"Server:")!=NULL || strstr(buffer,"SERVER:")!=NULL || strstr(buffer,"server:")!=NULL){
		printf("%s",BLUE);
		printf("\nBanner grabbed by header: ");
		printf("%s",HRED);
		printf("%s\n", buffer);
		printf("%s",BLUE);
		bannerHeaderFound=TRUE;
		return nitems * size;
	}
	return nitems * size;
}

int port_grabbing(in_addr_t ip, int port, int type){
	printf("%s",BLUE);
	curl_global_init(CURL_GLOBAL_ALL);
	int res=0;
	char url[50]="";
	int sk=0;
	switch(type){
	case HEADER_GRABBING:
		snprintf(url,sizeof(url),"%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
		CURL *mCurl = curl_easy_init();
		if(mCurl) {
			curl_easy_setopt(mCurl, CURLOPT_URL, url);
			curl_easy_setopt(mCurl, CURLOPT_HEADERFUNCTION, header_callback);
			curl_easy_setopt(mCurl, CURLOPT_TIMEOUT, 10L);
			curl_easy_setopt(mCurl, CURLOPT_NOBODY ,1 );
			res=curl_easy_perform(mCurl);
		}
		if(res!=CURLE_OK || bannerHeaderFound==FALSE) printf("No banner grabbed by header\n");
		curl_easy_reset(mCurl);
		break;
	case SOCKET_GRABBING:
		sk=socket(AF_INET,SOCK_STREAM, 0);
		if(sk<0){
			show_error("socket() error", errno);
			exit(EXIT_FAILURE);
		}
		struct sockaddr_in serverAddress;
		serverAddress.sin_family = AF_INET;
		serverAddress.sin_port=htons(port);
		serverAddress.sin_addr.s_addr= ip;
		if(connect(sk, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0){
			show_error("connect() error", (int) errno);
			return RETURN_ERROR;
		}
		fd_set read_fd_set;
		FD_ZERO(&read_fd_set);
		FD_SET((unsigned int)sk, &read_fd_set);
		char serverResp[BUFFER_RECV_MSG]={'\0'};
		struct timeval timeout;
		int bytesTransmm=0;
		bytesTransmm=send(sk, "\r\n", strlen("\r\n"), MSG_NOSIGNAL);
		if(bytesTransmm < 0){
			show_error("send() error", errno);
			if(strstr(strerror(errno), "Broken pipe") != NULL){
				show_error("Possibly the host is closing the connections. Aborting", 0);
				return RETURN_OK;
			}
		}
		do{
			FD_ZERO(&read_fd_set);
			FD_SET((unsigned int)sk, &read_fd_set);
			timeout.tv_sec = 10;
			timeout.tv_usec = 0;
			select(sk+1, &read_fd_set, NULL, NULL, &timeout);
			if (!(FD_ISSET(sk, &read_fd_set))) {
				printf("Banner grabbed by socket query: No response (timeout)\n");
				break;
			}
			int bytesReciv=recv(sk, serverResp, sizeof(serverResp),0);
			if(bytesReciv==0){
				printf("Banner grabbed by socket query: No response\n");
				break;
			}
			if(bytesReciv<0){
				printf("Error %d: %s\n", errno, strerror(errno));;
				break;
			}
			if(bytesReciv>0){
				printf("Banner grabbed by socket query: ");
				printf("%s",HRED);
				//for(int i=0; serverResp[i]!='\n';i++) printf("%c",serverResp[i]);
				for(int i=0;i<bytesReciv;i++){
					if(isprint(serverResp[i]) || serverResp[i]=='\n') printf("%c",serverResp[i]);
				}
				printf("\n");
				printf("%s",BLUE);
				break;
			}
		}while(TRUE);
		close(sk);
		break;
	default:
		break;
	}
	return RETURN_OK;
}
