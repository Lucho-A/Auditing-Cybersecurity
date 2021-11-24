/*
 ============================================================================
 Name        : TCP Syn Port Scanner Functions.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Common Functions
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

static size_t wrfu(void *ptr,  size_t  size,  size_t  nmemb,  void *stream){
	(void)stream;
	(void)ptr;
	return size * nmemb;
}

int itHasHttpHeader=FALSE;

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata){
	if(strstr(buffer,"Server:")!=NULL || strstr(buffer,"SERVER:")!=NULL || strstr(buffer,"server:")!=NULL){
		printf("%s",BLUE);
		printf("Banner grabbed: ");
		printf("%s",HRED);
		printf("%s\n", buffer);
		printf("%s",BLUE);
		return nitems * size;
	}
	itHasHttpHeader=TRUE;
	return nitems * size;
}

int port_grabbing(in_addr_t ip, int port){
	itHasHttpHeader=FALSE;
	curl_global_init(CURL_GLOBAL_ALL);
	char url[50]="";
	snprintf(url,sizeof(url),"%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
	CURL *mCurl = curl_easy_init();
	int res=0;
	if(mCurl && port!=445 && port!=139) {
		curl_easy_setopt(mCurl, CURLOPT_URL, url);
		curl_easy_setopt(mCurl, CURLOPT_HEADERFUNCTION, header_callback);
		curl_easy_setopt(mCurl,CURLOPT_NOBODY ,1 );
		res = curl_easy_perform(mCurl);
		if(res != CURLE_OK) itHasHttpHeader=FALSE;
	}
	curl_easy_reset(mCurl);
	curl_easy_cleanup(mCurl);
	if(itHasHttpHeader==TRUE) return EXIT_SUCCESS;
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
	int bytesTransmm=0;
	bytesTransmm=send(sk, "\r\n", strlen("\r\n"), MSG_NOSIGNAL);
	if(bytesTransmm < 0){
		printf("\nSend message error: %s\n", strerror(errno));
		if(strstr(strerror(errno), "Broken pipe") != NULL){
			printf("Possibly the host is closing the connections. Aborting");
			return 0;
		}
	}
	do{
		FD_ZERO(&read_fd_set);
		FD_SET((unsigned int)sk, &read_fd_set);
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		select(sk+1, &read_fd_set, NULL, NULL, &timeout);
		if (!(FD_ISSET(sk, &read_fd_set))) break;
		int bytesReciv=recv(sk, serverResp, sizeof(serverResp),0);
		if(bytesReciv==0) break;
		if(bytesReciv>0){
			printf("%s",BLUE);
			printf("Banner grabbed: ");
			printf("%s",HRED);
			printf("%s\n",serverResp);
			printf("%s",BLUE);
		}
	}while(TRUE);
	close(sk);
	return itHasHttpHeader;
}

void cert_grabbing(char url[50]){
	CURL *mCurl = curl_easy_init();
	CURLcode res;
	if(mCurl) {
		curl_easy_setopt(mCurl, CURLOPT_URL, url);
		curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, wrfu);
		curl_easy_setopt(mCurl, CURLOPT_TIMEOUT, 10L);
		curl_easy_setopt(mCurl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(mCurl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(mCurl, CURLOPT_CERTINFO, 1L);
		res = curl_easy_perform(mCurl);
		if (!res) {
			struct curl_certinfo *certinfo;
			res = curl_easy_getinfo(mCurl, CURLINFO_CERTINFO, &certinfo);
			if (!res && certinfo) {
				printf("%d certs.\n", certinfo->num_of_certs);
				for(int i = 0; i < certinfo->num_of_certs; i++) {
					struct curl_slist *slist;
					for(slist = certinfo->certinfo[i]; slist; slist = slist->next) printf("%s\n", slist->data);
				}
			}else{
				printf("%s\n",curl_easy_strerror(res));
			}
		}else{
			printf("%s\n",curl_easy_strerror(res));
		}
	}
	curl_easy_cleanup(mCurl);
	return;
}

int open_file(char *fileName, FILE **f){
	char file[256]="";
	snprintf(file,sizeof(file),"%s%s", PATH_TO_RESOURCES,fileName);
	if((*f=fopen(file,"r"))==NULL){
		printf("%s",HRED);
		printf("Users and passwords file opening error\n");
		printf("%s",DEFAULT);
		return -1;
	}
	int entries=0;
	char buffer[256]="";
	while(fscanf(*f, "%s ", buffer)!=EOF) entries++;
	rewind(*f);
	return entries;
}

void show_error(char *errMsg){
	printf("%s",HRED);
	printf("%s\n", errMsg);
	printf("%s",DEFAULT);
}
