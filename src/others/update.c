
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"

static int connect_to_github(unsigned char **serverResp){
	struct hostent *he;
	struct in_addr **addrList;
	if((he=gethostbyname("api.github.com"))==NULL) return RETURN_ERROR;
	addrList=(struct in_addr **) he->h_addr_list;
	if(addrList[0]==NULL) return RETURN_ERROR;
	char *msg="GET /repos/lucho-a/auditing-cybersecurity/releases/latest HTTP/1.1\r\n"
			"Host: api.github.com\r\n"
			"user-agent: auditing-cybersecurity\r\n"
			"accept: */*\r\n"
			"connection: close\r\n"
			"x-github-api-version: 2022-11-28\r\n\r\n";
	struct in_addr ip;
	ip.s_addr=inet_addr(inet_ntoa(*addrList[0]));
	int conn=0;
	if(send_msg_to_server(&conn,ip,"api.github.com",443, SSL_CONN_TYPE, msg,strlen(msg),
			serverResp, BUFFER_SIZE_8K,0)<0) return RETURN_ERROR;
	close(conn);
	return RETURN_OK;
}

static int get_latest_version_url(char *latestVersionURL){
	unsigned char *serverResp=NULL;
	if(connect_to_github(&serverResp)==RETURN_ERROR) return RETURN_ERROR;
	char *buffer="";
	if((buffer=strstr((char *) serverResp,"\"browser_download_url\":\""))!=NULL){
		for(int i=24;buffer[i]!='"';i++) latestVersionURL[i-24]=buffer[i];
		free(serverResp);
		return RETURN_OK;
	}
	free(serverResp);
	return RETURN_ERROR;
}

static int get_latest_version(char *latestVersion){
	unsigned char *serverResp=NULL;
	if(connect_to_github(&serverResp)==RETURN_ERROR) return RETURN_ERROR;
	char *buffer="";
	char *token="\"name\":\"auditing-cybersecurity-v";
	if((buffer=strstr((char *) serverResp,token))!=NULL){
		for(int i=strlen(token);buffer[i]!=' ';i++) latestVersion[i-strlen(token)]=buffer[i];
		free(serverResp);
		return RETURN_OK;
	}
	free(serverResp);
	return RETURN_ERROR;
}

int check_updates(){
	char latestVersion[BUFFER_SIZE_16B]="";
	if(get_latest_version(latestVersion)==RETURN_ERROR) return RETURN_ERROR;;
	if(strstr(latestVersion, PROGRAM_VERSION)==NULL) return FALSE;
	return TRUE;
}

