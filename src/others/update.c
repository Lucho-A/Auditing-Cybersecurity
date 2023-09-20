

#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"

static int connect_to_github(char **serverResp){
	struct hostent *he;
	struct in_addr **addrList;
	if((he=gethostbyname("api.github.com"))==NULL) return RETURN_ERROR;
	addrList=(struct in_addr **) he->h_addr_list;
	if(addrList[0]==NULL) return RETURN_ERROR;
	char msg[BUFFER_SIZE_1K]="";
	snprintf(msg,sizeof(msg),"GET /repos/lucho-a/auditing-cybersecurity/releases/latest HTTP/1.1\r\n"
			"Host: api.github.com\r\n"
			"user-agent: auditing-cybersecurity\r\n"
			"accept: */*\r\n"
			"connection: close\r\n"
			"x-github-api-version: 2022-11-28\r\n\r\n");
	struct in_addr ip;
	ip.s_addr=inet_addr(inet_ntoa(*addrList[0]));
	if(send_msg_to_server(ip,"api.github.com",443, SSL_CONN_TYPE, msg, serverResp, BUFFER_SIZE_8K,0)<0) return RETURN_ERROR;
	return RETURN_OK;
}

static int get_latest_version_url(char *latestVersionURL){
	char *serverResp=NULL;
	if(connect_to_github(&serverResp)==RETURN_ERROR) return RETURN_ERROR;
	char *buffer="";
	if((buffer=strstr(serverResp,"\"browser_download_url\":\""))!=NULL){
		for(int i=24;buffer[i]!='"';i++) latestVersionURL[i-24]=buffer[i];
		free(serverResp);
		return RETURN_OK;
	}
	free(serverResp);
	return RETURN_ERROR;
}

static int get_latest_version(char *latestVersion){
	char *serverResp=NULL;
	if(connect_to_github(&serverResp)==RETURN_ERROR) return RETURN_ERROR;
	char *buffer="";
	char *token="\"name\":\"auditing-cybersecurity-v";
	if((buffer=strstr(serverResp,token))!=NULL){
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

int update(){
	int resp=check_updates();
	if(resp==RETURN_ERROR) return RETURN_ERROR;
	if(resp){
		printf("\nLastest version already installed.\n\n");
		exit(EXIT_SUCCESS);
	}
	char latestVersion[BUFFER_SIZE_32B]="";
	if(get_latest_version(latestVersion)==RETURN_ERROR) return RETURN_ERROR;;
	char latestUrl[BUFFER_SIZE_8K]="";
	if(get_latest_version_url(latestUrl)==RETURN_ERROR) return RETURN_ERROR;;
	CURL *curl;
	CURLcode res;
	curl = curl_easy_init();
	char downloadFullPath[BUFFER_SIZE_512B]="";
	snprintf(downloadFullPath,sizeof(downloadFullPath),"/usr/share/auditing-cybersecurity/auditing-cybersecurity_%s.deb",latestVersion);
	FILE *fp;
	fp=fopen(downloadFullPath,"wb");
	curl_easy_setopt (curl, CURLOPT_URL,latestUrl);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	printf("\nDownloading update (%sv%s%s): ",C_HWHITE,latestVersion,C_DEFAULT);
	fflush(stdout);
	res=curl_easy_perform(curl);
	long httpCode=0;
	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &httpCode);
	if(res!=CURLE_OK || httpCode==404){
		printf("%serror getting file",C_HRED);
		PRINT_RESET;
		PRINT_RESET;
		exit(EXIT_SUCCESS);
	}
	fclose(fp);
	curl_easy_cleanup(curl);
	printf("%sOK",C_HGREEN);
	PRINT_RESET;
	printf("\nInstalling update...\n\n");
	fflush(stdout);
	char cmd[BUFFER_SIZE_512B]="";
	snprintf(cmd, sizeof(cmd),"apt-get install %s",downloadFullPath);
	system(cmd);
	PRINT_RESET;
	printf("Removing downloaded file...");
	snprintf(cmd, sizeof(cmd),"rm -f %s",downloadFullPath);
	system(cmd);
	PRINT_RESET;
	printf("\nUpdate finished. You can see the changelog in: %swww.github.com/lucho-a/auditing-cybersecurity/releases%s\n\n",C_CYAN,C_DEFAULT);
	exit(EXIT_SUCCESS);
}

