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

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata){
	return nitems * size;
}

struct memory {
	char *response;
	size_t size;
};

static size_t callback(void *data, size_t size, size_t nmemb, void *userp){
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)userp;
	mem->response=data;
	return realsize;
}

int hack_port_80(in_addr_t ip, int port){
	// CERT grabbing
	printf("%s", HBLUE);
	printf("\nTrying to obtain certs...\n\n");
	printf("%s",BLUE);
	curl_global_init(CURL_GLOBAL_ALL);
	char url[50]="";
	snprintf(url,sizeof(url),"%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
	cert_grabbing(url);
	// Headers
	printf("%s", HBLUE);
	printf("\nTrying to obtain headers...\n\n");
	printf("%s",BLUE);
	CURL *mCurl = curl_easy_init();
	CURLcode res;
	snprintf(url,sizeof(url),"%s:%d",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
	if(mCurl) {
		curl_easy_setopt(mCurl, CURLOPT_URL, url);
		curl_easy_setopt(mCurl, CURLOPT_HEADERFUNCTION, header_callback);
		curl_easy_perform(mCurl);
	}
	// Webpages and files requests
	printf("%s", HBLUE);
	printf("\nTrying to obtain webpages and some files...\n\n");
	printf("%s",BLUE);
	FILE *f;
	double totalFiles=0, cont=0.0;
	int i=0;
	if((totalFiles=open_file("p80_HTTP_dirs_and_files.txt",&f))==-1){
		show_error("Opening p80_HTTP_files.txt file error");
		return -1;
	}
	char **files = (char**)malloc(totalFiles * sizeof(char*) + 1);
	for (i=0;i<totalFiles;i++) files[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", files[i])!=EOF) i++;
	strcpy(files[0],"");
	struct memory chunk = {0};
	curl_easy_reset(mCurl);
	if(mCurl) {
		for(i=0;i<totalFiles;i++, cont++){
			printf("\rPercentaje completed: %.4lf%% (%s)                          ",(double)((cont/totalFiles)*100.0),files[i]);
			fflush(stdout);
			usleep(BRUTE_FORCE_DELAY);
			snprintf(url,sizeof(url),"%s:%d/%s",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port,files[i]);
			usleep(BRUTE_FORCE_DELAY);
			curl_easy_setopt(mCurl, CURLOPT_URL, url);
			curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, callback);
			curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, (void *)&chunk);
			curl_easy_setopt(mCurl, CURLOPT_TIMEOUT, 10L);
			res = curl_easy_perform(mCurl);
			curl_easy_reset(mCurl);
			if(res == CURLE_OK && chunk.response!=NULL){
				if(strstr(chunk.response,"403 Forbidden")==NULL
						&& strstr(chunk.response,"404 Not Found")==NULL
						&& strstr(chunk.response,"400 Bad Request")==NULL){
					printf("\n\n%s\n\n", chunk.response);
				}
			}
			if(res != CURLE_OK){
				printf("%s\n",curl_easy_strerror(res));
				return -1;
			}
		}
		curl_easy_cleanup(mCurl);
		curl_global_cleanup();
	}
	printf("\n");
	printf("%s",DEFAULT);
	return 0;
}
