/*
 ============================================================================
 Name        : Hack_Web.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : hack_web
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int itHasOptions=FALSE;

struct memory {
	char *response;
	size_t size;
};

static size_t options_callback(char *buffer, size_t size, size_t nitems, void *userdata){
	if(strstr(buffer,"Allow:")!=NULL || strstr(buffer,"ALLOW:")!=NULL || strstr(buffer,"allow:")!=NULL){
		printf("%s",BLUE);
		printf("Methods allowed found: ");
		printf("%s",HRED);
		printf("%s\n", buffer);
		printf("%s",BLUE);
		itHasOptions=TRUE;
		return nitems * size;
	}
	return nitems * size;
}

static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata){
	printf("%s\n", buffer);
	return nitems * size;
}

static size_t callback(void *data, size_t size, size_t nmemb, void *userp){
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)userp;
	mem->response=data;
	return realsize;
}

int hack_web(in_addr_t ip, int port, int type){
	char url[50]="";
	struct curl_slist *list=NULL;
	long httpResponseCode=0;
	char hostHeaders[4][128]={"Host: ???",
			"Host: anyhost.com",
			"Host:"};
	snprintf(hostHeaders[3],sizeof(hostHeaders[3]),"Host: %s:???",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)));
	struct memory chunk = {0};
	CURL *mCurl = curl_easy_init();
	CURLcode res;
	switch(type){
	case HEADER_GRABBING:
		printf("%s",BLUE);
		snprintf(url,sizeof(url),"%s:%d",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
		if(mCurl) {
			curl_easy_setopt(mCurl, CURLOPT_URL, url);
			curl_easy_setopt(mCurl, CURLOPT_HEADERFUNCTION, header_callback);
			curl_easy_setopt(mCurl,CURLOPT_NOBODY ,1 );
			curl_easy_perform(mCurl);
		}
		curl_easy_reset(mCurl);
		break;
	case METHODS_ALLOWED_GRABBING:
		printf("%s",BLUE);
		char hostHeader[128]="";
		snprintf(hostHeader, sizeof(hostHeader),"Host: %s",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)));
		list = curl_slist_append(list, hostHeader);
		curl_easy_setopt(mCurl, CURLOPT_URL, url);
		curl_easy_setopt(mCurl, CURLOPT_CUSTOMREQUEST, "OPTIONS");
		curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, list);
		curl_easy_setopt(mCurl, CURLOPT_HEADERFUNCTION, options_callback);
		curl_easy_setopt(mCurl,CURLOPT_NOBODY ,1 );
		res = curl_easy_perform(mCurl);
		if(itHasOptions==FALSE) printf("No Allowed Method founds\n");
		curl_slist_free_all(list);
		list=NULL;
		curl_easy_reset(mCurl);
		break;
	case SERVER_RESP_SPOOFED_HEADERS:
		printf("%s", BLUE);
		for(int i=0;i<4;i++){
			printf("%s", WHITE);
			printf("\nSending \"%s\"\n", hostHeaders[i]);
			printf("%s", BLUE);
			snprintf(url,sizeof(url),"%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)), port);
			list = curl_slist_append(list, hostHeaders[i]);
			curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, list);
			curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, callback);
			curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, (void *)&chunk);
			curl_easy_setopt(mCurl, CURLOPT_URL, url);
			res = curl_easy_perform(mCurl);
			if(res != CURLE_OK) printf("\n%s\n",curl_easy_strerror(res));
			curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
			printf("\nServer responsed with code: ");
			if(httpResponseCode==200 || httpResponseCode==301) printf("%s", HRED);
			printf("%ld\n", httpResponseCode);
			curl_easy_reset(mCurl);
			curl_slist_free_all(list);
			list=NULL;
		}
		break;
	case GET_WEBPAGES:
		printf("%s",BLUE);
		FILE *f;
		double totalFiles=0, cont=0.0;
		int i=0;
		if((totalFiles=open_file("dirs_and_files_HTTP.txt",&f))==-1){
			printf("fopen(%s) error: Error: %d (%s)\n", "p80_HTTP_dirs_and_files.txt", errno, strerror(errno));
			return RETURN_ERROR;
		}
		char **files = (char**)malloc(totalFiles * sizeof(char*) + 1);
		for (i=0;i<totalFiles;i++) files[i] = (char*)malloc(50 * sizeof(char));
		i=0;
		while(fscanf(f,"%s", files[i])!=EOF) i++;
		strcpy(files[0],"");
		if(mCurl) {
			for(i=0;i<totalFiles;i++, cont++){
				printf("\rPercentage completed: %.4lf%% (%s)                          ",(double)((cont/totalFiles)*100.0),files[i]);
				fflush(stdout);
				usleep(BRUTE_FORCE_DELAY);
				snprintf(url,sizeof(url),"%s:%d/%s",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port,files[i]);
				usleep(BRUTE_FORCE_DELAY);
				curl_easy_setopt(mCurl, CURLOPT_URL, url);
				curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, callback);
				curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, (void *)&chunk);
				curl_easy_setopt(mCurl, CURLOPT_TIMEOUT, 10L);
				res = curl_easy_perform(mCurl);
				if(res == CURLE_OK && chunk.response!=NULL){
					curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, httpResponseCode);
					if(httpResponseCode==200 || httpResponseCode==301) printf("\n%s\n", chunk.response);
				}
				if(res != CURLE_OK){
					printf("%s\n",curl_easy_strerror(res));
					return RETURN_ERROR;
				}
				curl_easy_reset(mCurl);
			}
		}
		break;
	default:
		break;
	}
	curl_easy_cleanup(mCurl);
	curl_global_cleanup();
	printf("%s",DEFAULT);
	return RETURN_OK;
}
