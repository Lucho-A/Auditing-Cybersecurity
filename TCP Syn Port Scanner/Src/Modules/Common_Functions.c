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
				printf("%d certs found.\n", certinfo->num_of_certs);
				for(int i = 0; i < certinfo->num_of_certs; i++) {
					struct curl_slist *slist;
					for(slist = certinfo->certinfo[i]; slist; slist = slist->next)
						printf("%s\n", slist->data);
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
