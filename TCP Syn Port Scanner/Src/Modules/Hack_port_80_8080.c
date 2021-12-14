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
	printf("%s\n", buffer);
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

int hack_port_80_8080(in_addr_t ip, int port, int scanType){
	// Port banner grabbing
	printf("%s", WHITE);
	printf("\nTrying to port grabbing...\n\n");
	printf("%s",BLUE);
	port_grabbing(ip, port);
	// CERT grabbing
	printf("%s", WHITE);
	printf("\nTrying to obtain certs...\n\n");
	printf("%s",BLUE);
	curl_global_init(CURL_GLOBAL_ALL);
	char url[50]="";
	snprintf(url,sizeof(url),"%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
	cert_grabbing(url);
	// Headers grabbing
	printf("%s", WHITE);
	printf("\nTrying to obtain headers...\n\n");
	printf("%s",BLUE);
	CURL *mCurl = curl_easy_init();
	CURLcode res;
	snprintf(url,sizeof(url),"%s:%d",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
	if(mCurl) {
		curl_easy_setopt(mCurl, CURLOPT_URL, url);
		curl_easy_setopt(mCurl, CURLOPT_HEADERFUNCTION, header_callback);
		curl_easy_setopt(mCurl,CURLOPT_NOBODY ,1 );
		curl_easy_perform(mCurl);
	}
	curl_easy_reset(mCurl);
	// Test OPTIONS Method
	printf("%s", WHITE);
	printf("\nTrying to evaluate OPTIONS in the server...\n\n");
	printf("%s",BLUE);
	struct curl_slist *list=NULL;
	char hostHeader[128]="";
	snprintf(hostHeader, sizeof(hostHeader),"Host: %s",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)));
	list = curl_slist_append(list, hostHeader);
	curl_easy_setopt(mCurl, CURLOPT_URL, url);
	curl_easy_setopt(mCurl, CURLOPT_CUSTOMREQUEST, "OPTIONS");
	curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, list);
	res = curl_easy_perform(mCurl);
	if(res != CURLE_OK) printf("%s\n",curl_easy_strerror(res));
	curl_easy_reset(mCurl);
	// Evaluate Headers response
	printf("%s", WHITE);
	printf("\nTrying to evaluate Headers response...\n");
	printf("\nSending \"Host: ???\"...\n\n");
	printf("%s", BLUE);
	long httpResponseCode=0;
	snprintf(url,sizeof(url),"%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)), port);
	snprintf(hostHeader, sizeof(hostHeader),"Host: ???");
	list = curl_slist_append(list, hostHeader);
	curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(mCurl, CURLOPT_URL, url);
	res = curl_easy_perform(mCurl);
	if(res != CURLE_OK) printf("%s\n",curl_easy_strerror(res));
	curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
	printf("\n\nServer responsed with code: ");
	if(httpResponseCode==200) printf("%s", HRED);
	printf("%ld \n\n", httpResponseCode);
	printf("%s", WHITE);
	printf("\nSending \"Host: %s\" & \"Host: ???\"...\n\n", inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)));
	printf("%s", BLUE);
	snprintf(hostHeader, sizeof(hostHeader),"Host: %s", inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)));
	list = curl_slist_append(list, hostHeader);
	snprintf(hostHeader, sizeof(hostHeader),"Host: ???");
	list = curl_slist_append(list, hostHeader);
	curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(mCurl, CURLOPT_URL, url);
	curl_easy_setopt(mCurl, CURLOPT_VERBOSE, 1);
	res = curl_easy_perform(mCurl);
	if(res != CURLE_OK) printf("%s\n",curl_easy_strerror(res));
	curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
	printf("\n\nServer responsed with code: ");
	if(httpResponseCode==200) printf("%s", HRED);
	printf("%ld \n\n", httpResponseCode);
	printf("%s", WHITE);
	printf("\nSending \"Host: %s:???\"...\n\n",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)));
	printf("%s", BLUE);
	snprintf(hostHeader, sizeof(hostHeader),"Host: %s:???",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)));
	list = curl_slist_append(list, hostHeader);
	curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(mCurl, CURLOPT_URL, url);
	curl_easy_setopt(mCurl, CURLOPT_VERBOSE, 1);
	res = curl_easy_perform(mCurl);
	if(res != CURLE_OK) printf("%s\n",curl_easy_strerror(res));
	curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
	printf("\n\nServer responsed with code: ");
	if(httpResponseCode==200) printf("%s", HRED);
	printf("%ld \n\n", httpResponseCode);
	printf("%s", WHITE);
	printf("\nSending \"Host:\"...\n\n");
	printf("%s", BLUE);
	list = curl_slist_append(list, "Host;");
	curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(mCurl, CURLOPT_URL, url);
	curl_easy_setopt(mCurl, CURLOPT_VERBOSE, 1);
	res = curl_easy_perform(mCurl);
	if(res != CURLE_OK) printf("%s\n",curl_easy_strerror(res));
	curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
	printf("\n\nServer responsed with code: ");
	if(httpResponseCode==200) printf("%s", HRED);
	printf("%ld \n\n", httpResponseCode);
	printf("%s", WHITE);
	printf("\nSending \"Host: google.com\"...\n\n");
	printf("%s", BLUE);
	list = curl_slist_append(list, "Host: google.com");
	curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(mCurl, CURLOPT_URL, url);
	res = curl_easy_perform(mCurl);
	if(res != CURLE_OK) printf("%s\n",curl_easy_strerror(res));
	curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
	printf("\n\nServer responsed with code: ");
	if(httpResponseCode==200) printf("%s", HRED);
	printf("%ld \n\n", httpResponseCode);
	curl_slist_free_all(list);
	curl_easy_reset(mCurl);
	printf("\n");
	if(scanType==FOOTPRINTING_SCAN) return EXIT_SUCCESS;
	// Webpages and files requests
	printf("%s", WHITE);
	printf("\nTrying to obtain webpages and some files...\n\n");
	printf("%s",BLUE);
	FILE *f;
	double totalFiles=0, cont=0.0;
	int i=0;
	if((totalFiles=open_file("p80_HTTP_dirs_and_files.txt",&f))==-1){
		printf("fopen(%s) error: Error: %d (%s)\n", "p80_HTTP_dirs_and_files.txt", errno, strerror(errno));
		return -1;
	}
	char **files = (char**)malloc(totalFiles * sizeof(char*) + 1);
	for (i=0;i<totalFiles;i++) files[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", files[i])!=EOF) i++;
	strcpy(files[0],"");
	struct memory chunk = {0};
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
			if(res == CURLE_OK && chunk.response!=NULL){
				curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, httpResponseCode);
				if(httpResponseCode==200) printf("\n\n%s\n\n", chunk.response);
			}
			if(res != CURLE_OK){
				printf("%s\n",curl_easy_strerror(res));
				return -1;
			}
			curl_easy_reset(mCurl);
		}
		curl_easy_cleanup(mCurl);
		curl_global_cleanup();
	}
	printf("\n");
	printf("%s",DEFAULT);
	return 0;
}
