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

int hack_port_80(in_addr_t ip, int port){
	// CERT grabbing
	printf("%s", HBLUE);
	printf("\nTrying to obtain certs...\n\n");
	printf("%s",BLUE);
	curl_global_init(CURL_GLOBAL_ALL);
	char url[50]="";
	snprintf(url,sizeof(url),"%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
	cert_grabbing(url);
	// Webpages and files requests
	printf("%s", HBLUE);
	printf("\nTrying to obtain webpages and some files...\n\n");
	printf("%s",BLUE);
	Message messages[3]={{
			.descrip="",
			.msg=""}};
	snprintf(messages[0].descrip,sizeof(messages[0].descrip),"%s","\nSearching for /...\n");
	snprintf(messages[0].msg,sizeof(messages[0].msg),"%s","");
	snprintf(messages[1].descrip,sizeof(messages[1].descrip),"%s","\nSearching for robots.txt...\n");
	snprintf(messages[1].msg,sizeof(messages[1].msg),"%s","robots.txt");
	snprintf(messages[2].descrip,sizeof(messages[2].descrip),"%s","\nSearching for sitemap.xlm...\n");
	snprintf(messages[2].msg,sizeof(messages[2].msg),"%s","sitemap.xlm");
	snprintf(messages[3].descrip,sizeof(messages[3].descrip),"%s","\nSearching for crossdomain.xml...\n");
	snprintf(messages[3].msg,sizeof(messages[3].msg),"%s","crossdomain.xml");
	snprintf(messages[4].descrip,sizeof(messages[4].descrip),"%s","\nSearching for clientaccesspolicy.xml...\n");
	snprintf(messages[4].msg,sizeof(messages[4].msg),"%s","clientaccesspolicy.xml");
	snprintf(messages[5].descrip,sizeof(messages[5].descrip),"%s","\nSearching for /.well-known/...\n");
	snprintf(messages[5].msg,sizeof(messages[5].msg),"%s",".well-known/");
	CURL *mCurl = curl_easy_init();
	CURLcode res;
	if(mCurl) {
		for(int i=0;i<6;i++){
			printf("%s",HBLUE);
			printf("\n%s\n",messages[i].descrip);
			printf("%s",BLUE);
			snprintf(url,sizeof(url),"%s:%d/%s",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port,messages[i].msg);
			usleep(BRUTE_FORCE_DELAY);
			curl_easy_setopt(mCurl, CURLOPT_URL, url);
			curl_easy_setopt(mCurl, CURLOPT_TIMEOUT, 10L);
			printf("\n");
			res = curl_easy_perform(mCurl);
			printf("\n");
			curl_easy_reset(mCurl);
			if(res != CURLE_OK){
				printf("%s\n",curl_easy_strerror(res));
				return -1;
			}
		}
		curl_easy_cleanup(mCurl);
		curl_global_cleanup();
	}
	return 0;
}
