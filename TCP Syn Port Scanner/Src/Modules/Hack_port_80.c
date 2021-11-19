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
	CURL *mCurlCerts = curl_easy_init();
	char url[50]="";
	snprintf(url,sizeof(url),"%s:%d/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port);
	if(mCurlCerts) {
		curl_easy_setopt(mCurlCerts, CURLOPT_URL, url);
		curl_easy_setopt(mCurlCerts, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(mCurlCerts, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(mCurlCerts, CURLOPT_CERTINFO, 1L);
		int res = curl_easy_perform(mCurlCerts);
		if (!res) {
			struct curl_certinfo *ci;
			res = curl_easy_getinfo(mCurlCerts, CURLINFO_CERTINFO, &ci);
			if (!res) {
				printf("%d certs found.\n", ci->num_of_certs);
				for(int i = 0; i < ci->num_of_certs; i++) {
					struct curl_slist *slist;
					for(slist = ci->certinfo[i]; slist; slist = slist->next)
						printf("%s\n", slist->data);
				}
			}else{
				printf("%s\n",curl_easy_strerror(res));
			}
		}else{
			printf("%s\n",curl_easy_strerror(res));
		}
		curl_easy_cleanup(mCurlCerts);
	}
	// Webpages and files requests
	printf("%s", HBLUE);
	printf("\nTrying to obtain webpages and some files...\n\n");
	printf("%s",BLUE);
	Message messages[3]={{
			.descrip="",
			.msg=""}};
	snprintf(messages[0].descrip,sizeof(messages[0].descrip),"%s","\nSearching for /...\n");
	snprintf(messages[0].msg,sizeof(messages[0].msg),"%s","");
	snprintf(messages[1].descrip,sizeof(messages[3].descrip),"%s","\nSearching for robots.txt...\n");
	snprintf(messages[1].msg,sizeof(messages[3].msg),"%s","robots.txt");
	snprintf(messages[2].descrip,sizeof(messages[4].descrip),"%s","\nSearching for sitemap.xlm...\n");
	snprintf(messages[2].msg,sizeof(messages[4].msg),"%s","sitemap.xlm");
	CURL *mCurl;
	CURLcode res;
	mCurl = curl_easy_init();
	if(mCurl) {
		for(int i=0;i<3;i++){
			printf("%s",HBLUE);
			printf("\n%s\n",messages[i].descrip);
			printf("%s",BLUE);
			snprintf(url,sizeof(url),"%s:%d/%s",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)),port,messages[i].msg);
			usleep(CURL_PERFORM_DELAY);
			curl_easy_setopt(mCurl, CURLOPT_URL, url);
			printf("\n");
			res = curl_easy_perform(mCurl);
			printf("\n");
			curl_easy_reset(mCurl);
			if(res != CURLE_OK){
				show_error("curl_easy_perform() failed");
				return -1;
			}
		}
		curl_easy_cleanup(mCurl);
	}
	return 0;
}
