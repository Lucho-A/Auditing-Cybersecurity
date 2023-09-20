
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"

struct memory {
	char *response;
	size_t size;
};

static size_t callback(void *data, size_t size, size_t nmemb, void *userp){
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)userp;
	char *ptr = realloc(mem->response, mem->size + realsize + 1);
	if(ptr == NULL) return show_message("Out of Memory",0,0, ERROR_MESSAGE, TRUE);
	mem->response = ptr;
	memcpy(&(mem->response[mem->size]), data, realsize);
	mem->size += realsize;
	mem->response[mem->size] = 0;
	return realsize;
}

int bfa_imap_ldap_pop3_smtp_ftp(int type){
	curl_global_init(CURL_GLOBAL_ALL);
	char url[255]="", protocol[10]="", usernamesFile[255]="", passwordsFile[255]="";
	switch(type){
	case IMAP_BFA:
		snprintf(protocol,sizeof(protocol),"%s","imap");
		snprintf(usernamesFile,sizeof(usernamesFile),"%s","usernames_imap.txt");
		snprintf(passwordsFile,sizeof(passwordsFile),"%s","passwords_imap.txt");
		break;
	case LDAP_BFA:
		snprintf(protocol,sizeof(protocol),"%s","ldap");
		snprintf(usernamesFile,sizeof(usernamesFile),"%s","usernames_ldap.txt");
		snprintf(passwordsFile,sizeof(passwordsFile),"%s","passwords_ldap.txt");
		break;
	case POP3_BFA:
		snprintf(protocol,sizeof(protocol),"%s","pop3");
		snprintf(usernamesFile,sizeof(usernamesFile),"%s","usernames_pop3.txt");
		snprintf(passwordsFile,sizeof(passwordsFile),"%s","passwords_pop3.txt");
		break;
	case SMTP_BFA:
		snprintf(protocol,sizeof(protocol),"%s","smtp");
		snprintf(usernamesFile,sizeof(usernamesFile),"%s","usernames_smtp.txt");
		snprintf(passwordsFile,sizeof(passwordsFile),"%s","passwords_smtp.txt");
		break;
	default:
		break;
	}
	snprintf(url,sizeof(url),"%s://%s:%d/",protocol,target.strTargetIp, portUnderHacking);
	struct BfaInfo bfaInfo;
	double totalComb= read_usernames_and_password_files(&bfaInfo, usernamesFile, passwordsFile);
	CURL *mCurl=curl_easy_init();
	int cont=0, timeouts=0;
	CURLcode res;
	if (mCurl){
		for(int i=0;i<bfaInfo.totalUsernames && timeouts<BRUTE_FORCE_TIMEOUT && cancelCurrentProcess==FALSE;i++){
			for(int j=0;j<bfaInfo.totalPasswords && timeouts<BRUTE_FORCE_TIMEOUT && cancelCurrentProcess==FALSE;j++,cont++){
				struct memory chunk={0};
				printf("\r  Percentaje completed: %.4lf%% (%s/%s)               ",(double)((cont/totalComb)*100.0),bfaInfo.usernames[i], bfaInfo.passwords[j]);
				fflush(stdout);
				curl_easy_setopt(mCurl, CURLOPT_URL, url);
				curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, callback);
				curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, (void *)&chunk);
				curl_easy_setopt(mCurl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
				curl_easy_setopt(mCurl, CURLOPT_USERNAME, bfaInfo.usernames[i]);
				curl_easy_setopt(mCurl, CURLOPT_PASSWORD, bfaInfo.passwords[j]);
				curl_easy_setopt(mCurl, CURLOPT_LOGIN_OPTIONS, "AUTH=*");
				res = curl_easy_perform(mCurl);
				if(res == CURLE_OK){
					printf("%s",C_HRED);
					printf("\n\n  Authentication success: %s/%s\n\n",bfaInfo.usernames[i],bfaInfo.passwords[j]);
					printf("%s", chunk.response);
					printf("%s\n", C_DEFAULT);
				}else{
					switch(res){
					case 67:
						break;
					case 28:
						timeouts++;
						break;
					default:
						char errMsg[BUFFER_SIZE_1K]="";
						snprintf(errMsg,sizeof(errMsg),"libcurl error: %d (%s)",res,curl_easy_strerror(res));
						show_message(errMsg,0, 0, ERROR_MESSAGE, TRUE);
						cancelCurrentProcess=TRUE;
						break;
					}
				}
				chunk.response="";
				curl_easy_reset(mCurl);
			}
		}
	}else{
		return show_message("Error curl initialization",0,0, ERROR_MESSAGE, TRUE);
	}
	if(timeouts==BRUTE_FORCE_TIMEOUT) printf("\n\n  %d timeouts. Aborting\n\n", BRUTE_FORCE_TIMEOUT);
	curl_easy_cleanup(mCurl);
	curl_global_cleanup();
	return RETURN_OK;
}
