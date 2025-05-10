
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <readline/history.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"
#include <errno.h>
#include <openssl/err.h>
#include <fcntl.h>

char **files=NULL;
double totalFiles=0;
char **stringTemplates=NULL;
long int selectedOpt=0;
int totalThreads=0;
int contProcesedFiles=0;

static int compare_dates(struct tm tm1,struct tm tm2){
	char strTm1[BUFFER_SIZE_32B]="", strTm2[BUFFER_SIZE_32B]="";
	snprintf(strTm1,BUFFER_SIZE_32B,"%d%02d%02d",tm1.tm_year,tm1.tm_mon,tm1.tm_mday);
	snprintf(strTm2,BUFFER_SIZE_32B,"%d%02d%02d",tm2.tm_year,tm2.tm_mon,tm2.tm_mday);
	for(size_t i=0;i<strlen(strTm1);i++){
		if(strTm1[i]<strTm2[i]) return -1;
		if(strTm1[i]>strTm2[i]) return 1;
	}
	return 0;
}

static int get_cert_info(){
	struct sockaddr_in serverAddress;
	serverAddress.sin_family=AF_INET;
	serverAddress.sin_port=htons(portUnderHacking);
	serverAddress.sin_addr.s_addr=target.targetIp.s_addr;
	int socketConn=socket(AF_INET, SOCK_STREAM, 0);
	if(socketConn<0) return set_last_activity_error(SOCKET_CONNECTION_ERROR, "");
	setsockopt(socketConn, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	int valResp=0;
	if((valResp=connect(socketConn, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0))
		return set_last_activity_error(SOCKET_CONNECTION_ERROR, "");
	SSL *sslConn = SSL_new(sslCtx);
	if(sslConn==NULL){
		clean_ssl(sslConn);
		return set_last_activity_error(SSL_CONNECTION_ERROR, "");
	}
	if(!SSL_set_fd(sslConn, socketConn)){
		clean_ssl(sslConn);
		return set_last_activity_error(SSL_FD_ERROR, "");
	}
	SSL_set_connect_state(sslConn);
	SSL_set_tlsext_host_name(sslConn, target.strTargetURL);
	if(!SSL_connect(sslConn)){
		clean_ssl(sslConn);
		return set_last_activity_error(SSL_CONNECT_ERROR, "");
	}
	X509 *cert = SSL_get_peer_certificate(sslConn);
	OpenSSL_add_all_algorithms();
	char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	printf("%s  Subject: %s",C_HWHITE,C_DEFAULT);
	for(size_t i=1;i<strlen(subj);i++) (subj[i]=='/')?(printf(", ")):(printf("%c", subj[i]));
	char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	printf("\n\n%s  Issuer:  %s",C_HWHITE,C_DEFAULT);
	for(size_t i=1;i<strlen(issuer);i++) (issuer[i]=='/')?(printf(", ")):(printf("%c", issuer[i]));
	int version = ((int) X509_get_version(cert)) + 1;
	printf("\n\n%s  Version: %sv%d",C_HWHITE,C_DEFAULT, version);
	ASN1_INTEGER *serial = X509_get_serialNumber(cert);
	BIGNUM *bnValue = NULL;
	bnValue = ASN1_INTEGER_to_BN(serial, NULL);
	char *asciiHex = BN_bn2hex(bnValue);
	printf("\n\n%s  Serial: %s%s",C_HWHITE,C_DEFAULT,asciiHex);
	ASN1_TIME *not_before = X509_get_notBefore(cert);
	struct tm tm;
	ASN1_TIME_to_tm(not_before, &tm);
	time_t timestamp = time(NULL);
	struct tm tmNow=*localtime(&timestamp);
	char *validityColor=C_DEFAULT;
	if(compare_dates(tm, tmNow)==1) validityColor=C_HRED;
	printf("\n\n%s  Start Date:\t%s%d/%02d/%02d %02d:%02d:%02d UTC:%s",C_HWHITE,validityColor,tm.tm_year + 1900,tm.tm_mon + 1,tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone);
	ASN1_TIME *not_after = X509_get_notAfter(cert);
	validityColor=C_DEFAULT;
	ASN1_TIME_to_tm(not_after, &tm);
	if(compare_dates(tm, tmNow)==-1) validityColor=C_HRED;
	printf("\n\n%s  Expire Date:\t%s%d/%02d/%02d %02d:%02d:%02d UTC:%s",C_HWHITE,validityColor,tm.tm_year + 1900,tm.tm_mon + 1,tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone);
	int pkey_nid=X509_get_signature_nid(cert);
	const char* sslbuf = OBJ_nid2ln(pkey_nid);
	printf("\n\n%s  Signature Algorithm: %s%s",C_HWHITE,C_DEFAULT,sslbuf);
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	if (EVP_PKEY_is_a(pkey, "RSA")) {
		if (EVP_PKEY_get_bn_param(pkey, "n", &bnValue)){
			asciiHex = BN_bn2hex(bnValue);
			printf("\n\n%s  RSA(n): %s%s",C_HWHITE,C_DEFAULT,asciiHex);
		}
		if (EVP_PKEY_get_bn_param(pkey, "e", &bnValue)){
			asciiHex = BN_bn2hex(bnValue);
			printf("\n\n%s  RSA(e): %s%s (%s)",C_HWHITE,C_DEFAULT,asciiHex, BN_bn2dec(bnValue));
		}
		if (EVP_PKEY_get_bn_param(pkey, "d", &bnValue)){
			asciiHex = BN_bn2hex(bnValue);
			printf("\n\n%s  RSA(d): %s%s",C_HWHITE,C_DEFAULT,asciiHex);
		}
		if (EVP_PKEY_get_bn_param(pkey, "rsa-factor1", &bnValue)){
			asciiHex = BN_bn2hex(bnValue);
			printf("\n\n%s  RSA(factor): %s%s",C_HWHITE,C_DEFAULT,asciiHex);
		}
	}else{
		show_message("\n\n  Public Key is not RSA",0, 0, ERROR_MESSAGE, false, false, false);
	}
	printf("\n\n%s  Key Length: %s%d",C_HWHITE,C_DEFAULT,EVP_PKEY_bits(pkey));
	printf("\n\n%s  Certificate: %s\n\n  ",C_HWHITE,C_DEFAULT);
	PEM_write_X509(stdout, cert);
	X509_free(cert);
	BN_free(bnValue);
	free(subj);
	free(issuer);
	free(asciiHex);
	clean_ssl(sslConn);
	return RETURN_OK;
}

static int send_http_msg_to_server(struct in_addr ip,int port, int connType, char *msg, char *serverResp,
		long int sizeResponse){
	int bytesSent=0,bytesReceived=0, localSocketCon=0;
	struct timeval timeout;
	timeout.tv_sec = SOCKET_SEND_TIMEOUT_S;
	timeout.tv_usec = 0;
	struct sockaddr_in serverAddress;
	serverAddress.sin_family=AF_INET;
	serverAddress.sin_port=htons(port);
	serverAddress.sin_addr.s_addr=ip.s_addr;
	do{
		if((localSocketCon=socket(AF_INET, SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR, "");
		setsockopt(localSocketCon, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
		setsockopt(localSocketCon, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
		setsockopt(localSocketCon, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
		int socketFlags=fcntl(localSocketCon, F_GETFL, 0);
		fcntl(localSocketCon, F_SETFL, socketFlags | O_NONBLOCK);
		int retVal=connect(localSocketCon, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
		if(retVal<0 && errno!=EINPROGRESS) return SOCKET_CONNECTION_ERROR;
		fd_set rFdset, wFdset;
		FD_ZERO(&rFdset);
		FD_SET(localSocketCon, &rFdset);
		wFdset=rFdset;
		if((retVal=select(localSocketCon+1,&rFdset,&wFdset,NULL,&timeout))<=0){
			if(retVal==0) return SOCKET_CONNECTION_TIMEOUT_ERROR;
			return retVal;
		}
		fcntl(localSocketCon, F_SETFL, socketFlags & ~O_NONBLOCK);
		SSL *sslConn=NULL;
		if(connType==SSL_CONN_TYPE){
			sslConn = SSL_new(sslCtx);
			if(sslConn==NULL){
				clean_ssl(sslConn);
				return set_last_activity_error(SSL_CONNECTION_ERROR, "");
			}
			if(!SSL_set_fd(sslConn, localSocketCon)){
				clean_ssl(sslConn);
				return set_last_activity_error(SSL_FD_ERROR, "");
			}
			SSL_set_connect_state(sslConn);
			SSL_set_tlsext_host_name(sslConn, target.strTargetURL);
			if(!SSL_connect(sslConn)){
				clean_ssl(sslConn);
				return set_last_activity_error(SSL_CONNECT_ERROR, "");
			}
		}
		struct timeval tvSendTo;
		tvSendTo.tv_sec=SOCKET_SEND_TIMEOUT_S;
		tvSendTo.tv_usec=0;
		FD_ZERO(&wFdset);
		FD_SET(localSocketCon, &wFdset);
		if((retVal=select(localSocketCon+1,NULL,&wFdset,NULL,&tvSendTo))<=0){
			if(retVal==0 ||(retVal<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINPROGRESS))){
				close(localSocketCon);
				continue;
			}
			if(retVal<0) return set_last_activity_error(SENDING_PACKETS_ERROR, "");
			close(localSocketCon);
			continue;
		}
		if(connType==SOCKET_CONN_TYPE || connType==SSH_CONN_TYPE){
			bytesSent=send(localSocketCon,msg,strlen(msg),0);
		}else{
			bytesSent=SSL_write(sslConn,msg,strlen(msg));
		}
		if(bytesSent<=0){
			if(bytesSent==0 || (bytesSent<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINPROGRESS))){
				close(localSocketCon);
				continue;
			}
			if(connType==SSL_CONN_TYPE){
				clean_ssl(sslConn);
				return SSL_get_error(sslConn, bytesSent);
			}
			return set_last_activity_error(SENDING_PACKETS_ERROR, "");
		}
		int contI=0;
		char buffer[BUFFER_SIZE_8K]={'\0'};
		snprintf(serverResp,BUFFER_SIZE_128B,"%s","");
		struct timeval tvRecvTo;
		tvRecvTo.tv_sec=SOCKET_RECV_TIMEOUT_S;
		tvRecvTo.tv_usec=0;
		FD_ZERO(&rFdset);
		FD_SET(localSocketCon, &rFdset);
		if((retVal=select(localSocketCon+1,&rFdset,NULL,NULL,&tvRecvTo))<=0){
			if(retVal==0 ||(retVal<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINPROGRESS))){
				close(localSocketCon);
				continue;
			}
			if(retVal<0) return set_last_activity_error(RECEIVING_PACKETS_ERROR, "");
			close(localSocketCon);
			continue;
		}
		if(connType==SOCKET_CONN_TYPE || connType==SSH_CONN_TYPE){
			bytesReceived=recv(localSocketCon, buffer, BUFFER_SIZE_8K,0);
		}else{
			bytesReceived=SSL_read(sslConn,buffer, BUFFER_SIZE_8K);
		}
		if(bytesReceived==0){
			close(localSocketCon);
			continue;
		}
		if(bytesReceived<=0){
			if(bytesReceived==0 ||(bytesReceived<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINPROGRESS))){
				close(localSocketCon);
				continue;
			}
			if(connType==SSL_CONN_TYPE){
				clean_ssl(sslConn);
				return SSL_get_error(sslConn, bytesReceived);
			}
			return set_last_activity_error(RECEIVING_PACKETS_ERROR, "");
		}
		for(int i=0; contI<sizeResponse && i<bytesReceived; i++, contI++) serverResp[contI]=buffer[i];
		serverResp[contI]='\0';
		close(localSocketCon);
		clean_ssl(sslConn);
		break;
	}while(true);
	return bytesReceived;
}

static void *evaluate_response(void *arg){
	char serverResp[BUFFER_SIZE_512B]="", msg[BUFFER_SIZE_512B]="";
	struct ThreadInfo *tinfo=arg;
	int resp=0, posF=ceil(totalFiles/totalThreads),cont=0,posI=tinfo->threadID*posF;
	if(tinfo->threadID==totalThreads-1) posF=totalFiles;
	for(int i=posI;i<totalFiles && cont<posF && !cancelCurrentProcess;i++,contProcesedFiles++, cont++){
		printf("\rPercentage completed: %.4lf%% (%d/%.0f)",(double)((contProcesedFiles/totalFiles)*100.0), contProcesedFiles, totalFiles);
		fflush(stdout);
		usleep(rand()%1000 + 500);
		snprintf(msg,sizeof(msg), stringTemplates[selectedOpt-1],files[i],target.strTargetURL);
		resp=send_http_msg_to_server(target.targetIp,portUnderHacking,
				target.ports[portUnderHacking].connectionType,msg,serverResp,BUFFER_SIZE_512B);
		if(resp<0 && !cancelCurrentProcess){
			if(target.ports[portUnderHacking].connectionType==SSL_CONN_TYPE){
				if(resp==SSL_AD_UNEXPECTED_MESSAGE || resp==SSL_AD_BAD_RECORD_MAC){
					i--;
					cont--;
					contProcesedFiles--;
					continue;
				}
			}
			cancelCurrentProcess=true;
			if(!lastActivityError.blocked){
				lastActivityError.blocked=true;
				lastActivityError.err= errno;
				lastActivityError.sslErr= resp;
				set_last_activity_error(SENDING_PACKETS_ERROR, "");
			}
			PRINT_RESET;
			pthread_exit(NULL);
		}
		if(resp>0 && (strstr(serverResp," 200 ")!=NULL
				|| strstr(serverResp," 204 ")!=NULL
				|| strstr(serverResp," 301 ")!=NULL
				|| strstr(serverResp," 302 ")!=NULL
				|| strstr(serverResp," 304 ")!=NULL)){
			if(strstr(serverResp," 301 " )!=NULL || strstr(serverResp," 302 " )!=NULL){
				printf(REMOVE_LINE);
				char loc[256]="";
				size_t len=strlen("Location: ");
				char *redir=strstr(serverResp,"Location: ");
				if(redir==NULL) redir=strstr(serverResp,"location: ");
				if(redir==NULL) continue; //TODO No location??
				for(size_t i=0; redir[len+i]!='\n';i++) loc[i]=redir[len+i];
				loc[strlen(loc)-1]=0;
				printf("  Redirection found: %s/%s%s (%sredirected: %s%s)",C_HRED, files[i],C_DEFAULT, C_HWHITE,loc,C_DEFAULT);
				printf("\n\n"REMOVE_LINE);
				continue;
			}
			printf(REMOVE_LINE);
			printf("  File found: %s/%s%s",C_HRED, files[i],C_DEFAULT);
			printf("\n\n"REMOVE_LINE);
		}
	}
	pthread_exit(NULL);
}

int http(int type){
	char serverResp[BUFFER_SIZE_1K]="";
	int bytesRecv=0, totalStrings=0;
	contProcesedFiles=0;
	char msg[BUFFER_SIZE_1K]="";
	FILE *f;
	switch(type){
	case HTTP_HEADER_BANNER_GRABBING:
		snprintf(msg,sizeof(msg), "HEAD / HTTP/1.1\r\n"
				"Host: %s\r\n"
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
				"Accept: */*\r\n\r\n",target.strTargetURL);
		bytesRecv=send_http_msg_to_server(target.targetIp
				,portUnderHacking
				,target.ports[portUnderHacking].connectionType
				,msg,serverResp,BUFFER_SIZE_1K);
		if(bytesRecv<0) return RETURN_ERROR;
		show_message(serverResp,bytesRecv, 0, RESULT_MESSAGE,false, false, false);
		PRINT_RESET;
		return RETURN_OK;
	case HTTP_TLS_GRABBING:
		if(target.ports[portUnderHacking].connectionType!=SSL_CONN_TYPE){
			show_message("SSL not supported for this port\n",0, 0, ERROR_MESSAGE, false, false, false);
			return RETURN_OK;
		}
		return get_cert_info();
	case HTTP_METHODS_ALLOWED_GRABBING:
		snprintf(msg,sizeof(msg),"OPTIONS * HTTP/1.1\r\n"
				"Host: %s\r\n"
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
				"Accept: */*\r\n\r\n",target.strTargetURL);
		bytesRecv=send_http_msg_to_server(target.targetIp, portUnderHacking, target.ports[portUnderHacking].connectionType
				,msg, serverResp, BUFFER_SIZE_1K);
		if(bytesRecv>0 && (strstr(serverResp," 200 ")!=NULL || strstr(serverResp," 204 ")!=NULL)){
			show_message(serverResp,bytesRecv,0, RESULT_MESSAGE,true, false, false);
			if(strstr(serverResp," POST")!=NULL || strstr(serverResp," PUT")!=NULL || strstr(serverResp," DELETE")!=NULL){
				show_message("POST, PUT or DELETE option(s) found",0, 0, ERROR_MESSAGE, false, false, false);
			}else{
				show_message("No methods allowed found.",0,0, ERROR_MESSAGE, false, false, false);
			}
			printf("\n");
			break;
		}
		if(bytesRecv<0) return RETURN_ERROR;
		show_message("No methods allowed found.",0,0, ERROR_MESSAGE, false, false, false);
		PRINT_RESET;
		break;
	case HTTP_SERVER_RESP_SPOOFED_HEADERS:
		char **headers=NULL;
		if((totalFiles=open_file_str(resourcesLocation, "spoofed_headers_http.txt",&f, &headers))==RETURN_ERROR) return show_message("Error opening file",0,0,ERROR_MESSAGE, true, false, false);
		fclose(f);
		for(int i=0;i<totalFiles;i++){
			snprintf(msg,sizeof(msg),"GET / HTTP/1.1\r\n"
					"Host: %s\r\n"
					"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
					"Accept: */*\r\n\r\n",headers[i]);
			char serverResp[BUFFER_SIZE_32B]="";
			bytesRecv=send_http_msg_to_server(target.targetIp, portUnderHacking, target.ports[portUnderHacking].connectionType
					,msg,serverResp,BUFFER_SIZE_32B);
			if(bytesRecv<0){
				free_char_double_pointer(&headers, totalFiles);
				return RETURN_ERROR;
			}
			printf("  Sending '%s': ", headers[i]);
			if((strstr(serverResp," 200 ")!=NULL || strstr(serverResp," 204 ")!=NULL)){
				show_message("200/204",strlen("200/204"),0, CRITICAL_MESSAGE,false, false, false);
			}else{
				char printResp[BUFFER_SIZE_32B]="";
				int i=0;
				for(i=0;serverResp[i]!='\0' && serverResp[i]!='\n' && i<BUFFER_SIZE_32B;i++) printResp[i]=serverResp[i];
				printResp[i]='\0';
				printf("%s%s%s", C_HWHITE, printResp,C_DEFAULT);
			}
			printf("\n");
		}
		free_char_double_pointer(&headers, totalFiles);
		break;
	case HTTP_GET_WEBPAGES:
		FILE *f=NULL;
		totalStrings=open_file_str(resourcesLocation, "getting_webpages.txt", &f, &stringTemplates);
		if(totalStrings==RETURN_ERROR){
			free_char_double_pointer(&stringTemplates, totalStrings);
			return set_last_activity_error(OPENING_FILE_ERROR, "");
		}
		fclose(f);
		totalThreads=request_quantity_threads(100);
		printf("\n");
		do{
			for(int i=0;i<totalStrings;i++) printf("  %d) %s\n", i+1, stringTemplates[i]);
			printf("\n");
			char * queryType=get_readline("Select the query type (;=exit | default=1):", true);
			if(strcmp(queryType,";")==0){
				free_char_double_pointer(&stringTemplates, totalStrings);
				free(queryType);
				printf("%s\n",C_DEFAULT);
				return RETURN_OK;
			}
			selectedOpt=strtol(queryType,NULL,10);
			if(strcmp(queryType,"")==0) selectedOpt=1;
			free(queryType);
			if(selectedOpt<1 || selectedOpt>totalStrings){
				show_message("Option not valid\n",0, 0, ERROR_MESSAGE, true, false, false);
				continue;
			}
			break;
		}while(true);
		printf("\n");
		format_strings_from_files(stringTemplates[selectedOpt-1], stringTemplates[selectedOpt-1]);
		if((totalFiles=open_file_str(resourcesLocation, "dirs_and_files_http.txt",&f, &files))==-1){
			free_char_double_pointer(&files, totalFiles);
			free_char_double_pointer(&stringTemplates, totalStrings);
			return show_message("Error opening file",0,0,ERROR_MESSAGE, true, false, false);
		}
		fclose(f);
		pthread_t *getWPThread = (pthread_t *)malloc(totalThreads * sizeof(pthread_t));
		struct ThreadInfo *tInfo = (struct ThreadInfo *) malloc(totalThreads * sizeof(struct ThreadInfo));
		for(int i=0;i<totalThreads;i++){
			tInfo[i].threadID=i;
			pthread_create(&getWPThread[i], NULL, &evaluate_response, &tInfo[i]);
		}
		for(int i=0;i<totalThreads;i++) pthread_join(getWPThread[i], NULL);
		free(getWPThread);
		free(tInfo);
		free_char_double_pointer(&files, totalFiles);
		free_char_double_pointer(&stringTemplates, totalStrings);
		if(cancelCurrentProcess) return RETURN_ERROR;
		PRINT_RESET;
		return RETURN_OK;
	case HTTP_OTHERS:
		char **commands=NULL;
		totalStrings=open_file_str(resourcesLocation, "http_commands.txt", &f, &commands);
		if(totalStrings==RETURN_ERROR) return set_last_activity_error(OPENING_FILE_ERROR,"");
		fclose(f);
		do{
			char *command=get_readline("![#]=templates,;=exit)->", false);
			if(command[0]==0){
				PRINT_RESET
				free(command);
				continue;
			}
			if(strcmp(command,";")==0){
				free(command);
				break;
			}
			if(strcmp(command,"!")==0){
				for(int i=0;i<totalStrings;i++) printf("\n  %d) %s", i+1, commands[i]);
				printf("\n\n");
				continue;
			}
			if(command[0]=='!' && strlen(command)>1){
				char buf[BUFFER_SIZE_32B]="";
				for(size_t i=1;i<strlen(command);i++) buf[i-1]=command[i];
				long int selectedOpt=strtol(buf,NULL,10);
				if(selectedOpt<1 || selectedOpt>totalStrings){
					show_message("Option not valid\n",0, 0, ERROR_MESSAGE, true, false, false);
					continue;
				}
				format_strings_from_files(commands[selectedOpt-1], commands[selectedOpt-1]);
				snprintf(msg,BUFFER_SIZE_1K, commands[selectedOpt-1], target.strTargetURL, portUnderHacking);
				add_history(msg);
				continue;
			}
			add_history(command);
			printf("\n");
			system_call(command);
			free(command);
			printf("\n");
		}while(true);
		free_char_double_pointer(&commands, totalStrings);
		break;
	default:
		break;
	}
	clear_history();
	return RETURN_OK;
}



