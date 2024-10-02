
#include "../auditing-cybersecurity.h"
#include "networking.h"
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

SSL_CTX *sslCtx=NULL;

static int parse_output(char **stringTo, char *stringFrom){
	*stringTo=malloc(strlen(stringFrom)+1);
	memset(*stringTo,0,strlen(stringFrom)+1);
	int cont=0;
	for(int i=0;stringFrom[i]!=0;i++,cont++){
		if(stringFrom[i]=='\\'){
			switch(stringFrom[i+1]){
			case 'n':
				(*stringTo)[cont]='\n';
				break;
			case 'r':
				(*stringTo)[cont]='\r';
				break;
			case 't':
				(*stringTo)[cont]='\t';
				break;
			case '\\':
				(*stringTo)[cont]='\\';
				break;
			case '"':
				(*stringTo)[cont]='\"';
				break;
			default:
				break;
			}
			i++;
			continue;
		}
		(*stringTo)[cont]=stringFrom[i];
	}
	(*stringTo)[cont]=0;
	return RETURN_OK;
}

static int parse_input(char **stringTo, char *stringFrom){
	int cont=0, contEsc=0;
	for(int i=0;i<strlen(stringFrom);i++){
		switch(stringFrom[i]){
		case '\"':
		case '\n':
		case '\t':
		case '\r':
		case '\\':
			contEsc++;
			break;
		default:
			break;
		}
	}
	*stringTo=malloc(strlen(stringFrom)+contEsc+1);
	memset(*stringTo,0,strlen(stringFrom)+contEsc+1);
	for(int i=0;i<strlen(stringFrom);i++,cont++){
		switch(stringFrom[i]){
		case '\"':
			(*stringTo)[cont]='\\';
			(*stringTo)[++cont]='\"';
			break;
		case '\n':
			(*stringTo)[cont]='\\';
			(*stringTo)[++cont]='n';
			break;
		case '\t':
			(*stringTo)[cont]='\\';
			(*stringTo)[++cont]='t';
			break;
		case '\r':
			(*stringTo)[cont]='\\';
			(*stringTo)[++cont]='r';
			break;
		case '\\':
			(*stringTo)[cont]='\\';
			(*stringTo)[++cont]='\\';
			break;
		default:
			(*stringTo)[cont]=stringFrom[i];
			break;
		}
	}
	(*stringTo)[cont]='\0';
	return RETURN_OK;
}

static int create_ollama_connection(char *srvAddr, int srvPort, int socketConnectTimeout){
	static char ollamaServerIp[INET_ADDRSTRLEN]="";
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;
	if(getaddrinfo(srvAddr, NULL, &hints, &res)!=0) return set_last_activity_error(GETADDRINFO_ERROR, "");
	struct sockaddr_in *ipv4=(struct sockaddr_in *)res->ai_addr;
	void *addr=&(ipv4->sin_addr);
	inet_ntop(res->ai_family, addr, ollamaServerIp, sizeof(ollamaServerIp));
	freeaddrinfo(res);
	int socketConn=0;
	struct sockaddr_in serverAddress;
	serverAddress.sin_family=AF_INET;
	serverAddress.sin_port=htons(srvPort);
	serverAddress.sin_addr.s_addr=inet_addr(ollamaServerIp);
	if((socketConn=socket(AF_INET, SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CONNECTION_ERROR, "");
	int socketFlags=fcntl(socketConn, F_GETFL, 0);
	fcntl(socketConn, F_SETFL, socketFlags | O_NONBLOCK);
	connect(socketConn, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
	fd_set rFdset, wFdset;
	struct timeval tv;
	FD_ZERO(&rFdset);
	FD_SET(socketConn, &rFdset);
	wFdset=rFdset;
	tv.tv_sec=socketConnectTimeout;
	tv.tv_usec=0;
	if(select(socketConn+1,&rFdset,&wFdset,NULL,&tv)<=0) return set_last_activity_error(SOCKET_SELECT_ERROR, "");
	fcntl(socketConn, F_SETFL, socketFlags);
	return socketConn;
}

static int get_string_from_token(char *text, char *token, char ***result, char endChar){
	char *message=strstr(text,token);
	int entriesFound=0;
	ssize_t cont=0;
	*result=NULL;
	while(message!=NULL){
		entriesFound++;
		cont=0;
		*result=(char**) realloc(*result, entriesFound * sizeof(char*));
		char buffer[BUFFER_SIZE_16K]={0};
		for(int i=strlen(token);(message[i-1]=='\\' || message[i]!=endChar);i++) buffer[i-strlen(token)]=message[i];
		(*result)[entriesFound-1]=malloc(strlen(buffer)+1);
		memset((*result)[entriesFound-1],0,strlen(buffer)+1);
		for(int i=0;i<strlen(buffer);i++,cont++){
			if(message[i]=='\\' && message[i+1]=='\"' && message[i+2]=='}' && message[i+3]==','){
				(*result)[entriesFound-1][cont]='\\';
				i+=3;
				continue;
			}
			(*result)[entriesFound-1][cont]=buffer[i];
		}
		message[0]=' ';
		message=strstr(message,token);
	}
	return entriesFound;
}

static int ollama_send_message(char *payload, char **fullResponse, char **content, Bool streamed){
	int socketConn=create_ollama_connection(oi.ip, oi.port, 5);
	if(socketConn<0) return RETURN_ERROR;
	SSL *sslConn=NULL;
	if((sslCtx=SSL_CTX_new(TLS_client_method()))==NULL) return RETURN_ERROR;
	SSL_CTX_set_verify(sslCtx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_default_verify_paths(sslCtx);
	if((sslConn=SSL_new(sslCtx))==NULL){
		clean_ssl(sslConn);
		return set_last_activity_error(SSL_CONNECT_ERROR, "");
	}
	if(!SSL_set_fd(sslConn, socketConn)){
		clean_ssl(sslConn);
		return RETURN_ERROR;
	}
	SSL_set_connect_state(sslConn);
	SSL_set_tlsext_host_name(sslConn, oi.ip);
	if(!SSL_connect(sslConn)){
		clean_ssl(sslConn);
		return set_last_activity_error(SSL_CONNECT_ERROR, "");
	}
	struct pollfd pfds[1];
	int numEvents=0,pollinHappened=0,bytesSent=0;
	fcntl(socketConn, F_SETFL, O_NONBLOCK);
	pfds[0].fd=socketConn;
	pfds[0].events=POLLOUT;
	numEvents=poll(pfds,1,5);
	if(numEvents==0){
		close(socketConn);
		clean_ssl(sslConn);
		return set_last_activity_error(POLLIN_ERROR, "");
	}
	pollinHappened=pfds[0].revents & POLLOUT;
	if(pollinHappened){
		int totalBytesSent=0;
		while(totalBytesSent<strlen(payload)){
			bytesSent=SSL_write(sslConn, payload + totalBytesSent, strlen(payload) - totalBytesSent);
			if(bytesSent<=0){
				close(socketConn);
				clean_ssl(sslConn);
				return set_last_activity_error(SENDING_PACKETS_ERROR, "");;
			}
			totalBytesSent+=bytesSent;
		}
	}else{
		close(socketConn);
		clean_ssl(sslConn);
		return RETURN_ERROR;
	}
	ssize_t bytesReceived=0,totalBytesReceived=0;
	pfds[0].events=POLLIN;
	numEvents=poll(pfds, 1, 5);
	if(numEvents==0){
		close(socketConn);
		clean_ssl(sslConn);
		return set_last_activity_error(POLLIN_ERROR, "");;
	}
	pollinHappened = pfds[0].revents & POLLIN;
	*fullResponse=malloc(1);
	(*fullResponse)[0]=0;
	if(content!=NULL){
		*content=malloc(1);
		(*content)[0]=0;
	}
	if (pollinHappened){
		do{
			char buffer[BUFFER_SIZE_16K]="";
			bytesReceived=SSL_read(sslConn,buffer, BUFFER_SIZE_16K);
			if(bytesReceived>0){
				totalBytesReceived+=bytesReceived;
				char **result=NULL;
				if(streamed){
					int retVal=get_string_from_token(buffer, "\"content\":\"", &result, '"');
					if(retVal>0){
						char *buffer=NULL;
						parse_output(&buffer, *result);
						for(int i=0;buffer[i]!=0 && !cancelCurrentProcess;i++){
							usleep(15000);
							printf("%c",buffer[i]);
							fflush(stdout);
						}
						free(buffer);
						if(content!=NULL){
							*content=realloc(*content,totalBytesReceived+1);
							strcat(*content,result[0]);
							free(result[0]);
							free(result);
						}
					}
				}
				*fullResponse=realloc(*fullResponse,totalBytesReceived+1);
				strcat(*fullResponse,buffer);
				if(strstr(buffer,"\"done\":false")!=NULL || strstr(buffer,"\"done\": false")!=NULL) continue;
				if(strstr(buffer,"\"done\":true")!=NULL || strstr(buffer,"\"done\": true")!=NULL) break;
			}
			if(bytesReceived==0) break;
			if(bytesReceived<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) continue;
			if(bytesReceived<0 && (errno!=EAGAIN)){
				close(socketConn);
				clean_ssl(sslConn);
				return set_last_activity_error(RECEIVING_PACKETS_ERROR, "");;
			}
		}while(TRUE && !cancelCurrentProcess);
	}
	close(socketConn);
	clean_ssl(sslConn);
	return totalBytesReceived;
}

int ollama_check_service_status(){
	char msg[2048]="";
	snprintf(msg,2048,
			"GET / HTTP/1.1\r\n"
			"Host: %s\r\n\r\n", oi.ip);
	char *buffer=NULL;
	int retVal=0;
	if((retVal=ollama_send_message(msg, &buffer,NULL, FALSE))<0){
		printf("\n%s\n\n%d\n", buffer, retVal);
		free(buffer);
		return retVal;
	}
	if(strstr(buffer,"Ollama")==NULL){
		free(buffer);
		return FALSE;
	}
	free(buffer);
	return TRUE;
}

int ollama_send_prompt(char *message){
	char *messageParsed=NULL;
	parse_input(&messageParsed, message);
	ssize_t len=
			strlen(oi.model)
			+sizeof(oi.temp)
			+sizeof(oi.maxTokens)
			+sizeof(oi.maxTokens)
			+strlen("IT Security Auditor")
			+strlen(messageParsed)
			+512;
	char *body=malloc(len);
	memset(body,0,len);
	snprintf(body,len,
			"{\"model\":\"%s\","
			"\"temperature\": %f,"
			"\"max_tokens\": %d,"
			"\"num_ctx\": %d,"
			"\"stream\": true,"
			"\"keep_alive\": -1,"
			"\"stop\": null,"
			"\"messages\":["
			"{\"role\":\"system\",\"content\":\"%s\"},"
			"{\"role\": \"user\",\"content\": \"%s\"}]}",
			oi.model,
			oi.temp,
			oi.maxTokens,
			oi.context,
			"IT Security Auditor",
			messageParsed);
	len=strlen(oi.ip)+sizeof(oi.port)+sizeof((int) strlen(body))+strlen(body)+512;
	char *msg=malloc(len);
	memset(msg,0,len);
	snprintf(msg,len,
			"POST /api/chat HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-agent: Ollama-C-lient/0.0.1 (Linux; x64)\r\n"
			"Accept: */*\r\n"
			"Content-Type: application/json; charset=utf-8\r\n"
			"Content-Length: %d\r\n\r\n"
			"%s",oi.ip,(int) strlen(body), body);
	free(body);
	char *fullResponse=NULL, *content=NULL;
	int retVal=ollama_send_message(msg, &fullResponse, &content, TRUE);
	free(msg);
	if(strstr(fullResponse,"{\"error")!=NULL){
		show_message(strstr(fullResponse,"{\"error"), strlen(strstr(fullResponse,"{\"error")), 0, ERROR_MESSAGE, FALSE);
		free(messageParsed);
		free(fullResponse);
		free(content);
		return RETURN_ERROR;
	}
	if(strstr(fullResponse," 503 ")!=NULL){
		show_message(strstr(fullResponse," 503 "), strlen(strstr(fullResponse," 503 ")), 0, ERROR_MESSAGE, FALSE);
		free(messageParsed);
		free(fullResponse);
		free(content);
		return RETURN_ERROR;
	}
	if(strstr(fullResponse,"\"done\":true")==NULL || strstr(fullResponse,"\"done\": true")!=NULL){
		free(messageParsed);
		free(fullResponse);
		free(content);
		return set_last_activity_error(OLLAMA_SERVER_UNAVAILABLE, "");
	}
	if(retVal<0){
		free(messageParsed);
		free(fullResponse);
		free(content);
		return set_last_activity_error(OLLAMA_SERVER_UNAVAILABLE, "");
	}
	free(messageParsed);
	free(fullResponse);
	free(content);
	return RETURN_OK;
}



