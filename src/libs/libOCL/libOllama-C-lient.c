/*
 ============================================================================
 Name        : libOllama-C-lient.c
 Author      : L. (lucho-a.github.io)
 Version     : 0.0.1
 Created on	 : 2024/04/19
 Copyright   : GNU General Public License v3.0
 Description : C file
 ============================================================================
 */

#include "libOllama-C-lient.h"

#include <sys/socket.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE_16K				(1024*16)

typedef struct Response{
	char *fullResponse;
	char *content;
}Response;

typedef struct Message{
	char *userMessage;
	char *assistantMessage;
	bool isNew;
	struct Message *nextMessage;
}Message;

Message *rootContextMessages=NULL;
int contContextMessages=0;
SSL_CTX *oclSslCtx=NULL;
bool ocl_canceled=false;

typedef struct _ocl{
	char *srvAddr;
	int srvPort;
	int responseSpeed;
	int socketConnectTimeout;
	int socketSendTimeout;
	int socketRecvTimeout;
	char *responseFont;
	char *model;
	char *systemRole;
	double temp;
	int maxHistoryCtx;
	int maxTokensCtx;
	char *contextFile;
	struct _ocl_response *ocl_resp;
}OCl;

struct _ocl_response{
	char *fullResponse;
	char *content;
	char *error;
	double loadDuration;
	double promptEvalDuration;
	double evalDuration;
	double totalDuration;
	int promptEvalCount;
	int evalCount;
	double tokensPerSec;
};

char * OCl_get_model(OCl *ocl){ return ocl->model;}

double OCL_get_response_load_duration(OCl *ocl){ return ocl->ocl_resp->loadDuration;}
double OCL_get_response_prompt_eval_duration(OCl *ocl){ return ocl->ocl_resp->promptEvalDuration;}
double OCL_get_response_eval_duration(OCl *ocl){ return ocl->ocl_resp->evalDuration;}
double OCL_get_response_total_duration(OCl *ocl){ return ocl->ocl_resp->totalDuration;}
int OCL_get_response_prompt_eval_count(OCl *ocl){ return ocl->ocl_resp->promptEvalCount;}
int OCL_get_response_eval_count(OCl *ocl){ return ocl->ocl_resp->evalCount;}
double OCL_get_response_tokens_per_sec(OCl *ocl){ return ocl->ocl_resp->tokensPerSec;}
char * OCL_get_response_error(OCl *ocl){return ocl->ocl_resp->error;}

int OCl_set_server_addr(OCl *ocl, char *serverAddr){
	if(serverAddr!=NULL && strcmp(serverAddr,"")!=0) ocl->srvAddr=serverAddr;
	return OCL_RETURN_OK;
}

static int OCl_set_server_port(OCl *ocl, char *serverPort){
	if(serverPort!=NULL && strcmp(serverPort,"")!=0){
		char *tail=NULL;
		ocl->srvPort=strtol(serverPort, &tail, 10);
		if(ocl->srvPort<1||ocl->srvPort>65535||tail[0]!=0) return OCL_ERR_PORT;
	}
	return OCL_RETURN_OK;
}

int OCl_set_model(OCl *ocl, char *model){
	if(ocl->model!=NULL) free(ocl->model);
	ocl->model=malloc(strlen(model)+1);
	memset(ocl->model,0,strlen(model)+1);
	if(model!=NULL && strcmp(model,"")!=0){
		int cont=0;
		for(size_t i=0;i<strlen(model);i++){
			if(model[i]!=' ') ocl->model[cont++]=model[i];
		}
	}
	return OCL_RETURN_OK;
}

int OCl_set_role(OCl *ocl, char *role){
	if(role!=NULL && strcmp(role,"")!=0){
		if(ocl->systemRole!=NULL) free(ocl->systemRole);
		ocl->systemRole=malloc(strlen(role)+1);
		memset(ocl->systemRole,0,strlen(role)+1);
		snprintf(ocl->systemRole, strlen(role)+1,"%s", role);
	}else{
		ocl->systemRole=malloc(1);
		memset(ocl->systemRole,0,1);
		ocl->systemRole[0]=0;
	}
	return OCL_RETURN_OK;
}

static int OCl_set_connect_timeout(OCl *ocl, char *connectto){
	if(connectto!=NULL && strcmp(connectto,"")!=0){
		char *tail=NULL;
		ocl->socketConnectTimeout=strtol(connectto, &tail, 10);
		if(ocl->socketConnectTimeout<1||tail[0]!=0) return OCL_ERR_SOCKET_CONNECTION_TIMEOUT_NOT_VALID;
	}
	return OCL_RETURN_OK;
}

static int OCl_set_send_timeout(OCl *ocl, char *sendto){
	if(sendto!=NULL && strcmp(sendto,"")!=0){
		char *tail=NULL;
		ocl->socketSendTimeout=strtol(sendto, &tail, 10);
		if(ocl->socketSendTimeout<1||tail[0]!=0) return OCL_ERR_SOCKET_SEND_TIMEOUT_NOT_VALID;
	}
	return OCL_RETURN_OK;
}

static int OCl_set_recv_timeout(OCl *ocl, char *recvto){
	if(recvto!=NULL && strcmp(recvto,"")!=0){
		char *tail=NULL;
		ocl->socketRecvTimeout=strtol(recvto, &tail, 10);
		if(ocl->socketRecvTimeout<1||tail[0]!=0) return OCL_ERR_SOCKET_RECV_TIMEOUT_NOT_VALID;
	}
	return OCL_RETURN_OK;
}

static int OCl_set_response_speed(OCl *ocl, char *respSpeed){
	if(respSpeed!=NULL && strcmp(respSpeed,"")!=0){
		char *tail=NULL;
		ocl->responseSpeed=strtol(respSpeed, &tail, 10);
		if(ocl->responseSpeed<1||tail[0]!=0) return OCL_ERR_RESPONSE_SPEED_NOT_VALID;
	}
	return OCL_RETURN_OK;
}

static int OCl_set_response_font(OCl *ocl, char *responseFont){
	if(responseFont!=NULL && strcmp(responseFont,"")!=0){
		ocl->responseFont=responseFont;
	}else{
		ocl->responseFont="";
	}
	return OCL_RETURN_OK;
}

static int OCl_set_temp(OCl *ocl, char *temp){
	if(temp!=NULL && strcmp(temp,"")!=0){
		char *tail=NULL;
		ocl->temp=strtod(temp,&tail);
		if(ocl->temp<=0.0 || tail[0]!=0) return OCL_ERR_TEMP;
	}
	return OCL_RETURN_OK;
}

static int OCl_set_max_history_ctx(OCl *ocl, char *maxHistoryCtx){
	if(maxHistoryCtx!=NULL && strcmp(maxHistoryCtx,"")!=0){
		char *tail=NULL;
		ocl->maxHistoryCtx=strtol(maxHistoryCtx,&tail,10);
		if(ocl->maxHistoryCtx<0 || tail[0]!=0) return OCL_ERR_MAX_HISTORY_CTX;
	}
	return OCL_RETURN_OK;
}

static int OCl_set_max_tokens_ctx(OCl *ocl, char *maxTokensCtx){
	if(maxTokensCtx!=NULL && strcmp(maxTokensCtx,"")!=0){
		char *tail=NULL;
		ocl->maxTokensCtx=strtol(maxTokensCtx,&tail,10);
		if(ocl->maxTokensCtx<0 || tail[0]!=0) return OCL_ERR_MAX_TOKENS_CTX;
	}
	return OCL_RETURN_OK;
}

static int OCl_set_context_file(OCl *ocl, char *contextFile){
	if(contextFile!=NULL && strcmp(contextFile,"")!=0){
		FILE *f=fopen(contextFile,"r");
		if(f==NULL) return OCL_ERR_CONTEXT_FILE_NOT_FOUND;
		fclose(f);
		ocl->contextFile=contextFile;
	}
	return OCL_RETURN_OK;
}


static int OCl_set_error(OCl *ocl, char *err){
	if(ocl->ocl_resp->error!=NULL) free(ocl->ocl_resp->error);
	ocl->ocl_resp->error=malloc(strlen(err)+1);
	memset(ocl->ocl_resp->error,0,strlen(err));
	snprintf(ocl->ocl_resp->error,strlen(err)+1,"%s",err);
	return OCL_RETURN_OK;
}

int OCl_init(){
	SSL_library_init();
	if((oclSslCtx=SSL_CTX_new(TLS_client_method()))==NULL) return OCL_ERR_SSL_CONTEXT_ERROR;
	SSL_CTX_set_verify(oclSslCtx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_default_verify_paths(oclSslCtx);
	ocl_canceled=false;
	return OCL_RETURN_OK;
}

int OCl_flush_context(void){
	while(rootContextMessages!=NULL){
		Message *temp=rootContextMessages;
		rootContextMessages=temp->nextMessage;
		if(temp->userMessage!=NULL) free(temp->userMessage);
		if(temp->assistantMessage!=NULL) free(temp->assistantMessage);
		free(temp);
	}
	contContextMessages=0;
	return OCL_RETURN_OK;
}

int OCl_free(OCl *ocl){
	if(ocl!=NULL){
		if(ocl->model!=NULL){
			free(ocl->model);
			ocl->model=NULL;
		}
		if(ocl->systemRole!=NULL){
			free(ocl->systemRole);
			ocl->systemRole=NULL;
		}
		if(ocl->ocl_resp!=NULL){
			free(ocl->ocl_resp->content);
			free(ocl->ocl_resp->fullResponse);
			free(ocl->ocl_resp->error);
			free(ocl->ocl_resp);
		}
		free(ocl);
	}
	OCl_flush_context();
	return OCL_RETURN_OK;
}

int OCl_get_instance(OCl **ocl, char *serverAddr, char *serverPort, char *socketConnTo, char *socketSendTo
		,char *socketRecvTo, char *responseSpeed, char *responseFont, char *model, char *systemRole
		,char *maxContextMsg, char *temp, char *maxTokensCtx, char *contextFile){
	*ocl=malloc(sizeof(OCl));
	int retVal=0;
	OCl_set_server_addr(*ocl, OCL_OLLAMA_SERVER_ADDR);
	OCl_set_server_addr(*ocl, serverAddr);
	OCl_set_server_port(*ocl, OCL_OLLAMA_SERVER_PORT);
	if((retVal=OCl_set_server_port(*ocl, serverPort))!=OCL_RETURN_OK) return retVal;
	OCl_set_connect_timeout(*ocl, OCL_SOCKET_CONNECT_TIMEOUT_S);
	if((retVal=OCl_set_connect_timeout(*ocl, socketConnTo))!=OCL_RETURN_OK) return retVal;
	OCl_set_send_timeout(*ocl, OCL_SOCKET_SEND_TIMEOUT_S);
	if((retVal=OCl_set_send_timeout(*ocl, socketSendTo))!=OCL_RETURN_OK) return retVal;
	OCl_set_recv_timeout(*ocl, OCL_SOCKET_RECV_TIMEOUT_S);
	if((retVal=OCl_set_recv_timeout(*ocl, socketRecvTo))!=OCL_RETURN_OK) return retVal;
	OCl_set_response_speed(*ocl, OCL_RESPONSE_SPEED);
	if((retVal=OCl_set_response_speed(*ocl, responseSpeed))!=OCL_RETURN_OK) return retVal;
	OCl_set_response_font(*ocl, responseFont);
	(*ocl)->model=NULL;
	OCl_set_model(*ocl, model);
	(*ocl)->systemRole=NULL;
	OCl_set_role(*ocl, systemRole);
	OCl_set_max_history_ctx(*ocl, OCL_MAX_HISTORY_CTX);
	if((retVal=OCl_set_max_history_ctx(*ocl, maxContextMsg))!=OCL_RETURN_OK) return retVal;
	OCl_set_temp(*ocl, OCL_TEMP);
	if((retVal=OCl_set_temp(*ocl, temp))!=OCL_RETURN_OK) return retVal;
	OCl_set_max_tokens_ctx(*ocl, OCL_MAX_TOKENS_CTX);
	if((retVal=OCl_set_max_tokens_ctx(*ocl, maxTokensCtx))!=OCL_RETURN_OK) return retVal;
	(*ocl)->contextFile=NULL;
	if((retVal=OCl_set_context_file(*ocl,contextFile))!=OCL_RETURN_OK) return retVal;
	(*ocl)->ocl_resp=malloc(sizeof(struct _ocl_response));
	(*ocl)->ocl_resp->content=NULL;
	(*ocl)->ocl_resp->fullResponse=NULL;
	(*ocl)->ocl_resp->error=NULL;
	(*ocl)->ocl_resp->loadDuration=0.0;
	(*ocl)->ocl_resp->promptEvalDuration=0.0;
	(*ocl)->ocl_resp->evalDuration=0.0;
	(*ocl)->ocl_resp->totalDuration=0.0;
	(*ocl)->ocl_resp->promptEvalCount=0;
	(*ocl)->ocl_resp->evalCount=0;
	(*ocl)->ocl_resp->tokensPerSec=0.0;
	return OCL_RETURN_OK;
}

static void clean_ssl(SSL *ssl){
	SSL_shutdown(ssl);
	SSL_certs_clear(ssl);
	SSL_clear(ssl);
	SSL_free(ssl);
}

static void create_new_context_message(char *userMessage, char *assistantMessage, bool isNew, int maxHistoryContext){
	Message *newMessage=malloc(sizeof(Message));
	newMessage->userMessage=malloc(strlen(userMessage)+1);
	snprintf(newMessage->userMessage,strlen(userMessage)+1,"%s",userMessage);
	newMessage->assistantMessage=malloc(strlen(assistantMessage)+1);
	snprintf(newMessage->assistantMessage,strlen(assistantMessage)+1,"%s",assistantMessage);
	newMessage->isNew=isNew;
	if(rootContextMessages!=NULL){
		if(contContextMessages>=maxHistoryContext){
			Message *temp=rootContextMessages->nextMessage;
			if(rootContextMessages->userMessage!=NULL) free(rootContextMessages->userMessage);
			if(rootContextMessages->assistantMessage!=NULL) free(rootContextMessages->assistantMessage);
			free(rootContextMessages);
			rootContextMessages=temp;
		}
		Message *temp=rootContextMessages;
		if(temp!=NULL){
			while(temp->nextMessage!=NULL) temp=temp->nextMessage;
			temp->nextMessage=newMessage;
		}else{
			rootContextMessages=newMessage;
		}
	}else{
		rootContextMessages=newMessage;
	}
	newMessage->nextMessage=NULL;
	contContextMessages++;
}


int OCl_save_message(OCl *ocl, char *userMessage, char *assistantMessage){
	if(ocl->contextFile!=NULL){
		FILE *f=fopen(ocl->contextFile,"a");
		if(f==NULL) return OCL_ERR_OPENING_FILE_ERROR;
		fprintf(f,"%s\t%s\n",userMessage,assistantMessage);
		fclose(f);
	}
	return OCL_RETURN_OK;
}

int OCl_import_context(OCl *ocl){
	if(ocl->contextFile!=NULL){
		FILE *f=fopen(ocl->contextFile,"r");
		if(f==NULL) return OCL_ERR_OPENING_FILE_ERROR;
		size_t len=0, i=0;
		int rows=0, initPos=0;
		ssize_t chars=0;
		char *line=NULL, *userMessage=NULL,*assistantMessage=NULL;;
		while((getline(&line, &len, f))!=-1) rows++;
		if(rows>ocl->maxHistoryCtx) initPos=rows-ocl->maxHistoryCtx;
		rewind(f);
		int contRows=0;
		while((chars=getline(&line, &len, f))!=-1){
			if(contRows>=initPos){
				userMessage=malloc(chars+1);
				memset(userMessage,0,chars+1);
				for(i=0;line[i]!='\t';i++) userMessage[i]=line[i];
				int index=0;
				assistantMessage=malloc(chars+1);
				memset(assistantMessage,0,chars+1);
				for(i++;line[i]!='\n';i++,index++) assistantMessage[index]=line[i];
				create_new_context_message(userMessage, assistantMessage, false, ocl->maxHistoryCtx);
				free(userMessage);
				free(assistantMessage);
			}
			contRows++;
		}
		free(line);
		fclose(f);
	}
	return OCL_RETURN_OK;
}

char * OCL_error_handling(int error){
	static char error_hndl[1024]="";
	int sslErr=ERR_get_error();
	switch(error){
	case OCL_ERR_MALLOC_ERROR:
		snprintf(error_hndl, 1024,"Malloc() error: %s", strerror(errno));
		break;
	case OCL_ERR_REALLOC_ERROR:
		snprintf(error_hndl, 1024,"Realloc() error: %s", strerror(errno));
		break;
	case OCL_ERR_GETTING_HOST_INFO_ERROR:
		snprintf(error_hndl, 1024,"Error getting host info: %s", strerror(errno));
		break;
	case OCL_ERR_SOCKET_CREATION_ERROR:
		snprintf(error_hndl, 1024,"Error creating socket: %s", strerror(errno));
		break;
	case OCL_ERR_SOCKET_CONNECTION_ERROR:
		snprintf(error_hndl, 1024,"Error connecting socket: %s", strerror(errno));
		break;
	case OCL_ERR_SOCKET_CONNECTION_TIMEOUT_ERROR:
		snprintf(error_hndl, 1024,"Socket connection time out. ");
		break;
	case OCL_ERR_SSLCTX_NULL_ERROR:
		snprintf(error_hndl, 1024,"SSL context null: %s (Did you call OCL_init()?). SSL Error: %s", strerror(errno),ERR_error_string(sslErr, NULL));
		break;
	case OCL_ERR_SSL_CONTEXT_ERROR:
		snprintf(error_hndl, 1024,"Error creating SSL context: %s. SSL Error: %s", strerror(errno),ERR_error_string(sslErr, NULL));
		break;
	case OCL_ERR_SSL_CERT_NOT_FOUND:
		snprintf(error_hndl, 1024,"SSL cert. not found: %s. SSL Error: %s", strerror(errno),ERR_error_string(sslErr, NULL));
		break;
	case OCL_ERR_SSL_FD_ERROR:
		snprintf(error_hndl, 1024,"SSL fd error: %s. SSL Error: %s", strerror(errno),ERR_error_string(sslErr, NULL));
		break;
	case OCL_ERR_SSL_CONNECT_ERROR:
		snprintf(error_hndl, 1024,"SSL Connection error: %s. SSL Error: %s", strerror(errno),ERR_error_string(sslErr, NULL));
		break;
	case OCL_ERR_SOCKET_SEND_TIMEOUT_ERROR:
		snprintf(error_hndl, 1024,"Sending packet time out. ");
		break;
	case OCL_ERR_SENDING_PACKETS_ERROR:
		snprintf(error_hndl, 1024,"Sending packet error. SSL Error: %s", ERR_error_string(sslErr, NULL));
		break;
	case OCL_ERR_SOCKET_RECV_TIMEOUT_ERROR:
		snprintf(error_hndl, 1024,"Receiving packet time out: %s. SSL Error: %s", strerror(errno),ERR_error_string(sslErr, NULL));
		break;
	case OCL_ERR_RECV_TIMEOUT_ERROR:
		snprintf(error_hndl, 1024,"Time out value not valid. ");
		break;
	case OCL_ERR_RECEIVING_PACKETS_ERROR:
		snprintf(error_hndl, 1024,"Receiving packet error: %s. SSL Error: %s", strerror(errno),ERR_error_string(sslErr, NULL));
		break;
	case OCL_ERR_RESPONSE_MESSAGE_ERROR:
		snprintf(error_hndl, 1024,"Error message into JSON. ");
		break;
	case OCL_ERR_PARTIAL_RESPONSE_RECV:
		snprintf(error_hndl, 1024,"Partial response received. ");
		break;
	case OCL_ERR_ZEROBYTESSENT_ERROR:
		snprintf(error_hndl, 1024,"Zero bytes sent. Try again...");
		break;
	case OCL_ERR_ZEROBYTESRECV_ERROR:
		snprintf(error_hndl, 1024,"Zero bytes received. Try again...");
		break;
	case OCL_ERR_MODEL_FILE_NOT_FOUND:
		snprintf(error_hndl, 1024,"Model file not found. ");
		break;
	case OCL_ERR_CONTEXT_FILE_NOT_FOUND:
		snprintf(error_hndl, 1024,"Context file not found. ");
		break;
	case OCL_ERR_CERT_FILE_NOT_FOUND:
		snprintf(error_hndl, 1024,"Cert. file not found. ");
		break;
	case OCL_ERR_OPENING_FILE_ERROR:
		snprintf(error_hndl, 1024,"Error opening file: %s", strerror(errno));
		break;
	case OCL_ERR_OPENING_ROLE_FILE_ERROR:
		snprintf(error_hndl, 1024,"Error opening 'Role' file: %s", strerror(errno));
		break;
	case OCL_ERR_NO_HISTORY_CONTEXT_ERROR:
		snprintf(error_hndl, 1024,"No message to save. ");
		break;
	case OCL_ERR_UNEXPECTED_JSON_FORMAT_ERROR:
		snprintf(error_hndl, 1024,"Unexpected JSON format error. ");
		break;
	case OCL_ERR_CONTEXT_MSGS_ERROR:
		snprintf(error_hndl, 1024,"'Max. Context Message' value out-of-boundaries. ");
		break;
	case OCL_ERR_NULL_STRUCT_ERROR:
		snprintf(error_hndl, 1024,"ChatGPT structure null. ");
		break;
	case OCL_ERR_SERVICE_UNAVAILABLE:
		snprintf(error_hndl, 1024,"Service unavailable. ");
		break;
	case OCL_ERR_GETTING_MODELS:
		snprintf(error_hndl, 1024,"Error getting models. ");
		break;
	case OCL_ERR_LOADING_MODEL:
		snprintf(error_hndl, 1024,"Error loading model. ");
		break;
	case OCL_ERR_UNLOADING_MODEL:
		snprintf(error_hndl, 1024,"Error unloading model. ");
		break;
	case OCL_ERR_SERVER_ADDR:
		snprintf(error_hndl, 1024,"Server address not valid. ");
		break;
	case OCL_ERR_PORT:
		snprintf(error_hndl, 1024,"Port not valid. ");
		break;
	case OCL_ERR_TEMP:
		snprintf(error_hndl, 1024,"Temperature value not valid. Check modfile.");
		break;
	case OCL_ERR_MAX_HISTORY_CTX:
		snprintf(error_hndl, 1024,"Max. message context value not valid. Check modfile.");
		break;
	case OCL_ERR_MAX_TOKENS_CTX:
		snprintf(error_hndl, 1024,"Max. tokens context value not valid. Check modfile.");
		break;
	case OCL_ERR_SOCKET_CONNECTION_TIMEOUT_NOT_VALID:
		snprintf(error_hndl, 1024,"Connection Timeout value not valid.");
		break;
	case OCL_ERR_SOCKET_SEND_TIMEOUT_NOT_VALID:
		snprintf(error_hndl, 1024,"Send Timeout value not valid.");
		break;
	case OCL_ERR_SOCKET_RECV_TIMEOUT_NOT_VALID:
		snprintf(error_hndl, 1024,"Recv. Timeout value not valid.");
		break;
	case OCL_ERR_RESPONSE_SPEED_NOT_VALID:
		snprintf(error_hndl, 1024,"Response Speed value not valid.");
		break;
	default:
		snprintf(error_hndl, 1024,"Error not handled. ");
		break;
	}
	return error_hndl;
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
		for(size_t i=0;i<strlen(buffer);i++,cont++){
			if(buffer[i]=='\\' && buffer[i+1]=='\"' && buffer[i+2]=='}' && buffer[i+3]==','){
				(*result)[entriesFound-1][cont]='\\';
				i+=4;
				continue;
			}
			(*result)[entriesFound-1][cont]=buffer[i];
		}
		message[0]=' ';
		message=strstr(message,token);
	}
	return entriesFound;
}

static int parse_input(char **stringTo, char *stringFrom){
	int cont=0, contEsc=0;
	for(size_t i=0;i<strlen(stringFrom);i++){
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
	for(size_t i=0;i<strlen(stringFrom);i++,cont++){
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
	return OCL_RETURN_OK;
}

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
			case 'u':
				char buffer[5]="";
				snprintf(buffer,5,"%c%c%c%c",stringFrom[i+2],stringFrom[i+3],stringFrom[i+4],stringFrom[i+5]);
				(*stringTo)[cont]=strtol(buffer,NULL,16);
				i+=4;
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
	return OCL_RETURN_OK;
}

static void print_response(char *response, OCl *ocl){
	char *buffer=NULL;
	printf("%s",ocl->responseFont);
	parse_output(&buffer, response);
	if(ocl->responseSpeed==0){
		printf("%s",buffer);
	}else{
		for(int i=0;buffer[i]!=0 && !ocl_canceled;i++){
			usleep(ocl->responseSpeed);
			printf("%c",buffer[i]);
			fflush(stdout);
		}
	}
	free(buffer);
}

static int create_connection(char *srvAddr, int srvPort, int socketConnectTimeout){
	static char ollamaServerIp[INET_ADDRSTRLEN]="";
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;
	if(getaddrinfo(srvAddr, NULL, &hints, &res)!=0) return OCL_ERR_GETTING_HOST_INFO_ERROR;
	struct sockaddr_in *ipv4=(struct sockaddr_in *)res->ai_addr;
	void *addr=&(ipv4->sin_addr);
	inet_ntop(res->ai_family, addr, ollamaServerIp, sizeof(ollamaServerIp));
	freeaddrinfo(res);
	int socketConn=0;
	struct sockaddr_in serverAddress;
	serverAddress.sin_family=AF_INET;
	serverAddress.sin_port=htons(srvPort);
	serverAddress.sin_addr.s_addr=inet_addr(ollamaServerIp);
	if((socketConn=socket(AF_INET, SOCK_STREAM, 0))<0) return OCL_ERR_SOCKET_CREATION_ERROR;
	int socketFlags=fcntl(socketConn, F_GETFL, 0);
	fcntl(socketConn, F_SETFL, socketFlags | O_NONBLOCK);
	struct timeval tvConnectionTo;
	int retVal=connect(socketConn, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
	if(retVal<0 && errno!=EINPROGRESS) return OCL_ERR_SOCKET_CONNECTION_ERROR;
	fd_set rFdset, wFdset;
	FD_ZERO(&rFdset);
	FD_SET(socketConn, &rFdset);
	wFdset=rFdset;
	tvConnectionTo.tv_sec=socketConnectTimeout;
	tvConnectionTo.tv_usec=0;
	if((retVal=select(socketConn+1,&rFdset,&wFdset,NULL,&tvConnectionTo))<=0){
		if(retVal==0) return OCL_ERR_SOCKET_CONNECTION_TIMEOUT_ERROR;
		return retVal;
	}
	fcntl(socketConn, F_SETFL, socketFlags & ~O_NONBLOCK);
	return socketConn;
}

static int send_message(OCl *ocl,char *payload, char **fullResponse, char **content, bool streamed){
	int socketConn=create_connection(ocl->srvAddr, ocl->srvPort, ocl->socketConnectTimeout);
	if(socketConn<=0) return socketConn;
	if(oclSslCtx==NULL) return OCL_ERR_SSLCTX_NULL_ERROR;
	SSL *sslConn=NULL;
	if((sslConn=SSL_new(oclSslCtx))==NULL){
		clean_ssl(sslConn);
		return OCL_ERR_SSL_CONTEXT_ERROR;
	}
	if(!SSL_set_fd(sslConn, socketConn)){
		clean_ssl(sslConn);
		return OCL_ERR_SSL_FD_ERROR;
	}
	SSL_set_connect_state(sslConn);
	SSL_set_tlsext_host_name(sslConn, ocl->srvAddr);
	if(!SSL_connect(sslConn)){
		clean_ssl(sslConn);
		return OCL_ERR_SSL_CONNECT_ERROR;
	}
	fd_set rFdset, wFdset;
	size_t totalBytesSent=0;
	struct timeval tvSendTo;
	tvSendTo.tv_sec=ocl->socketSendTimeout;
	tvSendTo.tv_usec=0;
	int retVal=0;
	while(totalBytesSent<strlen(payload)){
		FD_ZERO(&wFdset);
		FD_SET(socketConn, &wFdset);
		if((retVal=select(socketConn+1,NULL,&wFdset,NULL,&tvSendTo))<=0){
			if(retVal==0) return OCL_ERR_SOCKET_SEND_TIMEOUT_ERROR;
			return OCL_ERR_SENDING_PACKETS_ERROR;
		}
		totalBytesSent+=SSL_write(sslConn, payload + totalBytesSent, strlen(payload) - totalBytesSent);
	}
	ssize_t bytesReceived=0,totalBytesReceived=0;
	*fullResponse=malloc(1);
	(*fullResponse)[0]=0;
	if(content!=NULL){
		*content=malloc(1);
		(*content)[0]=0;
	}
	struct timeval tvRecvTo;
	tvRecvTo.tv_sec=ocl->socketRecvTimeout;
	tvRecvTo.tv_usec=0;
	do{
		FD_ZERO(&rFdset);
		FD_SET(socketConn, &rFdset);
		if((retVal=select(socketConn+1,&rFdset,NULL,NULL,&tvRecvTo))<=0){
			if(retVal==0) return OCL_ERR_SOCKET_RECV_TIMEOUT_ERROR;
			return OCL_ERR_RECEIVING_PACKETS_ERROR;
		}
		char buffer[BUFFER_SIZE_16K]="";
		bytesReceived=SSL_read(sslConn,buffer, BUFFER_SIZE_16K);
		if(bytesReceived==0) break;
		if(bytesReceived>0){
			totalBytesReceived+=bytesReceived;
			char **result=NULL;
			if(streamed){
				int retVal=get_string_from_token(buffer, "\"content\":\"", &result, '"');
				if(retVal>0){
					print_response(result[0], ocl);
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
		if(!SSL_pending(sslConn)) break;
	}while(true && !ocl_canceled);
	close(socketConn);
	clean_ssl(sslConn);
	return totalBytesReceived;
}

int OCl_send_chat(OCl *ocl, char *message){
	char *messageParsed=NULL;
	parse_input(&messageParsed, message);
	char *context=malloc(1), *buf=NULL;
	context[0]=0;
	if(message[strlen(message)-1]!=';'){
		char *contextTemplate="{\"role\":\"user\",\"content\":\"%s\"},{\"role\":\"assistant\",\"content\":\"%s\"},";
		Message *temp=rootContextMessages;
		ssize_t len=0;
		while(temp!=NULL){
			len=strlen(contextTemplate)+strlen(temp->userMessage)+strlen(temp->assistantMessage);
			buf=malloc(len);
			if(buf==NULL){
				free(messageParsed);
				free(context);
				return OCL_ERR_MALLOC_ERROR;
			}
			memset(buf,0,len);
			snprintf(buf,len,contextTemplate,temp->userMessage,temp->assistantMessage);
			context=realloc(context, strlen(context)+strlen(buf)+1);
			if(context==NULL){
				free(messageParsed);
				free(context);
				free(buf);
				return OCL_ERR_REALLOC_ERROR;
			}
			strcat(context,buf);
			temp=temp->nextMessage;
			free(buf);
		}
	}
	char *roleParsed=NULL;
	parse_input(&roleParsed, ocl->systemRole);
	ssize_t len=
			strlen(ocl->model)
			+sizeof(ocl->temp)
			+sizeof(ocl->maxTokensCtx)
			+strlen(roleParsed)
			+strlen(context)
			+strlen(messageParsed)
			+512;
	char *body=malloc(len);
	memset(body,0,len);
	snprintf(body,len,
			"{\"model\":\"%s\","
			"\"temperature\": %f,"
			"\"num_ctx\": %d,"
			"\"stream\": true,"
			"\"keep_alive\": -1,"
			"\"stop\": null,"
			"\"messages\":["
			"{\"role\":\"system\",\"content\":\"%s\"},"
			"%s""{\"role\": \"user\",\"content\": \"%s\"}]}",
			ocl->model,
			ocl->temp,
			ocl->maxTokensCtx,
			roleParsed,context,
			messageParsed);
	free(context);
	free(roleParsed);
	len=strlen(ocl->srvAddr)+sizeof(ocl->srvPort)+sizeof((int) strlen(body))+strlen(body)+512;
	char *msg=malloc(len);
	memset(msg,0,len);
	snprintf(msg,len,
			"POST /api/chat HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-agent: Ollama-C-lient/0.0.1 (Linux; x64)\r\n"
			"Accept: */*\r\n"
			"Content-Type: application/json; charset=utf-8\r\n"
			"Content-Length: %d\r\n\r\n"
			"%s",ocl->srvAddr,(int) strlen(body), body);
	free(body);
	char *fullResponse=NULL, *content=NULL;
	int retVal=send_message(ocl, msg, &fullResponse, &content, true);
	free(msg);
	if(retVal<0){
		free(messageParsed);
		free(fullResponse);
		free(content);
		return retVal;
	}
	if(strstr(fullResponse,"{\"error")!=NULL){
		OCl_set_error(ocl, strstr(fullResponse,"{\"error"));
		free(messageParsed);
		free(fullResponse);
		free(content);
		return OCL_ERR_RESPONSE_MESSAGE_ERROR;
	}
	if(strstr(fullResponse," 503 ")!=NULL){
		free(messageParsed);
		free(fullResponse);
		free(content);
		return OCL_ERR_SERVICE_UNAVAILABLE;
	}
	if(strstr(fullResponse,"\"done\":true")==NULL || strstr(fullResponse,"\"done\": true")!=NULL){
		free(messageParsed);
		free(fullResponse);
		free(content);
		return OCL_ERR_PARTIAL_RESPONSE_RECV;
	}
	if(!ocl_canceled && retVal>0){
		char **result=NULL;
		int retVal=0;
		retVal=get_string_from_token(fullResponse, "\"load_duration\":", &result, ',');
		if(retVal>0){
			ocl->ocl_resp->loadDuration=strtod(result[0],NULL)/1000000000.0;
			free(result[0]);
			free(result);
		}
		retVal=get_string_from_token(fullResponse, "\"prompt_eval_duration\":", &result, ',');
		if(retVal>0){
			ocl->ocl_resp->promptEvalDuration=strtod(result[0],NULL)/1000000000.0;
			free(result[0]);
			free(result);
		}
		retVal=get_string_from_token(fullResponse, "\"eval_duration\":", &result, '}');
		if(retVal>0){
			ocl->ocl_resp->evalDuration=strtod(result[0],NULL)/1000000000.0;
			free(result[0]);
			free(result);
		}
		retVal=get_string_from_token(fullResponse, "\"total_duration\":", &result, ',');
		if(retVal>0){
			ocl->ocl_resp->totalDuration=strtod(result[0],NULL)/1000000000.0;
			free(result[0]);
			free(result);
		}
		retVal=get_string_from_token(fullResponse, "\"prompt_eval_count\":", &result, ',');
		if(retVal>0){
			ocl->ocl_resp->promptEvalCount=strtol(result[0],NULL,10);
			free(result[0]);
			free(result);
		}
		retVal=get_string_from_token(fullResponse, "\"eval_count\":", &result, ',');
		if(retVal>0){
			ocl->ocl_resp->evalCount=strtol(result[0],NULL,10);
			free(result[0]);
			free(result);
		}
		if(retVal>0) ocl->ocl_resp->tokensPerSec=ocl->ocl_resp->evalCount/ocl->ocl_resp->evalDuration;
		if(message[strlen(message)-1]!=';'){
			create_new_context_message(messageParsed, content, true, ocl->maxHistoryCtx);
			OCl_save_message(ocl, messageParsed, content);
		}
	}
	free(messageParsed);
	free(fullResponse);
	free(content);
	return OCL_RETURN_OK;
}

int OCl_check_service_status(OCl *ocl){
	char msg[2048]="";
	snprintf(msg,2048,
			"GET / HTTP/1.1\r\n"
			"Host: %s\r\n\r\n",ocl->srvAddr);
	char *buffer=NULL;
	int retVal=0;
	if((retVal=send_message(ocl, msg, &buffer,NULL, false))<=0){
		free(buffer);
		return retVal;
	}
	if(strstr(buffer,"Ollama")==NULL){
		free(buffer);
		return OCL_ERR_SERVICE_UNAVAILABLE;
	}
	free(buffer);
	return OCL_RETURN_OK;
}


int OCl_load_model(OCl *ocl, bool load){
	char body[1024]="";
	if(load){
		snprintf(body,1024,"{\"model\": \"%s\", \"keep_alive\": -1}",ocl->model);
	}else{
		snprintf(body,1024,"{\"model\": \"%s\", \"keep_alive\": 0}",ocl->model);
	}
	char msg[2048]="";
	snprintf(msg,2048,
			"POST /api/chat HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Content-Type: application/json\r\n"
			"Content-Length: %d\r\n\r\n"
			"%s",ocl->srvAddr,(int) strlen(body), body);
	char *buffer=NULL;
	int retVal=0;
	if((retVal=send_message(ocl, msg, &buffer, NULL, false))<=0){
		free(buffer);
		return retVal;
	}
	if(strstr(buffer,"{\"error")!=NULL){
		OCl_set_error(ocl, strstr(buffer,"{\"error"));
		free(buffer);
		if(load) return OCL_ERR_LOADING_MODEL;
		return OCL_ERR_UNLOADING_MODEL;
	}
	if(strstr(buffer,"200 OK")!=NULL){
		free(buffer);
		return OCL_RETURN_OK;
	}
	if(strstr(buffer," 503 ")!=NULL){
		free(buffer);
		return OCL_ERR_SERVICE_UNAVAILABLE;
	}
	free(buffer);
	if(load) return OCL_ERR_LOADING_MODEL;
	return OCL_ERR_UNLOADING_MODEL;
}

int OCl_get_models(OCl *ocl, char ***models){
	char body[1024]="", msg[2048]="";
	snprintf(msg,2048,
			"GET /api/tags HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Content-Type: application/json\r\n"
			"Content-Length: %d\r\n\r\n"
			"%s",ocl->srvAddr,(int) strlen(body), body);
	char *buffer=NULL;
	int retVal=0;
	if((retVal=send_message(ocl, msg, &buffer, NULL, false))<=0){
		free(buffer);
		return retVal;
	}
	if(strstr(buffer,"{\"error")!=NULL){
		OCl_set_error(ocl, strstr(buffer,"{\"error"));
		free(buffer);
		return OCL_ERR_GETTING_MODELS;
	}
	if(strstr(buffer," 503 ")!=NULL){
		free(buffer);
		return OCL_ERR_SERVICE_UNAVAILABLE;
	}
	int cantModels=get_string_from_token(buffer, "\"name\":", models, ',');
	free(buffer);
	return cantModels;
}
