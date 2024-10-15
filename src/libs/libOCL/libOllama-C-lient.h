/*
 ============================================================================
 Name        : libOllama-C-lient.h
 Author      : L. (lucho-a.github.io)
 Version     : 0.0.1
 Created on	 : 204/04/19
 Copyright   : GNU General Public License v3.0
 Description : Header file
 ============================================================================
 */

#ifndef HEADERS_LIBOLLAMA_C_LIENT_H_
#define HEADERS_LIBOLLAMA_C_LIENT_H_

#include <stdbool.h>

#define OCL_RETURN_ERROR 						-1
#define OCL_RETURN_OK 							0

#define OCL_NAME 								"libOCl"
#define OCL_MAJOR_VERSION						"0"
#define OCL_MINOR_VERSION						"0"
#define OCL_MICRO_VERSION						"1"
#define OCL_VERSION								PROGRAM_MAJOR_VERSION"."PROGRAM_MINOR_VERSION"."PROGRAM_MICRO_VERSION
#define OCL_DESCRIPTION							"C library for interacting with Ollama server"

#define OCL_DBG									printf("\nWTFFF?!?!\n");

#define OCL_OLLAMA_SERVER_ADDR					"127.0.0.1"
#define OCL_OLLAMA_SERVER_PORT					"443"

#define	OCL_RESPONSE_SPEED						"15000"

#define OCL_SOCKET_CONNECT_TIMEOUT_S			"5"
#define OCL_SOCKET_SEND_TIMEOUT_S				"5"
#define OCL_SOCKET_RECV_TIMEOUT_S				"15"

#define OCL_MAX_HISTORY_CONTEXT					"3"
#define OCL_TEMP								"0.5"
#define OCL_MAX_TOKENS							"2048"
#define OCL_NUM_CTX								"2048"

enum ocl_errors{
	OCL_ERR_INIT_ERROR=-50,
	OCL_ERR_MALLOC_ERROR,
	OCL_ERR_REALLOC_ERROR,
	OCL_ERR_GETTING_HOST_INFO_ERROR,
	OCL_ERR_SOCKET_CREATION_ERROR,
	OCL_ERR_SOCKET_CONNECTION_ERROR,
	OCL_ERR_SOCKET_CONNECTION_TIMEOUT_ERROR,
	OCL_ERR_SSLCTX_NULL_ERROR,
	OCL_ERR_SSL_CONTEXT_ERROR,
	OCL_ERR_SSL_CERT_NOT_FOUND,
	OCL_ERR_SSL_FD_ERROR,							//-40
	OCL_ERR_SSL_CONNECT_ERROR,
	OCL_ERR_SOCKET_SEND_TIMEOUT_ERROR,
	OCL_ERR_SENDING_PACKETS_ERROR,
	OCL_ERR_POLLIN_ERROR,
	OCL_ERR_SOCKET_RECV_TIMEOUT_ERROR,
	OCL_ERR_RECV_TIMEOUT_ERROR,
	OCL_ERR_RECEIVING_PACKETS_ERROR,
	OCL_ERR_RESPONSE_MESSAGE_ERROR,
	OCL_ERR_PARTIAL_RESPONSE_RECV,
	OCL_ERR_ZEROBYTESSENT_ERROR,					//-30
	OCL_ERR_ZEROBYTESRECV_ERROR,
	OCL_ERR_MODEL_FILE_NOT_FOUND,
	OCL_ERR_CONTEXT_FILE_NOT_FOUND,
	OCL_ERR_CERT_FILE_NOT_FOUND,
	OCL_ERR_OPENING_FILE_ERROR,
	OCL_ERR_OPENING_ROLE_FILE_ERROR,
	OCL_ERR_NO_HISTORY_CONTEXT_ERROR,
	OCL_ERR_UNEXPECTED_JSON_FORMAT_ERROR,
	OCL_ERR_CONTEXT_MSGS_ERROR,
	OCL_ERR_NULL_STRUCT_ERROR,
	OCL_ERR_SERVICE_UNAVAILABLE,
	OCL_ERR_GETTING_MODELS,
	OCL_ERR_LOADING_MODEL,
	OCL_ERR_UNLOADING_MODEL,
	OCL_ERR_SERVER_ADDR,
	OCL_ERR_PORT,
	OCL_ERR_TEMP,
	OCL_ERR_MAX_MSG_CTX,
	OCL_ERR_MAX_TOKENS_CTX,
	OCL_ERR_MAX_TOKENS,
	OCL_ERR_SOCKET_CONNECTION_TIMEOUT_NOT_VALID,
	OCL_ERR_SOCKET_SEND_TIMEOUT_NOT_VALID,
	OCL_ERR_SOCKET_RECV_TIMEOUT_NOT_VALID,
	OCL_ERR_RESPONSE_SPEED_NOT_VALID
};

typedef struct _ocl OCl;

extern bool ocl_canceled;

int OCl_init();
int OCl_get_instance(OCl **, char *, char *, char *, char *, char *, char *, char *, char *,
		char *,char *, char *, char *, char *, char *);
int OCl_free(OCl *);

int OCl_flush_context();
int OCl_load_model(OCl *, bool load);
int OCl_send_chat(OCl *, char *);
int OCl_check_service_status(OCl *);
int OCl_import_context(OCl *);
char * OCL_error_handling(int);

int OCl_get_models(OCl *, char ***);
char * OCl_get_model(OCl *);
double OCL_get_response_load_duration(OCl *);
double OCL_get_response_prompt_eval_duration(OCl *);
double OCL_get_response_eval_duration(OCl *);
double OCL_get_response_total_duration(OCl *);
int OCL_get_response_prompt_eval_count(OCl *);
int OCL_get_response_eval_count(OCl *);
double OCL_get_response_tokens_per_sec(OCl *);
char * OCL_get_response_error(OCl *);

int OCl_set_model(OCl *, char *);
int OCl_set_role(OCl *, char *);

#endif /* HEADERS_LIBOLLAMA_C_LIENT_H_ */
