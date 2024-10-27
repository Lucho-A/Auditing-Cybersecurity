
#include <errno.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include "../auditing-cybersecurity.h"

int set_last_activity_error(int errorType, char const *errorAditionalDescription){
	lastActivityError.errorType=errorType;
	snprintf(lastActivityError.errorAditionalDescription,sizeof(lastActivityError.errorAditionalDescription),"%s",errorAditionalDescription);
	return RETURN_ERROR;
}

int error_handling(int errorType, bool exitProgram){
	char errorMsg[BUFFER_SIZE_1K]="", errorDescription[BUFFER_SIZE_512B]="";
	if(errorType<0) lastActivityError.errorType=errorType;
	if(lastActivityError.err==0) lastActivityError.err=errno;
	if(lastActivityError.sslErr==0) lastActivityError.sslErr=ERR_get_error();
	switch(lastActivityError.errorType){
	case RETURN_OK:
		return RETURN_OK;
	case SOCKET_CREATION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s","Error creating socket", strerror(lastActivityError.err));
		break;
	case SOCKET_CONNECTION_TIMEOUT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Connection error (timeouting)");
		break;
	case SOCKET_CONNECTION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Connection Error", strerror(lastActivityError.err));
		break;
	case SOCKET_CONNECTION_CLOSED_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Connection Closed", strerror(lastActivityError.err));
		break;
	case SOCKET_SETOPT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error setting socket options",strerror(lastActivityError.err));
		break;
	case SOCKET_SELECT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error socket select",strerror(lastActivityError.err));
		break;
	case SENDING_PACKETS_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s. %s", "Error sending packets",
				strerror(lastActivityError.err),ERR_error_string(lastActivityError.sslErr, NULL));
		break;
	case SENDING_PACKETS_TO_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Receiving packets timeout");
		break;
	case GETADDRINFO_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error getting address info",strerror(lastActivityError.err));
		break;
	case MALLOC_ERROR:
	case REALLOC_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Malloc/Realloc error", strerror(lastActivityError.err));
		break;
	case RECEIVING_PACKETS_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s. %s", "Error receiving packets",
				strerror(lastActivityError.err),ERR_error_string(lastActivityError.sslErr,NULL));
		break;
	case RECEIVING_PACKETS_TO_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Receiving packets timeout");
		break;
	case ZERO_BYTES_RECV_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "(Zero bytes received)");
		break;
	case DEVICE_NOT_FOUND_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Device not found");
		break;
	case DEVICE_MAC_NOT_FOUND_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Device MAC not found");
		break;
	case DEVICE_NOT_ETHERNET_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Device is not Ethernet");
		break;
	case DEVICE_OPENING_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Device opening error", strerror(lastActivityError.err));
		break;
	case SSL_FD_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "SSL setting fd error", ERR_error_string(ERR_get_error(), NULL));
		break;
	case SSL_CONNECT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "SSL connecting error", ERR_error_string(ERR_get_error(), NULL));
		break;
	case UNKNOW_CONNECTION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Unknown connection");
		break;
	case POLLIN_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Pollin error", strerror(lastActivityError.err));
		break;
	case GETSOCKNAME_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Getting sockname error", strerror(lastActivityError.err));
		break;
	case INET_NTOP_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "INET_ntop error", strerror(lastActivityError.err));
		break;
	case HOSTNAME_TO_IP_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Unable to resolve hostname", strerror(lastActivityError.err));
		break;
	case OPENING_PORT_FILE_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error opening port file");
		break;
	case OPENING_FILE_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error opening file", strerror(lastActivityError.err));
		break;
	case OPENING_SETTING_FILE_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error opening setting file", strerror(lastActivityError.err));
		break;
	case THREAD_CREATION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error creating thread", strerror(lastActivityError.err));
		break;
	case SSH_INIT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error init SSH session");
		break;
	case SSH_HANDSHAKE_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error creating SSH session");
		break;
	case FTP_CONNECTION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error creating FTP connection");
		break;
	case FTP_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "FTP Error");
		break;
	case MYSQL_CONNECTION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error creating MySQL connection");
		break;
	case SMB_CONTEXT_CREATION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error creating SMB context");
		break;
	case OLLAMA_SERVER_UNAVAILABLE:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Ollama server unavailable");
		break;
	default:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error not handled");
		break;
	}
	snprintf(errorMsg, sizeof(errorMsg), "%s. %s", errorDescription, lastActivityError.errorAditionalDescription);
	show_message(errorMsg,0, 0, ERROR_MESSAGE, true, false, false);
	if(lastActivityError.err==1) show_message("Are you root and/or any firewall restriction?", 0, 0, ERROR_MESSAGE, true, false, true);
	if(exitProgram){
		PRINT_RESET;
		PRINT_RESET;
		exit(EXIT_FAILURE);
	}
	PRINT_RESET;
	return RETURN_ERROR;
}
