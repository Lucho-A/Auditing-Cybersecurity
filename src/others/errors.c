
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "../auditing-cybersecurity.h"

int set_last_activity_error(int errorType, char const *errorAditionalDescription){
	lastActivityError.errorType=errorType;
	snprintf(lastActivityError.errorAditionalDescription,sizeof(lastActivityError.errorAditionalDescription),"%s",errorAditionalDescription);
	return RETURN_ERROR;
}

int error_handling(int errorType, bool exitProgram){
	char errorMsg[BUFFER_SIZE_1K]="", errorDescription[BUFFER_SIZE_256B]="";
	if(errorType<0) lastActivityError.errorType=errorType;
	switch(lastActivityError.errorType){
	case RETURN_OK:
		return RETURN_OK;
	case SOCKET_CREATION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s","Error creating socket", strerror(errno));
		break;
	case SOCKET_CONNECTION_TIMEOUT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Connection error (timeouting)");
		break;
	case SOCKET_CONNECTION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Connection Error", strerror(errno));
		break;
	case SOCKET_CONNECTION_CLOSED_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Connection Closed", strerror(errno));
		break;
	case SOCKET_SETOPT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error setting socket options",strerror(errno));
		break;
	case SOCKET_SELECT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error socket select",strerror(errno));
		break;
	case SENDING_PACKETS_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error sending packets");
		break;
	case GETADDRINFO_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error getting address info");
		break;
	case MALLOC_ERROR:
	case REALLOC_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Malloc/Realloc error", strerror(errno));
		break;
	case RECEIVING_PACKETS_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error receiving packets");
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
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Device opening error");
		break;
	case SSL_FD_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "SSL setting fd error");
		break;
	case SSL_CONNECT_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "SSL connecting error");
		break;
	case UNKNOW_CONNECTION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Unknown connection");
		break;
	case POLLIN_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Pollin error", strerror(errno));
		break;
	case GETSOCKNAME_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Getting sockname error", strerror(errno));
		break;
	case INET_NTOP_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "INET_ntop error", strerror(errno));
		break;
	case HOSTNAME_TO_IP_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Unable to resolve hostname");
		break;
	case OPENING_PORT_FILE_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s", "Error opening port file");
		break;
	case OPENING_FILE_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error opening file", strerror(errno));
		break;
	case OPENING_SETTING_FILE_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error opening setting file", strerror(errno));
		break;
	case THREAD_CREATION_ERROR:
		snprintf(errorDescription, sizeof(errorDescription), "%s. %s", "Error creating thread", strerror(errno));
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
		break;
	}
	snprintf(errorMsg, sizeof(errorMsg), "%s. %s", errorDescription, lastActivityError.errorAditionalDescription);
	show_message(errorMsg,0, 0, ERROR_MESSAGE, true);
	if(exitProgram){
		PRINT_RESET;
		PRINT_RESET;
		exit(EXIT_FAILURE);
	}
	PRINT_RESET;
	return RETURN_ERROR;
}
