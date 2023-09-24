
#include <libssh2.h>
#include <unistd.h>
#include "../auditing-cybersecurity.h"
#include "activities.h"
#include "../others/networking.h"

#define LIBSSH2_INIT_NO_CRYPTO 0x0001

static int create_ssh_connection(LIBSSH2_SESSION **sshConn, int *socketConn){
	if((*sshConn=libssh2_session_init())==NULL) return set_last_activity_error(SSH_INIT_ERROR,"");
	libssh2_session_set_timeout(*sshConn, SSH_TIMEOUT_MS);
	libssh2_session_banner_set(*sshConn,"SSH-2.0-OpenSSH_for_Windows_8.1");
	if(libssh2_session_handshake(*sshConn, *socketConn)<0) return set_last_activity_error(SSH_HANDSHAKE_ERROR,"");
	return RETURN_OK;
}

int ssh_check_user(char *username, char *password){
	LIBSSH2_SESSION *sshSessionConn=NULL;
	int sk=0;
	if((create_socket_conn(&sk))<0) return set_last_activity_error(SOCKET_CREATION_ERROR,"");
	int valResp=0;
	if((valResp=create_ssh_connection(&sshSessionConn,&sk))<0){
		libssh2_session_free(sshSessionConn);
		return set_last_activity_error(valResp,"");
	}
	valResp=libssh2_userauth_password(sshSessionConn, username, password);
	libssh2_session_disconnect(sshSessionConn,"");
	libssh2_session_free(sshSessionConn);
	close(sk);
	switch(valResp){
	case 0:
		return TRUE;
	case LIBSSH2_ERROR_AUTHENTICATION_FAILED:
		return FALSE;
	case LIBSSH2_ERROR_SOCKET_DISCONNECT:
		return SSH_SOCKET_DISCONNECTION_ERROR;
	case LIBSSH2_ERROR_TIMEOUT:
	default:
		return RETURN_ERROR;
	}
}

int ssh(int type){
	if(target.portsToScan[get_port_index(portUnderHacking)].connectionType!=SSH_CONN_TYPE){
		return show_message("SSH not supported for this port (or couldn't create a connection because the IP was locked)",0, 0, ERROR_MESSAGE, FALSE);
	}
	char cmd[BUFFER_SIZE_1K]="";
	switch(type){
	case SSH_BFA:
		return bfa_init(1, "usernames_ssh.txt", "passwords_ssh.txt",SSH_BFA);
		break;
	case SSH_FINGER_PRINTING:
		LIBSSH2_SESSION *sshSessionConn=NULL;
		char *userauthlist="";
		int sshSocket=0;
		if((sshSocket=socket(AF_INET,SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR,"");
		setsockopt(sshSocket, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
		struct sockaddr_in serverAddress;
		serverAddress.sin_family = AF_INET;
		serverAddress.sin_port=htons(portUnderHacking);
		serverAddress.sin_addr.s_addr= target.targetIp.s_addr;
		if(connect(sshSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0) return set_last_activity_error(SOCKET_CONNECTION_ERROR,"");
		if((sshSessionConn = libssh2_session_init())==NULL){
			libssh2_session_free(sshSessionConn);
			return set_last_activity_error(SSH_HANDSHAKE_ERROR,"");
		}
		libssh2_session_set_timeout(sshSessionConn, SSH_TIMEOUT_MS);
		libssh2_session_banner_set(sshSessionConn,"SSH-2.0-OpenSSH_for_Windows_8.1");
		if(libssh2_session_handshake(sshSessionConn, sshSocket)<0) return set_last_activity_error(SSH_HANDSHAKE_ERROR,"");
		libssh2_hostkey_hash(sshSessionConn, LIBSSH2_HOSTKEY_HASH_SHA1);
		printf("  Banner: ");
		show_message((char *) libssh2_session_banner_get(sshSessionConn),strlen((char *) libssh2_session_banner_get(sshSessionConn)), 0, INFO_MESSAGE, FALSE);
		size_t len;
		int type;
		const char *hostkey=libssh2_session_hostkey(sshSessionConn, &len, &type);
		if(hostkey!=NULL){
			char hostkeyTypeMsg[BUFFER_SIZE_512B]="";
			switch(type){
			case LIBSSH2_HOSTKEY_TYPE_UNKNOWN:
				snprintf(hostkeyTypeMsg, sizeof(hostkeyTypeMsg), "Unknown (lenght: %lu)", len);
				break;
			case LIBSSH2_HOSTKEY_TYPE_RSA:
				snprintf(hostkeyTypeMsg, sizeof(hostkeyTypeMsg), "RSA (lenght: %lu)", len);
				break;
			case LIBSSH2_HOSTKEY_TYPE_DSS:
				snprintf(hostkeyTypeMsg, sizeof(hostkeyTypeMsg), "DSS (lenght: %lu)", len);
				break;
			case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
				snprintf(hostkeyTypeMsg, sizeof(hostkeyTypeMsg), "ECDSA256 (lenght: %lu)", len);
				break;
			case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
				snprintf(hostkeyTypeMsg, sizeof(hostkeyTypeMsg), "ECDSA384 (lenght: %lu)", len);
				break;
			case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
				snprintf(hostkeyTypeMsg, sizeof(hostkeyTypeMsg), "ECDSA521 (lenght: %lu)", len);
				break;
			case LIBSSH2_HOSTKEY_TYPE_ED25519:
				snprintf(hostkeyTypeMsg, sizeof(hostkeyTypeMsg), "ED25519 (lenght: %lu)", len);
				break;
			default:
				snprintf(hostkeyTypeMsg, sizeof(hostkeyTypeMsg), "Unknown");
				break;
			}
			printf("\n\n  Algorithm: ");
			show_message(hostkeyTypeMsg,strlen(hostkeyTypeMsg), 0, INFO_MESSAGE,FALSE);
		}
		const char *fingerprint=libssh2_hostkey_hash(sshSessionConn, LIBSSH2_HOSTKEY_HASH_SHA1);
		printf("\n\n  Hash: ");
		printf("%s",C_HWHITE);
		for(int i=0;i<20;i++) printf("%02X ", (unsigned char)fingerprint[i]);
		printf("%s\n",C_DEFAULT);
		userauthlist = libssh2_userauth_list(sshSessionConn, "anyUser", strlen("anyUser"));
		printf("\n  Authentication methods allowed: ");
		if(userauthlist==NULL) userauthlist="Failure -no authentication methods found (!?)-";
		show_message(userauthlist,strlen(userauthlist), 0, INFO_MESSAGE,FALSE);
		libssh2_session_free(sshSessionConn);
		break;
	case SSH_USER_ENUM:
		char userFilePath[BUFFER_SIZE_512B]="";
		snprintf(userFilePath, sizeof(userFilePath),"%s%s", resourcesLocation, "msf_users.txt");
		snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'use scanner/ssh/ssh_enumusers;set RHOSTS %s; "
				"set RPORT %d; set USER_FILE %s;run; exit'",target.strTargetIp, portUnderHacking, userFilePath);
		system_call(cmd);
		break;
	case USER_GUEST_SSH:
		//TODO
		break;
	case SSH_RUN_JUNIPER_BACKDOOR:
		snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'use auxiliary/scanner/ssh/juniper_backdoor;set RHOSTS %s; set RPORT %d; run; exit'", target.strTargetIp,portUnderHacking);
		system_call(cmd);
		break;
	default:
		break;
	}
	PRINT_RESET;
	return RETURN_OK;
}

