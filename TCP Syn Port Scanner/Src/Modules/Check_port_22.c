/*
 ============================================================================
 Name        : Check_port_22.c
 Author      : L.
 Version     : 1.0.4
 Copyright   : GNU General Public License v3.0
 Description : Check Port 22
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

#define LIBSSH2_INIT_NO_CRYPTO 0x0001

int check_port_22(in_addr_t ip, int port){
	printf("%s", DEFAULT);
	const char *username = "Admin";
	const char *password = "Admin";
	char *userauthlist;
	int auth_pw = 0, rc;
	LIBSSH2_SESSION *session;
	printf("%s",HBLUE);
	printf("\nTrying Admin/Admin login...\n");
	printf("%s",BLUE);
	rc = libssh2_init(0);
	if(rc != 0) {
		printf("libssh2 initialization failed (%d)\n", rc);
		return 1;
	}
	int sk=socket(AF_INET,SOCK_STREAM, 0);
	if(sk<0){
		printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port=htons(port);
	serverAddress.sin_addr.s_addr= ip;
	if(connect(sk, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0){
		printf("Send message connection error. Error message: %s (%d)\n", strerror(errno),errno);
		return -1;
	}
	session = libssh2_session_init();
	if(libssh2_session_handshake(session, sk)) {
		printf("Failure establishing SSH session: %s (%d)\n", strerror(errno),errno);
		return -1;
	}
	const char *fingerprint;
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	printf("Fingerprint: ");
	for(int i = 0; i < 20; i++) {
		printf("%02X ", (unsigned char)fingerprint[i]);
	}
	printf("\n");
	userauthlist = libssh2_userauth_list(session, username, strlen(username));
	printf("Authentication methods supported: %s\n", userauthlist);
	if(strstr(userauthlist, "password") != NULL) auth_pw |= 1;
	if(strstr(userauthlist, "keyboard-interactive") != NULL) auth_pw |= 2;
	if(strstr(userauthlist, "publickey") != NULL) auth_pw |= 4;
	if(auth_pw & 1) {
		if(libssh2_userauth_password(session, username, password)) {
			printf("Authentication by password failed\n");
			goto shutdown;
		}
		else {
			printf("%s",HRED);
			printf("Authentication by password succeeded.\n");
			printf("Service Vulnerable\n\n");
		}
	}else if(auth_pw & 2) {
		printf("Authentication by keyboard not implemented\n");
		return -1;
	}else if(auth_pw & 4) {
		printf("Authentication by keyboard not implemented\n");
		return -1;
	}
	else {
		printf("No supported authentication methods found\n");
		goto shutdown;
	}
	shutdown:
	libssh2_session_disconnect(session, "");
	libssh2_session_free(session);
	printf("%s", DEFAULT);
	printf("\n");
	close(sk);
	return 0;
}
