
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include "../auditing-cybersecurity.h"
#include "../activities/activities.h"

struct BfaInfo bfaInfo;
int contUsersAndPasswords=0;

void *bfa_check_users(void *arg){
	struct ThreadInfo *tinfo=arg;
	int posF=ceil(bfaInfo.totalUsernames/tinfo->totalThreads),cont=0,posI=tinfo->threadID*posF;
	if(tinfo->threadID==tinfo->totalThreads-1) posF=bfaInfo.totalUsernames;
	Bool again=FALSE,nextI=FALSE;
	for(int i=posI;i<bfaInfo.totalUsernames && cont<posF && !cancelCurrentProcess;i++,cont++){
		nextI=FALSE;
		for(int j=0;j<bfaInfo.totalPasswords && !cancelCurrentProcess;j++,contUsersAndPasswords++){
			usleep(rand()%1000 + 1000);
			printf("\r  Percentage completed: %.4lf%% (%d/%.0f)",(double)((contUsersAndPasswords/(bfaInfo.totalUsernames*bfaInfo.totalPasswords))*100.0),contUsersAndPasswords, (bfaInfo.totalUsernames*bfaInfo.totalPasswords));
			fflush(stdout);
			if(nextI) continue;
			do{
				again=FALSE;
				int resp=FALSE;
				switch(tinfo->service){
				case FTP_BFA:
					resp=ftp_check_user(bfaInfo.usernames[i], bfaInfo.passwords[j]);
					break;
				case SSH_BFA:
					resp=ssh_check_user(bfaInfo.usernames[i], bfaInfo.passwords[j]);
					break;
				case MSSQL_BFA:
					resp=mssql_check_user(bfaInfo.usernames[i], bfaInfo.passwords[j]);
					break;
				case MYSQL_BFA:
					resp=mysql_check_user(bfaInfo.usernames[i], bfaInfo.passwords[j]);
					break;
				case ORACLE_BFA:
					resp=oracle_check_user(bfaInfo.usernames[i], bfaInfo.passwords[j]);
					break;
				case POSTGRES_BFA:
					resp=postgres_check_user(bfaInfo.usernames[i], bfaInfo.passwords[j]);
					break;
				case SMB_BFA:
					resp=smb_check_user(bfaInfo.usernames[i], bfaInfo.passwords[j]);
					break;
				}
				switch(resp){
				case TRUE:
					printf(REMOVE_LINE);
					printf("  %sUser found: %s%s/%s%s",C_HWHITE,C_HRED,bfaInfo.usernames[i],bfaInfo.passwords[j],C_DEFAULT);
					printf("\n\n"REMOVE_LINE);
					nextI=TRUE;
					break;
				case FALSE:
					break;
				case SSH_SOCKET_DISCONNECTION_ERROR:
					again=TRUE;
					break;
				default:
					cancelCurrentProcess=TRUE;
					pthread_exit(NULL);
				}
			}while(again && !cancelCurrentProcess);
		}
	}
	pthread_exit(NULL);
}

int bfa_init(int threadsDefault, char *usernamesFile, char *passwordFile, int service){
	contUsersAndPasswords=0;
	read_usernames_and_password_files(&bfaInfo, usernamesFile, passwordFile);
	int tThreads=0;
	if(threadsDefault!=0){
		tThreads=request_quantity_threads(threadsDefault);
		PRINT_RESET;
	}else{
		tThreads=1;
	}
	struct ThreadInfo *tInfo=(struct ThreadInfo *) malloc(tThreads * sizeof(struct ThreadInfo));
	pthread_t *bfaThreads=(pthread_t *) malloc(tThreads * sizeof(pthread_t));
	for(int i=0;i<tThreads;i++){
		tInfo[i].threadID=i;
		tInfo[i].totalThreads=tThreads;
		tInfo[i].service=service;
		usleep(10000);
		pthread_create(&bfaThreads[i], NULL, &bfa_check_users, &tInfo[i]);
	}
	for(int i=0;i<tThreads;i++) pthread_join(bfaThreads[i], NULL);
	PRINT_RESET;
	for(int i=0;i<bfaInfo.totalUsernames;i++) free(bfaInfo.usernames[i]);
	for(int i=0;i<bfaInfo.totalPasswords;i++) free(bfaInfo.passwords[i]);
	free(tInfo);
	free(bfaThreads);
	if(cancelCurrentProcess) return RETURN_ERROR;
	return RETURN_OK;
}
