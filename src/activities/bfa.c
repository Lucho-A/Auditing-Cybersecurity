
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "../auditing-cybersecurity.h"
#include "../activities/activities.h"

struct BfaInfo bfaInfo;
int contUsersAndPasswords=0;
bool onlyUserCheck=false;

bool ask_user_check_only(){
	char prompt[BUFFER_SIZE_512B]="";
	snprintf(prompt, BUFFER_SIZE_512B,"User checking, only?? [y|Y] (default: no):");
	do{
		char *userCheckOnly=get_readline(prompt, false);
		if(strcmp(userCheckOnly, "")==0){
			free(userCheckOnly);
			return false;
		}
		if(strcmp(userCheckOnly, "y")==0 || strcmp(userCheckOnly, "Y")==0){
			free(userCheckOnly);
			return true;
		}
		free(userCheckOnly);
	}while(true);
}

void *bfa_check_users(void *arg){
	struct ThreadInfo *tinfo=arg;
	int posF=ceil(bfaInfo.totalUsernames/tinfo->totalThreads),cont=0,posI=tinfo->threadID*posF;
	if(tinfo->threadID==tinfo->totalThreads-1) posF=bfaInfo.totalUsernames;
	bool again=false,nextI=false,isStdDevHomogeneous=false;
	struct timespec tInit, tEnd;
	int repeat=0, contLoginAttemps=0, contLogins=0;
	double avg=0.0, time=0.0, stdDev=0.0, cv=0.0,totalTime=0.0,totalVarianceNum=0.0;
	if(onlyUserCheck) repeat=3;
	do{
		for(int i=posI;i<bfaInfo.totalUsernames && cont<posF && !cancelCurrentProcess;i++,cont++){
			nextI=false;
			for(int j=0;j<bfaInfo.totalPasswords && !cancelCurrentProcess;j++){
				contUsersAndPasswords++;
				usleep(rand()%1000 + 1000);
				if(!onlyUserCheck){
					printf("\r  Percentage completed: %.4lf%% (%d/%.0f)",(double)((contUsersAndPasswords/(bfaInfo.totalUsernames*bfaInfo.totalPasswords))*100.0),
							contUsersAndPasswords, (bfaInfo.totalUsernames*bfaInfo.totalPasswords));
				}else{
					printf("\r  Percentage completed: %.4lf%% (%d/%.0f) (%.6f%%/%.6f/%.6f)",(double)((bfaInfo.totalUsernames/(bfaInfo.totalUsernames))*100.0),
							++contLogins, bfaInfo.totalUsernames, cv, time, avg);
				}
				fflush(stdout);
				if(nextI) continue;
				do{
					again=false;
					int resp=false;
					clock_gettime(CLOCK_MONOTONIC_RAW, &tInit);
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
					clock_gettime(CLOCK_MONOTONIC_RAW, &tEnd);
					switch(resp){
					case true:
						printf(REMOVE_LINE);
						printf("  %sUser found: %s%s/%s%s",C_HWHITE,C_HRED,bfaInfo.usernames[i],bfaInfo.passwords[j],C_DEFAULT);
						printf("\n\n"REMOVE_LINE);
						nextI=true;
						break;
					case false:
						break;
					case SSH_SOCKET_DISCONNECTION_ERROR:
						again=true;
						break;
					default:
						cancelCurrentProcess=true;
						pthread_exit(NULL);
					}
				}while(again && !cancelCurrentProcess);
				if(onlyUserCheck){
					time=(tEnd.tv_nsec-tInit.tv_nsec)/1000000000.0 + (tEnd.tv_sec-tInit.tv_sec);
					totalTime+=time;
					avg=totalTime/++contLoginAttemps;
					double dev=(time-avg)*(time-avg);
					totalVarianceNum+=dev;
					stdDev=pow(totalVarianceNum/contLoginAttemps,0.5);
					cv=(stdDev/avg)*100;
					(cv<10)?(isStdDevHomogeneous=true):(isStdDevHomogeneous=false);
					if(isStdDevHomogeneous && time>avg*1.2 && repeat==1){
						printf("\n\n%s  Warning: %s%s%s. Elapsed Time: %.6f, Avg. Time: %.6f. Standard Deviation: %.6f\n\n",
								C_HYELLOW, C_HWHITE, bfaInfo.usernames[i], C_DEFAULT, time, avg, stdDev);
					}
					break;
				}
			}
		}
		repeat--;
		cont=0;
		contLogins=0;
	}while(repeat>0);
	pthread_exit(NULL);
}

int bfa_init(int threadsDefault, char *usernamesFile, char *passwordFile, int service){
	onlyUserCheck=false;
	contUsersAndPasswords=0;
	read_usernames_and_password_files(&bfaInfo, usernamesFile, passwordFile);
	int tThreads=0;
	onlyUserCheck=ask_user_check_only();
	PRINT_RESET;
	if(threadsDefault!=0 && !onlyUserCheck){
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
