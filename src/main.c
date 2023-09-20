/*
 ============================================================================
 Name        : main.c
 Author      : L.
 Version     : 1.1.2
 Copyright   : GNU General Public License v3.0
 Description : Main file
 ============================================================================
*/

#include <stdlib.h>
#include <libssh2.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <openssl/ssl.h>
#include "auditing-cybersecurity.h"
#include "activities/activities.h"
#include "others/networking.h"

struct LastestError lastActivityError;
struct ServerTarget target;
struct NetworkInfo networkInfo;
int singlePortToScan=0;
int portUnderHacking=0;
Bool cancelCurrentProcess=0;
Bool canceledBySignal=0;
pcap_t *arpHandle=NULL;

static void signal_handler(int signalType){
	printf("\b\b  %s\n",C_DEFAULT);
	switch(signalType){
	case SIGINT:
	case SIGTSTP:
		printf("  Cancelling...\n");
		cancelCurrentProcess=TRUE;
		if(arpHandle!=NULL) pcap_breakloop(arpHandle);
		break;
	case SIGPIPE:
		//show_message("SIGPIPE babyyy...", 0, ERROR_MESSAGE, TRUE);
		break;
	default:
		break;
	}
	canceledBySignal=TRUE;
}

static int initMrAnderson(){
	signal(SIGINT, signal_handler);
	signal(SIGTSTP, signal_handler);
	signal(SIGPIPE, signal_handler);
	//rl_initialize();
	SSL_library_init();
	libssh2_init(0);
	return init_networking();
}

int main(int argc, char *argv[]){
	show_intro(PROGRAM_NAME, PROGRAM_VERSION);
	Bool argOK=FALSE, noIntro=FALSE, discover=FALSE, updateProgram=FALSE;
	char urlIp[16]="", msgError[BUFFER_SIZE_512B]="";
	for(int i=1;i<argc;i++){
		if(i==1){
			if(strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0) continue;
			if(strcmp(argv[i],"-u")==0 || strcmp(argv[i],"--update")==0){
				if(getuid()!=0) return show_message("You must be root for updating.\n", 0, 0, ERROR_MESSAGE, TRUE);
				updateProgram=noIntro=argOK=TRUE;
				continue;
			}
			if(strcmp(argv[i],"-d")==0 || strcmp(argv[i],"--discover")==0){
				discover=argOK=TRUE;
				continue;
			}
			if(argc==2){
				snprintf(msgError,sizeof(msgError),"\nYou must enter, at least, the url|ip and the number of ports to be scanned\n");
				break;
			}
			snprintf(urlIp,sizeof(urlIp),"%s",argv[i]);
			continue;
		}
		if(i==2 && !argOK){
			if(strtol(argv[i],NULL,10)>0 && strtol(argv[i],NULL,10)<MAX_PORTS_TO_SCAN){
				target.cantPortsToScan=strtol(argv[i],NULL,10);
				argOK=TRUE;
				continue;
			}
			if(strcmp(argv[i],"-a")==0 || strcmp(argv[i],"--all")==0){
				target.cantPortsToScan=ALL_PORTS;
				argOK=TRUE;
				continue;
			}
			if(strcmp(argv[i],"-p")==0 || strcmp(argv[i],"--port")==0){
				if(strtol(argv[i+1],NULL,10)>0 && strtol(argv[i],NULL,10)<ALL_PORTS){
					target.cantPortsToScan=1;
					singlePortToScan=strtol(argv[i+1],NULL,10);
					i++;
					argOK=TRUE;
					continue;
				}
			}
			snprintf(msgError,sizeof(msgError),"\nYou must enter a valid number of ports to be scanned (1-5000 | -a)\n");
			argOK=FALSE;
			break;
		}
		if(strcmp(argv[i],"-n")==0 || strcmp(argv[i],"--no-intro")==0){
			noIntro=TRUE;
			continue;
		}
		snprintf(msgError,sizeof(msgError),"\nArgument %s not recognized\n",argv[i]);
		argOK=FALSE;
		break;
	}
	if(!argOK){
		show_help(msgError);
		exit(EXIT_FAILURE);
	}
	if(!noIntro) show_intro_banner();
	if(updateProgram){
		if(update()==RETURN_ERROR){
			printf("\n%sUpdating error. %s.\n",C_HRED,strerror(errno));
			PRINT_RESET;
		}
		exit(EXIT_SUCCESS);
	}
	printf("\nChecking updates: ");
	int latestVersion=check_updates();
	if(latestVersion==RETURN_ERROR){
		printf("%s%s.\n",C_HRED,strerror(errno));
	}else{
		if(latestVersion){
			printf("%sup-to-date\n",C_HGREEN);
		}else{
			printf("%sout-of-date.%s You can execute 'auditing-cybersecurity --update' or download the latest version from: https://github.com/Lucho-A/Auditing-Cybersecurity/releases/tag/Latest\n",C_HRED,C_DEFAULT);
		}
	}
	time_t timestamp = time(NULL);
	struct tm tm = *localtime(&timestamp);
	char strTimeStamp[50]="";
	snprintf(strTimeStamp,sizeof(strTimeStamp),"%d/%02d/%02d %02d:%02d:%02d UTC:%s",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone);
	printf("%s\nStarting: %s\n\n",C_DEFAULT,strTimeStamp);
	if(initMrAnderson()==RETURN_ERROR) error_handling(TRUE);
	if(discover){
		if(others(OTHERS_ARP_DISCOVER_D)==RETURN_ERROR) error_handling(TRUE);
		printf("%s",C_DEFAULT);
		exit(EXIT_SUCCESS);
	}
	if(scan_init(urlIp)==RETURN_ERROR) error_handling(TRUE);
	if(scan_ports()==RETURN_ERROR) error_handling(TRUE);
	if(hack_port_request()==RETURN_ERROR) error_handling(TRUE);
	printf("%s\n",C_DEFAULT);
	exit(EXIT_SUCCESS);
}

