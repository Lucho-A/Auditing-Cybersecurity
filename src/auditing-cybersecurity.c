/*
 ============================================================================
 Name        : main.c
 Author      : L.
 Version     : 1.2.8
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
#include <pcap.h>
#include <readline/readline.h>
#include "auditing-cybersecurity.h"
#include "activities/activities.h"
#include "others/networking.h"

struct LastestError lastActivityError;
struct ServerTarget target;
struct NetworkInfo networkInfo;
int portUnderHacking=0;
Bool cancelCurrentProcess=FALSE;
Bool canceledBySignal=FALSE;
pcap_t *arpHandle=NULL;
char *resourcesLocation=NULL;
long int sendPacketPerPortDelayUs=SEND_PACKET_PER_PORT_DELAY_US;

static void signal_handler(int signalType){
	printf("%s\n\n",C_DEFAULT);
	switch(signalType){
	case SIGINT:
	case SIGTSTP:
		printf("  Canceling...\n");
		cancelCurrentProcess=TRUE;
		if(arpHandle!=NULL) pcap_breakloop(arpHandle);
		break;
	case SIGPIPE:
		show_message("SIGPIPE babyyy...", 0, 0, ERROR_MESSAGE, TRUE);
		break;
	default:
		break;
	}
	canceledBySignal=TRUE;
}

static int closeMrAnderson(){
	printf("%s\n",C_DEFAULT);
	if(resourcesLocation!=NULL) free(resourcesLocation);
	return RETURN_OK;
}

static int readline_input(FILE *stream){
	int c=fgetc(stream);
	switch(c){
	case -1:
	case 4:
		return 13;
		break;
	default:
		break;
	}
	return c;
}

static int initMrAnderson(){
	signal(SIGINT, signal_handler);
	signal(SIGTSTP, signal_handler);
	signal(SIGPIPE, signal_handler);
	SSL_library_init();
	libssh2_init(0);
	rl_getc_function=readline_input;
	if(resourcesLocation==NULL){
		resourcesLocation=malloc(strlen(PATH_TO_RESOURCES)+1);
		snprintf(resourcesLocation, sizeof(PATH_TO_RESOURCES)+1,"%s", PATH_TO_RESOURCES);
	}
	return init_networking();
}

int main(int argc, char *argv[]){
	show_intro(PROGRAM_NAME, PROGRAM_VERSION);
	Bool noIntro=FALSE, discover=FALSE;
	char urlIp[255]="", msgError[BUFFER_SIZE_512B]="";
	int singlePortToScan=0;
	target.cantPortsToScan=0;
	for(int i=1;i<argc;i++){
		if(strcmp(argv[i],"-v")==0 || strcmp(argv[i],"--version")==0){
			PRINT_RESET;
			exit(EXIT_SUCCESS);
		}
		if(strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0){
			show_help("");
			closeMrAnderson();
			exit(EXIT_FAILURE);
		}
		if(strcmp(argv[i],"-d")==0 || strcmp(argv[i],"--discover")==0){
			discover=TRUE;
			continue;
		}
		if(strcmp(argv[i],"-t")==0 || strcmp(argv[i],"--target")==0){
			if(i==argc-1){
				show_help("\nTarget not specified\n");
				exit(EXIT_SUCCESS);
			}
			snprintf(urlIp,sizeof(urlIp),"%s",argv[i+1]);
			i++;
			continue;
		}
		if(strcmp(argv[i],"-P")==0 || strcmp(argv[i],"--ports")==0){
			if(i==argc-1){
				show_help("\nQuantity of ports not specified\n");
				exit(EXIT_SUCCESS);
			}
			if(strtol(argv[i+1],NULL,10)>0 && strtol(argv[i+1],NULL,10)<MAX_PORTS_TO_SCAN){
				target.cantPortsToScan=strtol(argv[i+1],NULL,10);
				i++;
				continue;
			}
			show_help("\nYou must enter a valid number of ports to be scanned (1-5000)\n");
			exit(EXIT_SUCCESS);
		}
		if(strcmp(argv[i],"-a")==0 || strcmp(argv[i],"--all")==0){
			target.cantPortsToScan=ALL_PORTS;
			continue;
		}
		if(strcmp(argv[i],"-p")==0 || strcmp(argv[i],"--port")==0){
			if(i==argc-1){
				show_help("\nPort not specified\n");
				exit(EXIT_SUCCESS);
			}
			if(strtol(argv[i+1],NULL,10)>0 && strtol(argv[i+1],NULL,10)<ALL_PORTS){
				target.cantPortsToScan=1;
				singlePortToScan=strtol(argv[i+1],NULL,10);
				i++;
				continue;
			}
			show_help("\nPort number not valid (0-65535)\n");
			exit(EXIT_SUCCESS);
		}
		if(strcmp(argv[i],"-n")==0 || strcmp(argv[i],"--no-intro")==0){
			noIntro=TRUE;
			continue;
		}
		if(strcmp(argv[i],"-r")==0 || strcmp(argv[i],"--resources-location")==0){
			if(i==argc-1){
				show_help("\nResource location not specified\n");
				exit(EXIT_SUCCESS);
			}
			resourcesLocation=malloc(strlen(argv[i+1])+1);
			snprintf(resourcesLocation,strlen(argv[i+1])+1,"%s",argv[i+1]);
			i++;
			continue;
		}
		if(strcmp(argv[i],"-s")==0 || strcmp(argv[i],"--scan-delay")==0){
			if(i==argc-1){
				show_help("\nScan delay value not specified\n");
				exit(EXIT_SUCCESS);
			}
			if(strtol(argv[i+1],NULL,10)>0 && strtol(argv[i+1],NULL,10)>0){
				sendPacketPerPortDelayUs=strtol(argv[i+1],NULL,10);
				i++;
				continue;
			}
			show_help("\nScan delay value not valid (0-INF)\n");
			exit(EXIT_SUCCESS);
		}
		snprintf(msgError,sizeof(msgError),"\nArgument %s not recognized\n",argv[i]);
		show_help(msgError);
		closeMrAnderson();
		exit(EXIT_FAILURE);
	}
	if(strcmp(urlIp,"")==0 && !discover){
		show_help("\nYou must enter the url|ip to be scanned\n");
		closeMrAnderson();
		exit(EXIT_FAILURE);
	}
	if(resourcesLocation==NULL && !discover){
		show_help("\nYou must enter the resource folder path.\n");
		closeMrAnderson();
		exit(EXIT_FAILURE);
	}
	if(!noIntro) show_intro_banner();
	if(initMrAnderson()==RETURN_ERROR){
		closeMrAnderson();
		error_handling(0,TRUE);
	}
	printf("\nChecking updates: ");
	int latestVersion=check_updates();
	if(latestVersion==RETURN_ERROR){
		printf("%s%s\n",C_HRED,"connection error");
		PRINT_RESET;
		printf("Internet connection: %sno",C_HRED);
	}else{
		if(latestVersion){
			printf("%sup-to-date\n",C_HGREEN);
		}else{
			printf("%sout-of-date. You can execute 'auditing-cybersecurity --update' or download the latest version from: https://github.com/Lucho-A/Auditing-Cybersecurity/releases/tag/Latest\n",C_HRED);
		}
		PRINT_RESET;
		printf("Internet connection: %sOK",C_HGREEN);
	}
	PRINT_RESET;
	time_t timestamp = time(NULL);
	struct tm tm = *localtime(&timestamp);
	char strTimeStamp[50]="";
	snprintf(strTimeStamp,sizeof(strTimeStamp),"%d/%02d/%02d %02d:%02d:%02d UTC:%s",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone);
	printf("%s\nStarting: %s\n",C_DEFAULT,strTimeStamp);
	if(discover){
		if(others(OTHERS_ARP_DISCOVER_D)==RETURN_ERROR) error_handling(0,TRUE);
		closeMrAnderson();
		exit(EXIT_SUCCESS);
	}
	if(scan_init(urlIp)==RETURN_ERROR) error_handling(0,TRUE);
	if(target.cantPortsToScan!=0) if(scan_ports(singlePortToScan, TRUE)==RETURN_ERROR) error_handling(0,TRUE);
	if(hack_port_request()==RETURN_ERROR) error_handling(0,TRUE);
	closeMrAnderson();
	exit(EXIT_SUCCESS);
}

