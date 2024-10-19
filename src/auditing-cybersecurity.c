/*
 ============================================================================
 Name        : main.c
 Author      : L.
 Version     : 1.3.0
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
OCl *ocl=NULL;
struct OllamaInfo oi;
int portUnderHacking=0;
bool cancelCurrentProcess=false;
bool canceledBySignal=false;
bool discover=false;
pcap_t *arpHandle=NULL;
char *resourcesLocation=NULL;
long int sendPacketPerPortDelayUs=SEND_PACKET_PER_PORT_DELAY_US;
SSL_CTX *sslCtx=NULL;
int prevInput=0;

static void signal_handler(int signalType){
	switch(signalType){
	case SIGINT:
	case SIGTSTP:
		printf("%s\n\n",C_DEFAULT);
		printf("  Canceling...\n");
		cancelCurrentProcess=true;
		canceledBySignal=true;
		oclCanceled=true;
		if(arpHandle!=NULL) pcap_breakloop(arpHandle);
		break;
	case SIGPIPE:
		break;
	default:
		break;
	}
}

static int closeMrAnderson(){
	PRINT_RESET
	SSL_CTX_free(sslCtx);
	if(resourcesLocation!=NULL) free(resourcesLocation);
	if(ocl!=NULL) OCl_load_model(ocl, false);
	return RETURN_OK;
}

static int readline_input(FILE *stream){
	int c=fgetc(stream);
	if(c==13 && prevInput==27){
		if(strlen(rl_line_buffer)==0){
			rl_done=true;
			return 13;
		}
		rl_insert_text("\n");
		prevInput=0;
		return 0;
	}
	if(c==8 && rl_point==0) return 0;
	if(c==9) rl_insert_text("\t");
	if(c==-1 || c==4){
		rl_delete_text(0,strlen(rl_line_buffer));
		return 13;
	}
	prevInput=c;
	return c;
}

static int initMrAnderson(){
	signal(SIGINT, signal_handler);
	signal(SIGTSTP, signal_handler);
	signal(SIGPIPE, signal_handler);
	lastActivityError.errorType=0;
	lastActivityError.blocked=false;
	if(!discover){
		SSL_library_init();
		if((sslCtx=SSL_CTX_new(TLS_method()))==NULL) return set_last_activity_error(SSL_CONTEXT_ERROR, "");
		libssh2_init(0);
		rl_getc_function=readline_input;
		FILE *f=NULL;
		int entries=open_file(resourcesLocation, "settings.txt", &f);
		if(entries<0) return set_last_activity_error(OPENING_SETTING_FILE_ERROR, "");
		int chars;
		size_t len;
		char *line=NULL;
		oi.ip=OCL_OLLAMA_SERVER_ADDR;
		oi.port=OCL_OLLAMA_SERVER_PORT;
		oi.temp=OCL_TEMP;
		oi.maxHistoryCtx=OCL_MAX_HISTORY_CTX;
		while((chars=getline(&line, &len, f))!=-1){
			if((strstr(line,"[OLLAMA_SERVER_ADDR]"))==line){
				chars=getline(&line, &len, f);
				oi.ip=malloc(chars+1);
				memset(oi.ip,0,chars+1);
				for(int i=0;i<chars-1;i++) oi.ip[i]=line[i];
				continue;
			}
			if((strstr(line,"[OLLAMA_SERVER_PORT]"))==line){
				chars=getline(&line, &len, f);
				oi.port=malloc(chars+1);
				memset(oi.port,0,chars+1);
				for(int i=0;i<chars-1;i++) oi.port[i]=line[i];
				continue;
			}
			if((strstr(line,"[OLLAMA_SERVER_MODEL]"))==line){
				chars=getline(&line, &len, f);
				oi.model=malloc(chars+1);
				memset(oi.model,0,chars+1);
				for(int i=0;i<chars-1;i++) oi.model[i]=line[i];
				continue;
			}
			if((strstr(line,"[OLLAMA_SERVER_NUM_CTX]"))==line){
				chars=getline(&line, &len, f);
				oi.numCtx=malloc(chars+1);
				memset(oi.numCtx,0,chars+1);
				for(int i=0;i<chars-1;i++) oi.numCtx[i]=line[i];
				continue;
			}
			if((strstr(line,"[OLLAMA_SERVER_MAX_HISTORY_CTX]"))==line){
				chars=getline(&line, &len, f);
				oi.maxHistoryCtx=malloc(chars+1);
				memset(oi.maxHistoryCtx,0,chars+1);
				for(int i=0;i<chars-1;i++) oi.maxHistoryCtx[i]=line[i];
				continue;
			}
			if((strstr(line,"[OLLAMA_SERVER_TEMP]"))==line){
				chars=getline(&line, &len, f);
				oi.temp=malloc(chars+1);
				memset(oi.temp,0,chars+1);
				for(int i=0;i<chars-1;i++) oi.temp[i]=line[i];
				continue;
			}
		}
	}
	return init_networking();
}

int main(int argc, char *argv[]){
	show_intro(PROGRAM_NAME, PROGRAM_VERSION);
	bool noIntro=false;
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
			discover=true;
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
			noIntro=true;
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
	if(initMrAnderson()!=RETURN_OK){
		error_handling(0,false);
		closeMrAnderson();
		exit(EXIT_FAILURE);
	}
	time_t timestamp = time(NULL);
	struct tm tm = *localtime(&timestamp);
	char strTimeStamp[50]="";
	snprintf(strTimeStamp,sizeof(strTimeStamp),"%d/%02d/%02d %02d:%02d:%02d UTC:%s",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone);
	printf("%s\nStarting: %s\n",C_DEFAULT,strTimeStamp);
	if(discover){
		if(others(OTHERS_ARP_DISCOVER_D)!=RETURN_OK) error_handling(0,true);
		closeMrAnderson();
		exit(EXIT_SUCCESS);
	}
	if(scan_init(urlIp)!=RETURN_OK) error_handling(0,true);
	if(target.cantPortsToScan!=0) if(scan_ports(singlePortToScan, true)!=RETURN_OK) error_handling(0,true);
	if(hack_port_request()!=RETURN_OK) error_handling(0,true);
	closeMrAnderson();
	exit(EXIT_SUCCESS);
}

