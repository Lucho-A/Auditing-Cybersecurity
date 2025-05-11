
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <readline/history.h>
#include <arpa/inet.h>
#include "../auditing-cybersecurity.h"
#include "../activities/activities.h"
#include "../others/networking.h"

int others(int type){
	FILE *f=NULL;
	char *msg=NULL, cmd[BUFFER_SIZE_1K]="";
	switch(type){
	case OTHERS_SHOW_FILTERED_PORTS:
		show_filtered_ports();
		break;
	case OTHERS_SHOW_OPENED_PORTS:
		show_opened_ports();
		break;
	case OTHERS_INTERACTIVE:
		char **stringTemplates=NULL;
		int totalStrings=open_file_str(resourcesLocation, "interactive_strings_templates.txt", &f, &stringTemplates);
		if(totalStrings==RETURN_ERROR) return set_last_activity_error(OPENING_FILE_ERROR,"");
		fclose(f);
		do{
			msg=get_readline("![#]=templates,;=exit)-> ", true);
			if(strcmp(msg,"")==0){
				PRINT_RESET;
				free(msg);
				continue;
			}
			if(strcmp(msg,";")==0){
				free(msg);
				break;
			}
			if(strcmp(msg,"!")==0){
				for(int i=0;i<totalStrings;i++) printf("\n  %d) %s", i+1, stringTemplates[i]);
				free(msg);
				printf("\n\n");
				continue;
			}
			if(msg[0]=='!' && strlen(msg)>1){
				char buf[BUFFER_SIZE_32B]="";
				for(size_t i=1;i<strlen(msg);i++) buf[i-1]=msg[i];
				long int selectedOpt=strtol(buf,NULL,10);
				if(selectedOpt<1 || selectedOpt>totalStrings){
					show_message("Option not valid\n",0, 0, ERROR_MESSAGE, true, false, false);
					free(msg);
					continue;
				}
				char bufferHistory[BUFFER_SIZE_1K]="";
				snprintf(bufferHistory,sizeof(bufferHistory), stringTemplates[selectedOpt-1],target.strTargetURL, portUnderHacking);
				add_history(bufferHistory);
				free(msg);
				continue;
			}
			unsigned char *serverResp=NULL;
			int c=format_strings_from_files(msg,msg);
			int sk=0;
			char askTor=ask_tor_service();
			if(askTor=='C'){
				free(msg);
				continue;
			}
			bool usingTor=false;
			if (askTor=='Y') usingTor=true;
			int bytesRecv=send_msg_to_server(&sk,target.targetIp, target.strTargetURL, portUnderHacking,
					target.ports[portUnderHacking].connectionType,
					msg, c, &serverResp,BUFFER_SIZE_128K, 0, usingTor);
			free(msg);
			close(sk);
			if(bytesRecv<0){
				error_handling(0);
				continue;
			}
			if(bytesRecv>0 && strcmp((char *) serverResp,"")!=0)
				show_message((char *)serverResp,bytesRecv,0, RESULT_MESSAGE, true, false, false);
			printf("\n\n");
			free(serverResp);
		}while(true);
		free_char_double_pointer(&stringTemplates, totalStrings);
		break;
	case OTHERS_SYSTEM_CALL:
		system_call(NULL);
		break;
	case OTHERS_TRACEROUTE:
		snprintf(cmd,sizeof(cmd),"traceroute %s", target.strTargetIp);
		system_call(cmd);
		break;
	case OTHERS_ARP_DISCOVER:
		return arp(OTHERS_ARP_DISCOVER);
	case OTHERS_ARP_DISCOVER_D:
		return arp(OTHERS_ARP_DISCOVER_D);
	case OTHERS_SHOW_ACTIVIIES:
		show_options();
		break;
	case OTHERS_WHOIS:
		snprintf(cmd,sizeof(cmd),"whois %s", target.strTargetIp);
		system_call(cmd);
		break;
	case OTHERS_SEARCH_CVE:
		srand(time(0));
		char httpMsg[BUFFER_SIZE_512B]="";
		char *host="app.opencve.io";
		char *nistIP=hostname_to_ip(host);
		if(nistIP==NULL) return RETURN_ERROR;
		struct in_addr ip;
		ip.s_addr=inet_addr(nistIP);
		do{
			cancelCurrentProcess=false;
			unsigned char *serverResp=NULL;
			char *msg=get_readline("Insert string to search (;=exit):", true);
			if(strcmp(msg,";")==0){
				free(msg);
				break;
			}
			for(size_t i=0;i<strlen(msg);i++){
				if(msg[i]==' ' || msg[i]=='\"') msg[i]='+';
			}
			snprintf(httpMsg,BUFFER_SIZE_512B,
					"GET /api/cve?search=%s HTTP/1.1\r\n"
					"Host: %s\r\n"
					"Authorization: Basic YXVkaXRpbmctYW5kLXNlY3VyaXR5Ok1yQW5kZXJzb25PcGVuQ1ZF\r\n"
					"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\r\n"
					"Accept: */*\r\n\r\n",msg,host);
			free(msg);
			int bytesRecv=0, sk=0;
			if((bytesRecv=send_msg_to_server(&sk,ip,host, 443, SSL_CONN_TYPE, httpMsg,strlen(httpMsg),
					&serverResp,BUFFER_SIZE_16K,30000, false))<0){
				return RETURN_ERROR;
			}
			close(sk);
			char *token="\"cve_id\":";
			char *json=strstr((char *)serverResp,token);
			if(json==NULL){
				free(serverResp);
				show_message("No results found.", strlen("No results found."), 0, INFO_MESSAGE, true, false, false);
				PRINT_RESET;
				continue;
			}
			int cont=0, cveId=1;
			while(json!=NULL && cont<bytesRecv){
				printf("%s\n\t%d) ",C_HWHITE,cveId);
				for(cont=strlen(token);;cont++){
					if((json[cont]=='"'&& json[cont+1]==',') || cont>=bytesRecv) break;
					printf("%c",json[cont]);
					json[cont-strlen(token)]='X';
				}
				printf("%s:",C_DEFAULT);
				cont+=2;
				for(int i=cont+strlen("\"description\":");;i++,cont++){
					if((json[i]=='"'&& json[i+1]=='}') || cont>=bytesRecv) break;
					if(json[i]=='\\'){
						switch(json[i+1]){
						case 'n':
							break;
						case '"':
							printf("\"");
							break;
						case '\\':
							printf("\\");
							break;
						default:
							break;
						}
						i++;
						continue;
					}
					printf("%c",json[i]);
				}
				printf("\"\n  ");
				json=strstr(json,token);
				if(cveId==10){
					show_message("Max. size per page achieved.", 0, 0, ERROR_MESSAGE, true, false, false);
					break;
				}
				cveId++;
			}
			free(serverResp);
			PRINT_RESET;
		}while(true);
		break;
	case OTHERS_EXIT:
		printf("%s",C_DEFAULT);
	default:
		break;
	}
	clear_history();
	return RETURN_OK;
}
