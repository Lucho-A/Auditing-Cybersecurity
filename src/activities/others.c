
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
	case OTHERS_SHOW_OPENED_PORTS:
		show_opened_ports();
		break;
	case OTHERS_INTERACTIVE:
		char **stringTemplates=NULL;
		int totalStrings=open_file_str(PATH_TO_RESOURCES, "interactive_strings_templates.txt", &f, &stringTemplates);
		if(totalStrings==RETURN_ERROR) return set_last_activity_error(OPENING_FILE_ERROR,"");
		fclose(f);
		do{
			msg=get_readline("![#]=templates,;=exit)-> ", TRUE);
			if(strcmp(msg,";")==0) break;
			if(strcmp(msg,"!")==0){
				for(int i=0;i<totalStrings;i++) printf("\n  %d) %s", i+1, stringTemplates[i]);
				printf("\n\n");
				continue;
			}
			if(msg[0]=='!' && strlen(msg)>1){
				char buf[BUFFER_SIZE_32B]="";
				for(int i=1;i<strlen(msg);i++) buf[i-1]=msg[i];
				long int selectedOpt=strtol(buf,NULL,10);
				if(selectedOpt<1 || selectedOpt>totalStrings){
					show_message("Option not valid\n",0, 0, ERROR_MESSAGE, TRUE);
					continue;
				}
				char bufferHistory[BUFFER_SIZE_1K]="";
				snprintf(bufferHistory,sizeof(bufferHistory), stringTemplates[selectedOpt-1], target.strTargetURL, portUnderHacking);
				add_history(bufferHistory);
				continue;
			}
			char *serverResp=NULL;
			format_strings_from_files(msg,msg);
			int bytesRecv=send_msg_to_server(target.targetIp, NULL,portUnderHacking, target.portsToScan[get_port_index(portUnderHacking)].connectionType, msg, &serverResp, BUFFER_SIZE_128K, 5000);
			if(bytesRecv<0){
				error_handling(FALSE);
				continue;
			}
			if(bytesRecv>0 && strcmp(serverResp,"")!=0) show_message(serverResp,bytesRecv,0, RESULT_MESSAGE, TRUE);
			printf("\n\n");
			free(msg);
		}while(TRUE);
		free_char_double_pointer(stringTemplates, totalStrings);
		break;
	case OTHERS_CHATGPT:
		srand(time(0));
		char **api=NULL;
		int entries=open_file_str(PATH_TO_RESOURCES, "chatgpt.txt", &f, &api);
		fclose(f);
		if(entries==RETURN_ERROR || strcmp(api[1],"")==0 || api[1]==NULL) return show_message("API not found.\n", strlen("API not found."), 0, ERROR_MESSAGE, FALSE);
		char httpMsg[BUFFER_SIZE_512B]="";
		char *chatGptIp=hostname_to_ip("api.openai.com");
		if(chatGptIp==NULL) return RETURN_ERROR;
		struct in_addr ip;
		ip.s_addr=inet_addr(chatGptIp);
		do{
			cancelCurrentProcess=FALSE;
			char *serverResp=NULL;
			msg=get_readline(";=exit)-> ", TRUE);
			if(strcmp(msg,";")==0) break;
			for(int i=0;i<strlen(msg);i++){
				if(msg[i]=='\"') msg[i]='\'';
			}
			char *payload = (char *) malloc((strlen(msg) + BUFFER_SIZE_512B) * sizeof(char));
			sprintf(payload,
					"{"
					"\"model\":\"gpt-3.5-turbo\","
					"\"messages\":["
					"{\"role\":\"system\",\"content\":\"Act as IT auditor, security and cybersecurity professional.\"},"
					"{\"role\":\"user\",\"content\":\"%s\"}],"
					"\"max_tokens\": %ld,"
					"\"temperature\": %.2f"
					"}\r\n\r\n",msg,strtol(api[3],NULL,10),strtod(api[5],NULL));
			snprintf(httpMsg,BUFFER_SIZE_1K,
					"POST /v1/chat/completions HTTP/1.1\r\n"
					"Host: api.openai.com\r\n"
					"user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
					"content-type: application/json\r\n"
					"authorization: Bearer %s\r\n"
					"content-length: %ld\r\n\r\n"
					"%s \r\n\r\n",api[1],strlen(payload),payload);
			free_char_double_pointer(api, entries);
			int bytesRecv=0;
			if((bytesRecv=send_msg_to_server(ip,"api.openai.com", 443, SSL_CONN_TYPE, httpMsg, &serverResp, BUFFER_SIZE_8K,60000))<0) return RETURN_ERROR;
			printf("%s\n  ",C_HWHITE);
			char *resp=strstr(serverResp,"\"content\": \"");
			if(resp==NULL){
				if(bytesRecv==0) printf("  %sOps, 0 bytes received... maybe, service momentarily unavailable. Try again...\n",C_HRED);
				if(bytesRecv!=0) printf("  %sNo response... check config file (apikey and values) and/or try again...\n",C_HRED);
				PRINT_RESET;
				free(msg);
				free(serverResp);
				continue;
			}
			for(int i=strlen("\"content\": \"");resp[i]!='"' && !cancelCurrentProcess;i++){
				usleep(rand() % 30000 + 20000);
				if(resp[i]=='\\'){
					switch(resp[i+1]){
					case 'n':
						printf("\n  ");
						break;
					case '"':
						printf("\"");
						break;
					default:
						break;
					}
					i++;
					continue;
				}
				printf("%c",resp[i]);
				fflush(stdout);
			}
			PRINT_RESET;
			PRINT_RESET;
			free(payload);
			free(serverResp);
		}while(TRUE);
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
	case OTHERS_MONITOR_IF:
		//monitor(OTHERS_MONITOR_IF);
		break;
	case OTHERS_SHOW_ACTIVIIES:
		show_options();
		break;
	case OTHERS_WHOIS:
		snprintf(cmd,sizeof(cmd),"whois %s", target.strTargetIp);
		system_call(cmd);
		break;
	case OTHERS_EXIT:
		printf("%s",C_DEFAULT);
		exit(EXIT_SUCCESS);
	default:
		break;
	}
	clear_history();
	return RETURN_OK;
}
