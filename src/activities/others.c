
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
		int totalStrings=open_file_str(resourcesLocation, "interactive_strings_templates.txt", &f, &stringTemplates);
		if(totalStrings==RETURN_ERROR) return set_last_activity_error(OPENING_FILE_ERROR,"");
		fclose(f);
		do{
			msg=get_readline("![#]=templates,;=exit)-> ", TRUE);
			if(strcmp(msg,";")==0) break;
			if(strcmp(msg,"!")==0){
				for(int i=0;i<totalStrings;i++) printf("\n  %d) %s", i+1, stringTemplates[i]);
				free(msg);
				printf("\n\n");
				continue;
			}
			if(msg[0]=='!' && strlen(msg)>1){
				char buf[BUFFER_SIZE_32B]="";
				for(int i=1;i<strlen(msg);i++) buf[i-1]=msg[i];
				long int selectedOpt=strtol(buf,NULL,10);
				if(selectedOpt<1 || selectedOpt>totalStrings){
					show_message("Option not valid\n",0, 0, ERROR_MESSAGE, TRUE);
					free(msg);
					continue;
				}
				char bufferHistory[BUFFER_SIZE_1K]="";
				snprintf(bufferHistory,sizeof(bufferHistory), stringTemplates[selectedOpt-1], target.strTargetURL, portUnderHacking);
				add_history(bufferHistory);
				free(msg);
				continue;
			}
			unsigned char *serverResp=NULL;
			int c=format_strings_from_files(msg,msg);
			int sk=0;
			int bytesRecv=send_msg_to_server(&sk,target.targetIp, target.strHostname,portUnderHacking,
					target.portsToScan[get_port_index(portUnderHacking)].connectionType,
					msg, c, &serverResp,BUFFER_SIZE_128K, 5000);
			free(msg);
			close(sk);
			if(bytesRecv<0){
				error_handling(0,FALSE);
				continue;
			}
			if(bytesRecv>0 && strcmp((char *) serverResp,"")!=0) show_message((char *)serverResp,bytesRecv,0, RESULT_MESSAGE, TRUE);
			printf("\n\n");
			free(serverResp);
		}while(TRUE);
		free_char_double_pointer(&stringTemplates, totalStrings);
		break;
	case OTHERS_CHATGPT:
		srand(time(0));
		char **api=NULL;
		int entries=open_file_str(resourcesLocation, "chatgpt.txt", &f, &api);
		fclose(f);
		if(entries==RETURN_ERROR || strcmp(api[1],"")==0 || api[1]==NULL) return show_message("API not found.\n", strlen("API not found."), 0, ERROR_MESSAGE, FALSE);
		char *chatGptIp=hostname_to_ip("api.openai.com");
		if(chatGptIp==NULL) return RETURN_ERROR;
		struct in_addr ip;
		ip.s_addr=inet_addr(chatGptIp);
		char *prevUserMsg=malloc(1), *prevAssistantMsg=malloc(1);
		prevUserMsg[0]=0;
		prevAssistantMsg[0]=0;
		do{
			cancelCurrentProcess=FALSE;
			unsigned char *serverResp=NULL;
			char *msg=get_readline(";=exit)-> ", TRUE);
			if(strcmp(msg,";")==0){
				free(msg);
				break;
			}
			char *msgParsed=malloc(strlen(msg)*2);
			memset(msgParsed,0,strlen(msg)*2);
			int parsedIdx=0;
			for(int i=0;i<strlen(msg);i++,parsedIdx++){
				switch(msg[i]){
				case '\n':
					msgParsed[parsedIdx]='\\';
					msgParsed[++parsedIdx]='n';
					break;
				case '\t':
					msgParsed[parsedIdx]='\\';
					msgParsed[++parsedIdx]='t';
					break;
				case '"':
					msgParsed[parsedIdx]='\\';
					msgParsed[++parsedIdx]='\"';
					break;
				default:
					msgParsed[parsedIdx]=msg[i];
					break;
				}
			}
			free(msg);
			int len=strlen(msgParsed)+strlen(prevUserMsg)+strlen(prevAssistantMsg)+BUFFER_SIZE_1K;
			char *payload=malloc(len);
			memset(payload,0,len);
			snprintf(payload,len,
					"{"
					"\"model\":\"gpt-3.5-turbo\","
					"\"messages\":["
					"{\"role\":\"system\",\"content\":\"Act as IT auditor, security and cybersecurity professional.\"},"
					"{\"role\":\"user\",\"content\":\"%s\"},"
					"{\"role\":\"assistant\",\"content\":\"%s\"},"
					"{\"role\":\"user\",\"content\":\"%s\"}"
					"],"
					"\"max_tokens\": %ld,"
					"\"temperature\": %.2f"
					"}\r\n\r\n",prevUserMsg,prevAssistantMsg,msgParsed,strtol(api[3],NULL,10),strtod(api[5],NULL));
			if(prevUserMsg!=NULL) free(prevUserMsg);
			prevUserMsg=malloc(strlen(msgParsed)+1);
			snprintf(prevUserMsg,strlen(msgParsed)+1,"%s",msgParsed);
			free(msgParsed);
			char *httpMsg=malloc(strlen(payload)+BUFFER_SIZE_256B);
			memset(httpMsg,0,strlen(payload)+BUFFER_SIZE_256B);
			snprintf(httpMsg,strlen(payload)+BUFFER_SIZE_1K,
					"POST /v1/chat/completions HTTP/1.1\r\n"
					"Host: api.openai.com\r\n"
					"user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
					"content-type: application/json\r\n"
					"authorization: Bearer %s\r\n"
					"content-length: %ld\r\n\r\n"
					"%s \r\n\r\n",api[1],strlen(payload),payload);
			free(payload);
			int bytesRecv=0;
			int sk=0;
			if((bytesRecv=send_msg_to_server(&sk,ip,"api.openai.com", 443, SSL_CONN_TYPE, httpMsg,
					strlen(httpMsg), &serverResp,BUFFER_SIZE_8K,60000))<0) return RETURN_ERROR;
			close(sk);
			free(httpMsg);
			printf("%s\n  ",C_HWHITE);
			char *resp=strstr((char *) serverResp,"\"content\": \"");
			if(resp==NULL){
				if((resp=strstr((char *) serverResp,"\"error\": {"))!=NULL){
					resp=strstr((char *) serverResp,"\"message\": \"");
					printf(" %s\n", C_HRED);
					for(int i=strlen("\"message\": \"");resp[i]!='"';i++) printf("%c", resp[i]);
					PRINT_RESET;
				}
				if(bytesRecv==0) printf("  %sOps, 0 bytes received... maybe, service momentarily unavailable. Try again...\n",C_HRED);
				PRINT_RESET;
				free(serverResp);
				continue;
			}
			if(prevAssistantMsg!=NULL) free(prevAssistantMsg);
			prevAssistantMsg=malloc(strlen(resp)+1);
			memset(prevAssistantMsg,0,strlen(resp)+1);
			for(int i=strlen("\"content\": \"");!(resp[i-1]!='\\' && resp[i]=='"');i++) prevAssistantMsg[i-strlen("\"content\": \"")]=resp[i];
			for(int i=strlen("\"content\": \"");!(resp[i-1]!='\\' && resp[i]=='"') && !cancelCurrentProcess;i++){
				usleep(rand() % 10000 + 20000);
				if(resp[i]=='\\'){
					switch(resp[i+1]){
					case 'n':
						printf("\n");
						break;
					case '"':
						printf("\"");
						break;
					case 't':
						printf("\t");
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
				printf("%c",resp[i]);
				fflush(stdout);
			}
			PRINT_RESET;
			PRINT_RESET;
			free(serverResp);
		}while(TRUE);
		if(prevUserMsg!=NULL) free(prevUserMsg);
		if(prevAssistantMsg!=NULL) free(prevAssistantMsg);
		free_char_double_pointer(&api, entries);
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
