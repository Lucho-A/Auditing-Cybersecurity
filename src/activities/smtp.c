
#include <unistd.h>
#include <string.h>
#include "../auditing-cybersecurity.h"
#include "activities.h"
#include "../others/networking.h"

int smtp(int type){
	char cmd[BUFFER_SIZE_1K]="";
	switch(type){
	case SMTP_BANNER_GRABBING:
		int bytesSent=0, localSocketCon=0;
		struct timeval timeout;
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		struct sockaddr_in serverAddress;
		serverAddress.sin_family=AF_INET;
		serverAddress.sin_port=htons(portUnderHacking);
		serverAddress.sin_addr.s_addr=target.targetIp.s_addr;
		if((localSocketCon=socket(AF_INET, SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR, "");
		setsockopt(localSocketCon, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
		setsockopt(localSocketCon, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
		setsockopt(localSocketCon, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
		if(connect(localSocketCon, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0) return set_last_activity_error(SOCKET_CONNECTION_ERROR, "");
		char serverResp[BUFFER_SIZE_1K]="";
		char msgs[2][BUFFER_SIZE_32B]=
				{"EHLO .\r\n",
				 "HELP\r\n"};
		for(int i=0;i<2;i++){
			bytesSent=send(localSocketCon,msgs[i],strlen(msgs[i]),0);
			if(bytesSent<=0) return set_last_activity_error(SENDING_PACKETS_ERROR, "");
			int bytesRecv=0,contI=0;
			char buffer[BUFFER_SIZE_1K]={'\0'};
			snprintf(serverResp,BUFFER_SIZE_1K,"%s","");
			bytesRecv=recv(localSocketCon, buffer, BUFFER_SIZE_1K,0);
			if(bytesRecv<=0){
				close(localSocketCon);
				return set_last_activity_error(RECEIVING_PACKETS_ERROR, "");
			}
			for(int i=0; contI<BUFFER_SIZE_1K && i<bytesRecv; i++, contI++) serverResp[contI]=buffer[i];
			serverResp[contI]='\0';
			show_message(buffer,bytesRecv, 0, RESULT_MESSAGE, FALSE);
			printf("\n");
		}
		close(localSocketCon);
		break;
	case SMTP_ENUMERATION:
		snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_ntlm_domain; set RHOSTS %s; set RPORT %d; run; exit'", target.strTargetIp,portUnderHacking);
		system_call(cmd);
		break;
	case SMTP_RELAY:
		snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_relay; set RHOSTS %s; set RPORT %d; run; exit'", target.strTargetIp,portUnderHacking);
		system_call(cmd);
		break;
	case SMTP_BFA:
		return bfa_imap_ldap_pop3_smtp_ftp(SMTP_BFA);
		break;
	default:
		break;
	}
	return RETURN_OK;
}
