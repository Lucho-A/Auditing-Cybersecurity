
#include <unistd.h>
#include <string.h>
#include "../auditing-cybersecurity.h"
#include "activities.h"
#include "../others/networking.h"

int smtp(int type){
	char cmd[BUFFER_SIZE_1K]="";
	switch(type){
	case SMTP_BANNER_GRABBING:
		int sk=0, bytesRecv=0;
		unsigned char *serverResp=NULL;
		char msgs[3][BUFFER_SIZE_32B]=
				{"EHLO .\r\n",
				"HELP\r\n",
				"VRFY\r\n"};
		for(int i=0;i<3;i++){
			bytesRecv=send_msg_to_server(&sk, target.targetIp, target.strTargetURL, portUnderHacking,
					target.ports[portUnderHacking].connectionType,
					msgs[i], strlen(msgs[i]), &serverResp, BUFFER_SIZE_1K, 0, false);
			if(bytesRecv==0){
				show_message("(Zero bytes received)",bytesRecv, 0, ERROR_MESSAGE, false, false, false);
				continue;
			}
			if(bytesRecv<0){
				close(sk);
				return set_last_activity_error(RECEIVING_PACKETS_ERROR, "");
			}
			show_message((char *)serverResp,bytesRecv, 0, RESULT_MESSAGE, false, false, false);
			printf("\n");
		}
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
