
#include <ftplib.h>
#include <string.h>
#include <stdlib.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"
#include <unistd.h>

int ftp_check_user(char *username, char *password){
	netbuf *ftpConn=NULL;
	char host[BUFFER_SIZE_128B]="";
	snprintf(host, BUFFER_SIZE_128B, "%s:%d", target.strTargetIp,portUnderHacking);
	int valResp=FtpConnect(host, &ftpConn);
	if(!valResp){
		if(ftpConn!=NULL) FtpClose(ftpConn);
		return set_last_activity_error(FTP_CONNECTION_ERROR, FtpLastResponse(ftpConn));
	}
	valResp=FtpLogin(username,password,ftpConn);
	if(valResp){
		FtpQuit(ftpConn);
		return true;
	}
	if(strstr(FtpLastResponse(ftpConn),"430")!=NULL || strstr(FtpLastResponse(ftpConn),"530")!=NULL || strstr(FtpLastResponse(ftpConn),"500")!=NULL){
		FtpClose(ftpConn);
		return false;
	}
	FtpClose(ftpConn);
	return set_last_activity_error(FTP_ERROR, FtpLastResponse(ftpConn));
}

int ftp(int type){
	char host[BUFFER_SIZE_128B]="";
	switch(type){
	case FTP_BANNER_GRABBING:
		unsigned char *serverResp=NULL;
		int conn=0;
		int bytesRecv=send_msg_to_server(&conn,target.targetIp, NULL,
				portUnderHacking,target.ports[portUnderHacking].connectionType,
				"\n", strlen("\n"), &serverResp,BUFFER_SIZE_128B,0);
		if(bytesRecv<0) error_handling(0,false);
		if(bytesRecv>0) show_message((char *)serverResp, bytesRecv, 0, RESULT_MESSAGE, true);
		free(serverResp);
		close(conn);
		break;
	case FTP_ANONYMOUS:
		netbuf *ftpConn=NULL;
		snprintf(host, BUFFER_SIZE_128B, "%s:%d", target.strTargetIp,portUnderHacking);
		int valResp=FtpConnect(host, &ftpConn);
		if(!valResp) return set_last_activity_error(FTP_CONNECTION_ERROR, FtpLastResponse(ftpConn));
		valResp=FtpLogin("anonymous","",ftpConn);
		show_message(FtpLastResponse(ftpConn),0, 0, ERROR_MESSAGE, false);
		if(valResp){
			printf("\n%s",C_HRED);
			FtpDir(NULL, "", ftpConn);
			printf("%s",C_DEFAULT);
		}
		FtpQuit(ftpConn);
		break;
	case FTP_BFA:
		return bfa_init(10,"usernames_ftp.txt","passwords_ftp.txt", FTP_BFA);
		break;
	default:
		break;
	}
	return RETURN_OK;
}
