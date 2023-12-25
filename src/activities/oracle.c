
#include "dpi.h"
#include "../libodpi/dpiImpl.h"
//#include "dpi.c"
#include <errno.h>
#include <string.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "activities.h"

int oracle_check_user(char *username, char *password){
	char dbURL[BUFFER_SIZE_1K]="";
	snprintf(dbURL, sizeof(dbURL), "%s:%d", target.strTargetIp,portUnderHacking);
	dpiContext *gContext = NULL;
	dpiErrorInfo gErrorInfo;
	char errorDesc[BUFFER_SIZE_1K]="";
	if(dpiContext_create(DPI_MAJOR_VERSION, DPI_MINOR_VERSION, &gContext, &gErrorInfo)<0){
		if(gContext) dpiContext_getError(gContext, &gErrorInfo);
		snprintf(errorDesc,sizeof(errorDesc),"%.*s", (int) gErrorInfo.messageLength,gErrorInfo.message);
		return show_message(errorDesc,0, 0, ERROR_MESSAGE, TRUE);
	}
	if(gContext==NULL) return show_message("",0, errno, ERROR_MESSAGE, TRUE);
	//dpiConn_addRef(&oracleConn);
	//dpiVersionInfo *versionInfo=NULL;
	//dpiConn_getServerVersion(oracleConn, NULL, NULL, versionInfo);
	//printf("\n%d\n",versionInfo->releaseNum);
	dpiConn *oracleConn=NULL;
	if(dpiConn_create(gContext, username, strlen(username),password, strlen(password), dbURL, strlen(dbURL),
			NULL, NULL, &oracleConn) == DPI_SUCCESS) return TRUE;
	dpiConn_release(oracleConn);
	//dpiConn__free(oracleConn, NULL);
	if(gContext) dpiContext_getError(gContext, &gErrorInfo);
	if(gErrorInfo.code==28000){
		printf("\n\n%sExisting account (but blocked): %s",C_HRED,username);
		PRINT_RESET;
	}
	return FALSE;
}

int oracle(int type){
	switch(type){
	case ORACLE_BFA:
		bfa_init(10, "usernames_oracle.txt", "passwords_oracle.txt", ORACLE_BFA);
		break;
	default:
		break;
	}
	return RETURN_OK;
}
