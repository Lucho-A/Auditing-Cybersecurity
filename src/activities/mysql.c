
#include <mysql/mysql.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"

int mysql_check_user(char *username, char *password){
	MYSQL mysqlConn;
	mysql_init(&mysqlConn);
	//int n=10;
	//mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT,&n);
	//mysql_ssl_set(&mysqlConn, NULL, NULL, NULL, NULL, NULL);
	//int opt=1;
	//mysql_options(&mysqlConn, MYSQL_OPT_SSL_MODE, &opt);
	if(!mysql_real_connect(&mysqlConn, target.strTargetIp, username,password, "", portUnderHacking, NULL, 0)){
		if(mysql_errno(&mysqlConn)!=1045) return set_last_activity_error(MYSQL_CONNECTION_ERROR, mysql_error(&mysqlConn));
		return FALSE;
	}
	return TRUE;
}

int mysql(int type){
	switch(type){
	case MYSQL_BANNER_GRABBING:
		/*
		MYSQL mysqlConn;
		mysql_init(&mysqlConn);
		int mysqlTimeout=5;
		mysql_options(&mysqlConn, MYSQL_OPT_CONNECT_TIMEOUT,&mysqlTimeout);
		if(!mysql_real_connect(&mysqlConn, target.strTargetIp, "usuario??", "", NULL, portUnderHacking, NULL, 0)) return set_last_activity_error(MYSQL_CONNECTION_ERROR,mysql_error(&mysqlConn));
		const char *version=mysql_get_server_info(&mysqlConn);
		*/
		char *serverResp=NULL;
		int lenght=send_msg_to_server(target.targetIp, NULL, portUnderHacking,SOCKET_CONN_TYPE, "\n", &serverResp, BUFFER_SIZE_128B,0);
		int i=0;
		while(serverResp[i++]!=10 && i<lenght);
		printf("  Version found: %s",C_HWHITE);
		while(serverResp[i++]!=0) printf("%c", serverResp[i-1]);
		break;
	case MYSQL_BFA:
		return bfa_init(10,"usernames_mysql.txt","passwords_mysql.txt",MYSQL_BFA);
	default:
		break;
	}
	PRINT_RESET;
	PRINT_RESET;
	return RETURN_OK;
}
