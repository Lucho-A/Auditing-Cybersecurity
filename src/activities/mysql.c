
#include <mysql/mysql.h>
#include <string.h>
#include <unistd.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"

int mysql_check_user(char *username, char *password){
	MYSQL mysqlConn;
	mysql_init(&mysqlConn);
	int n=5;
	mysql_options(&mysqlConn, MYSQL_OPT_CONNECT_TIMEOUT,&n);
	if(!mysql_real_connect(&mysqlConn, target.strTargetIp, username,password, "", portUnderHacking, NULL, 0)){
		if(mysql_errno(&mysqlConn)!=1045){
			if(!lastActivityError.blocked){
				lastActivityError.blocked=true;
				set_last_activity_error(MYSQL_CONNECTION_ERROR, mysql_error(&mysqlConn));
				mysql_close(&mysqlConn);
			}
			return RETURN_ERROR;
		}
		mysql_close(&mysqlConn);
		return false;
	}
	mysql_close(&mysqlConn);
	return true;
}

int mysql(int type){
	switch(type){
	case MYSQL_BANNER_GRABBING:
		unsigned char *serverResp=NULL;
		int sk=0;
		int lenght=send_msg_to_server(&sk,target.targetIp, NULL, portUnderHacking,SOCKET_CONN_TYPE,
				"\n",strlen("\n"), &serverResp, BUFFER_SIZE_128B,0);
		close(sk);
		if(lenght==0){
			show_message("No server response\n", 0, 0, ERROR_MESSAGE, false, false, false);
			free(serverResp);
			return RETURN_OK;
		}
		int i=0;
		switch(serverResp[0]){
		case 'I':
		case 'J':
			i=5;
			printf("Version found: %s",C_HWHITE);
			while(serverResp[i++]!=0) printf("%c", serverResp[i-1]);
			break;
		case 'E':
			i=7;
			printf("%s",C_HRED);
			while(serverResp[i++]!=0) printf("%c", serverResp[i-1]);
			break;
		default:
			show_message("No recognized response:", 0, 0, ERROR_MESSAGE, false, false, false);
			break;
		}
		show_message((char *)serverResp, lenght, 0, RESULT_MESSAGE, true, true, true);
		show_message((char *)serverResp, lenght, 0, RESULT_MESSAGE, true, false, true);
		PRINT_RESET;
		free(serverResp);
		break;
		case MYSQL_BFA:
			return bfa_init(10,"usernames_mysql.txt","passwords_mysql.txt",MYSQL_BFA);
		default:
			break;
	}
	return RETURN_OK;
}
