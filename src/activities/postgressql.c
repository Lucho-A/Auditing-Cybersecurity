
#include </usr/include/postgresql/libpq-fe.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"

int postgres_check_user(char *username, char *password){
	char postgresConnInfo[BUFFER_SIZE_1K]="";
	snprintf(postgresConnInfo,sizeof(postgresConnInfo), "hostaddr=%s port=%d dbname=postgres user=%s password=%s connect_timeout=5",target.strTargetIp, portUnderHacking, username,password);
	PGconn *postgresConn = PQconnectdb(postgresConnInfo);
	printf("\n%s\n", PQerrorMessage(postgresConn));
	if(PQstatus(postgresConn)==CONNECTION_OK) return TRUE;
	if(postgresConn!=NULL) PQfinish(postgresConn);
	return FALSE;
}

int postgres(int type){
	switch(type){
	case POSTGRES_BFA:
		return bfa_init(10, "usernames_postgressql.txt", "passwords_postgressql.txt", POSTGRES_BFA);
		break;
	default:
		break;
	}
	PRINT_RESET;
	return RETURN_OK;
}
