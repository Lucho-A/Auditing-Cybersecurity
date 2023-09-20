
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"

int dns(int type){
	char cmd[BUFFER_SIZE_1K]="";
	switch(type){
	case DNS_DIG:
		snprintf(cmd,sizeof(cmd),"dig axfr @%s",target.strTargetURL);
		system_call(cmd);
		break;
	case DNS_BANNER:
		snprintf(cmd,sizeof(cmd),"dig version.bind CHAOS TXT @%s",target.strTargetURL);
		system_call(cmd);
		break;
	case DNS_ZONE_TRANSFER:
		snprintf(cmd,sizeof(cmd),"fierce --domain %s", target.strTargetURL);
		system_call(cmd);
		break;
	case DNS_ENUM:
		snprintf(cmd,sizeof(cmd),"dnsenum --enum %s", target.strTargetURL);
		system_call(cmd);
		break;
	default:
		break;
	}
	PRINT_RESET;
	return RETURN_OK;
}

