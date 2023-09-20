
#include "../auditing-cybersecurity.h"
#include "activities.h"

int pop3(int type){
	switch(type){
	case POP3_BFA:
		bfa_imap_ldap_pop3_smtp_ftp(POP3_BFA);
		break;
	default:
		break;
	}
	printf("\n\n");
	return RETURN_OK;
}
