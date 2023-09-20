
#include "../auditing-cybersecurity.h"
#include "activities.h"

int imap(int type){
	switch(type){
	case IMAP_BFA:
		bfa_imap_ldap_pop3_smtp_ftp(IMAP_BFA);
		break;
	default:
		break;
	}
	printf("\n\n");
	return RETURN_OK;
}
