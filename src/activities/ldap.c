
#include "../auditing-cybersecurity.h"
#include "../activities/activities.h"

int ldap(int type){
	switch(type){
	case LDAP_BFA:
		bfa_imap_ldap_pop3_smtp_ftp(LDAP_BFA);
		break;
	default:
		break;
	}
	return RETURN_OK;
}
