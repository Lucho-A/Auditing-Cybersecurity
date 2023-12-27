
#include "../auditing-cybersecurity.h"
#include "activities.h"
#include "../others/networking.h"

int pop3(int type){
	switch(type){
	case POP3_BFA:
		return bfa_imap_ldap_pop3_smtp_ftp(POP3_BFA);
	default:
		break;
	}
	return RETURN_OK;
}
