
#include <libssh2.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <readline/readline.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"
#include <errno.h>
#include <netinet/ip.h>

#define ACTIVITY_NOT_SELECTED		100

static int check_conn_type(){
	int sk=0;
	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port=htons(portUnderHacking);
	serverAddress.sin_addr.s_addr= target.targetIp.s_addr;
	if(create_socket_conn(&sk, target.targetIp, portUnderHacking)!=RETURN_OK) return RETURN_ERROR;
	// check SSH
	LIBSSH2_SESSION *sshSession=NULL;
	if((sshSession = libssh2_session_init())==NULL) return set_last_activity_error(SSH_HANDSHAKE_ERROR,"");
	libssh2_session_set_timeout(sshSession, SSH_TIMEOUT_MS);
	libssh2_session_banner_set(sshSession,"SSH-2.0-OpenSSH_for_Windows_8.1");
	if(libssh2_session_handshake(sshSession, sk)==0){
		libssh2_session_free(sshSession);
		close(sk);
		return SSH_CONN_TYPE;
	}
	libssh2_session_free(sshSession);
	close(sk);
	if((sk=socket(AF_INET,SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR,"");
	setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	if(connect(sk, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0) return set_last_activity_error(SOCKET_CONNECTION_ERROR,"");
	// check SSL
	fcntl(sk, F_SETFL, O_NONBLOCK);
	SSL *sslConn = SSL_new(sslCtx);
	if(sslConn==NULL) return set_last_activity_error(SSL_CONNECT_ERROR,"");
	if(!SSL_set_fd(sslConn, sk)) return set_last_activity_error(SSL_FD_ERROR, "");
	int respSSLConn=0, errSSLConn=0;
	time_t tInit=time(0)+SSL_TIMEOUT_S;
	SSL_set_connect_state(sslConn);
	SSL_set_tlsext_host_name(sslConn, target.strTargetURL);
	do{
		respSSLConn=SSL_connect(sslConn);
		if(respSSLConn>0) break;
		errSSLConn=SSL_get_error(sslConn, respSSLConn);
		usleep(100000);
		if(errSSLConn==SSL_ERROR_SSL) break;
	}while((errSSLConn==SSL_ERROR_WANT_READ || errSSLConn==SSL_ERROR_WANT_WRITE || errSSLConn==SSL_ERROR_WANT_CONNECT) && time(0)<tInit);
	close(sk);
	if(sslConn!=NULL){
		SSL_shutdown(sslConn);
		SSL_certs_clear(sslConn);
		SSL_clear(sslConn);
		SSL_free(sslConn);
	}
	if(respSSLConn>0) return SSL_CONN_TYPE;
	return SOCKET_CONN_TYPE;
}

static int hack_port() {
	show_options();
	char prompt[BUFFER_SIZE_256B]="";
	snprintf(prompt,sizeof(prompt),"%s@%s%s:%s%d%s:",C_DEFAULT,C_HWHITE,target.strTargetIp,C_HCYAN,portUnderHacking,C_DEFAULT);
	while(true){
		cancelCurrentProcess=false;
		canceledBySignal=false;
		oclCanceled=false;
		int valResp=ACTIVITY_NOT_SELECTED;
		lastActivityError.blocked=false;
		lastActivityError.errorType=0;
		lastActivityError.err=0;
		lastActivityError.sslErr=0;
		memset(lastActivityError.errorAditionalDescription,0,sizeof(lastActivityError.errorAditionalDescription));
		char *c=get_readline(prompt, false);
		if(strcmp(c,"")==0) continue;
		printf("\n");
		if(strcmp(c,"1.1")==0) valResp=any(ANY_BANNER_GRABBING);
		if(strcmp(c,"1.2")==0) valResp=any(ANY_NMAP_VULNER_SCAN);
		if(strcmp(c,"1.3")==0) valResp=any(ANY_SEARCH_NMAP);
		if(strcmp(c,"1.4")==0) valResp=any(ANY_RUN_NMAP);
		if(strcmp(c,"1.5")==0) valResp=any(ANY_SEARCH_MSF);
		if(strcmp(c,"1.6")==0) valResp=any(ANY_RUN_MSF);
		if(strcmp(c,"1.7")==0) valResp=any(ANY_SQL_MAP);
		if(strcmp(c,"1.8")==0) valResp=any(ANY_DOS_SYN_FLOOD_ATTACK);
		if(strcmp(c,"1.9")==0) valResp=any(ANY_ARP_SNIFFING);

		if(strcmp(c,"2.1")==0) valResp=http(HTTP_HEADER_BANNER_GRABBING);
		if(strcmp(c,"2.2")==0) valResp=http(HTTP_TLS_GRABBING);
		if(strcmp(c,"2.3")==0) valResp=http(HTTP_METHODS_ALLOWED_GRABBING);
		if(strcmp(c,"2.4")==0) valResp=http(HTTP_SERVER_RESP_SPOOFED_HEADERS);
		if(strcmp(c,"2.5")==0) valResp=http(HTTP_GET_WEBPAGES);
		if(strcmp(c,"2.6")==0) valResp=http(HTTP_OTHERS);

		if(strcmp(c,"3.1")==0) valResp=ssh(SSH_FINGER_PRINTING);
		if(strcmp(c,"3.2")==0){
			valResp=ssh(SSH_USER_ENUM);
			//ssh( USER_GUEST_SSH);
		}
		if(strcmp(c,"3.3")==0) valResp=ssh(SSH_BFA);
		if(strcmp(c,"3.4")==0) valResp=ssh(SSH_RUN_JUNIPER_BACKDOOR);

		if(strcmp(c,"4.1")==0) valResp=dns(DNS_DIG);
		if(strcmp(c,"4.2")==0) valResp=dns(DNS_BANNER);
		if(strcmp(c,"4.3")==0) valResp=dns(DNS_ZONE_TRANSFER);
		if(strcmp(c,"4.4")==0) valResp=dns(DNS_ENUM);

		if(strcmp(c,"5.1")==0) valResp=ftp(FTP_ANONYMOUS);
		if(strcmp(c,"5.2")==0) valResp=ftp(FTP_BFA);
		if(strcmp(c,"5.3")==0) valResp=ftp(FTP_BANNER_GRABBING);

		if(strcmp(c,"6.1")==0) valResp=smb(SMB_BANNER_GRABBING);
		if(strcmp(c,"6.2")==0) valResp=smb(SMB_ETERNAL_BLUE);
		if(strcmp(c,"6.3")==0) valResp=smb(SMB_BFA);

		if(strcmp(c,"7.1")==0) valResp=mysql(MYSQL_BANNER_GRABBING);
		if(strcmp(c,"7.2")==0) valResp=mysql(MYSQL_BFA);

		if(strcmp(c,"8.1")==0) valResp=smtp(SMTP_ENUMERATION);
		if(strcmp(c,"8.2")==0) valResp=smtp(SMTP_RELAY);
		if(strcmp(c,"8.3")==0) valResp=smtp(SMTP_BFA);
		if(strcmp(c,"8.4")==0) valResp=smtp(SMTP_BANNER_GRABBING);

		if(strcmp(c,"9.1")==0) valResp=imap(IMAP_BFA);

		if(strcmp(c,"10.1")==0) valResp=ldap(LDAP_BFA);

		if(strcmp(c,"11.1")==0) valResp=pop3(POP3_BFA);

		if(strcmp(c,"12.1")==0) valResp=oracle(ORACLE_BFA);

		if(strcmp(c,"13.1")==0) valResp=postgres(POSTGRES_BFA);

		if(strcmp(c,"14.1")==0) valResp=mssql(MSSQL_BFA);
		if(strcmp(c,"14.2")==0) valResp=mssql(MSSQL_SHELL);

		if(strcmp(c,"o")==0) valResp=others(OTHERS_SHOW_OPENED_PORTS);
		if(strcmp(c,"f")==0) valResp=others(OTHERS_SHOW_FILTERED_PORTS);
		if(strcmp(c,"d")==0) valResp=others(OTHERS_ARP_DISCOVER);
		if(strcmp(c,"i")==0) valResp=others(OTHERS_INTERACTIVE);
		if(strcmp(c,"s")==0) valResp=others(OTHERS_SYSTEM_CALL);
		if(strcmp(c,"t")==0) valResp=others(OTHERS_TRACEROUTE);
		if(strcmp(c,"h")==0) valResp=others(OTHERS_SHOW_ACTIVIIES);
		if(strcmp(c,"w")==0) valResp=others(OTHERS_WHOIS);
		if(strcmp(c,"v")==0) valResp=others(OTHERS_SEARCH_CVE);
		if(strcmp(c,"c")==0){
			free(c);
			return RETURN_OK;
		}
		if(strcmp(c,"q")==0){
			free(c);
			return RETURN_CLOSE;
		}
		if(valResp==ACTIVITY_NOT_SELECTED){
			if((valResp=OCl_send_chat(ocl,c))!=RETURN_OK){
				switch(valResp){
				case OCL_ERR_RESPONSE_MESSAGE_ERROR:
					show_message(OCL_get_response_error(ocl), strlen(OCL_get_response_error(ocl)),
							0, ERROR_MESSAGE, true,false,false);
					break;
				default:
					if(oclCanceled){
						printf("\n");
						break;
					}
					show_message(OCL_error_handling(valResp), strlen(OCL_error_handling(valResp)),
							0, ERROR_MESSAGE, true, false, false);
					break;
				}
			}
			PRINT_RESET
		}
		if(!canceledBySignal && valResp!=RETURN_OK) error_handling(0,false);
		free(c);
		PRINT_RESET;
	}
}

int hack_port_request(){
	do{
		do{
			printf("%s",C_DEFAULT);
			char *c=get_readline("Insert port to hack (0 = exit, default):",false);
			if(strcmp(c,"0")==0 || strcmp(c,"")==0){
				free(c);
				return RETURN_OK;
			}
			if(strtol(c,NULL,10)>0 && strtol(c,NULL,10)<ALL_PORTS){
				portUnderHacking=strtol(c,NULL,10);
				free(c);
				break;
			}
			show_message("Port number not valid (1-65535)\n", strlen("Port number not valid (1-65535)\n"),
					0, ERROR_MESSAGE, true, false,false);
			free(c);
		}while(true);
		if(target.ports[portUnderHacking].connectionType==UNKNOWN_CONN_TYPE){
			PRINT_RESET;
			if(target.ports[portUnderHacking].portStatus==PORT_UNKNOWN) scan_ports(portUnderHacking, false);
			switch (target.ports[portUnderHacking].portStatus){
			case PORT_FILTERED:
				printf("%sFiltered%s\n\n", C_HYELLOW, C_DEFAULT);
				continue;
			case PORT_CLOSED:
				printf("%sClosed%s\n\n", C_HGREEN, C_DEFAULT);
				continue;
			}
			int resp=0;
			if((resp=check_conn_type())<0){
				error_handling(0,false);
				continue;
			}
			target.ports[portUnderHacking].connectionType=resp;
		}
		if(hack_port()==RETURN_CLOSE) return RETURN_OK;
	}while(true);
}




