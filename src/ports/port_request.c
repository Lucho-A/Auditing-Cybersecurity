
#include <libssh2.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <readline/readline.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"

static int check_conn_type(){
	int sk=0;
	if((sk=socket(AF_INET,SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR,"");
	setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port=htons(portUnderHacking);
	serverAddress.sin_addr.s_addr= target.targetIp.s_addr;
	if(connect(sk, (struct sockaddr *) &serverAddress, sizeof(serverAddress))<0) return set_last_activity_error(SOCKET_CONNECTION_ERROR,"");
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
	SSL_CTX *sslCtx = NULL;
	sslCtx=SSL_CTX_new(SSLv23_method());
	SSL *sslConn = SSL_new(sslCtx);
	SSL_CTX_free(sslCtx);
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
	snprintf(prompt,sizeof(prompt),"%s@%s%s:%s%d%s: ",C_DEFAULT,C_HWHITE,target.strTargetIp,C_HCYAN,portUnderHacking,C_DEFAULT);
	while(TRUE){
		cancelCurrentProcess=FALSE;
		canceledBySignal=FALSE;
		int valResp=0;
		lastActivityError.errorType=0;
		//lastActivityError.exitProgram=FALSE;
		memset(lastActivityError.errorAditionalDescription,0,sizeof(lastActivityError.errorAditionalDescription));
		char *c=get_readline(prompt, FALSE);
		printf("\n");
		if(strcmp(c,"1.1")==0) valResp=any(ANY_BANNER_GRABBING);
		if(strcmp(c,"1.2")==0) valResp=any(ANY_DOS_SYN_FLOOD_ATTACK);
		if(strcmp(c,"1.3")==0) valResp=any(ANY_NMAP_VULNER_SCAN);
		if(strcmp(c,"1.4")==0) valResp=any(ANY_CODE_RED);
		if(strcmp(c,"1.5")==0) valResp=any(ANY_SEARCH_MSF);
		if(strcmp(c,"1.6")==0) valResp=any(ANY_RUN_MSF);
		if(strcmp(c,"1.7")==0) valResp=any(ANY_SEARCH_NMAP);
		if(strcmp(c,"1.8")==0) valResp=any(ANY_RUN_NMAP);
		if(strcmp(c,"1.9")==0) valResp=any(ANY_SQL_MAP);
		if(strcmp(c,"1.10")==0) valResp=any(ANY_ARP_SNIFFING);
		if(strcmp(c,"1.11")==0) valResp=any(ANY_SEARCH_CVE);

		if(strcmp(c,"2.1")==0) valResp=http(HTTP_HEADER_BANNER_GRABBING);
		if(strcmp(c,"2.2")==0) valResp=http(HTTP_TLS_GRABBING);
		if(strcmp(c,"2.3")==0) valResp=http(HTTP_METHODS_ALLOWED_GRABBING);
		if(strcmp(c,"2.4")==0) valResp=http(HTTP_SERVER_RESP_SPOOFED_HEADERS);
		if(strcmp(c,"2.5")==0) valResp=http(HTTP_GET_WEBPAGES);
		if(strcmp(c,"2.6")==0) valResp=http(HTTP_OTHERS);

		if(strcmp(c,"3.1")==0) valResp=ssh(SSH_FINGER_PRINTING);
		if(strcmp(c,"3.2")==0){
			//show_message("Activity not available", 0, WARNING_MESSAGE, TRUE);
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
		//if(strcmp(c,"8.3")==0) valResp=smtp(SMTP_BFA); //TODO
		if(strcmp(c,"8.4")==0) valResp=smtp(SMTP_BANNER_GRABBING);

		if(strcmp(c,"9.1")==0) valResp=imap(IMAP_BFA);

		if(strcmp(c,"10.1")==0) valResp=ldap(LDAP_BFA);

		if(strcmp(c,"11.1")==0) valResp=pop3(POP3_BFA);

		if(strcmp(c,"12.1")==0) valResp=oracle(ORACLE_BFA);

		if(strcmp(c,"13.1")==0) valResp=postgres(POSTGRES_BFA);

		if(strcmp(c,"14.1")==0) valResp=mssql(MSSQL_BFA);
		if(strcmp(c,"14.2")==0) valResp=mssql(MSSQL_SHELL);

		if(strcmp(c,"o")==0) valResp=others(OTHERS_SHOW_OPENED_PORTS);
		if(strcmp(c,"d")==0) valResp=others(OTHERS_ARP_DISCOVER);
		if(strcmp(c,"i")==0) valResp=others(OTHERS_INTERACTIVE);
		if(strcmp(c,"s")==0) valResp=others(OTHERS_SYSTEM_CALL);
		if(strcmp(c,"t")==0) valResp=others(OTHERS_TRACEROUTE);
		if(strcmp(c,"h")==0) valResp=others(OTHERS_SHOW_ACTIVIIES);
		if(strcmp(c,"w")==0) valResp=others(OTHERS_WHOIS);
		if(strcmp(c,"g")==0) valResp=others(OTHERS_CHATGPT);
		if(strcmp(c,"c")==0) return RETURN_OK;
		if(strcmp(c,"q")==0){
			free(c);
			cancelCurrentProcess=TRUE;
			exit(EXIT_SUCCESS);
		}
		if(!canceledBySignal && valResp!=RETURN_OK) error_handling(FALSE);
		free(c);
		PRINT_RESET;
	}
}

int hack_port_request(){
	do{
		int selectedPort=0;
		do{
			printf("%s",C_DEFAULT);
			char *c=readline("Insert port to hack (0 = exit, default): ");
			if(strcmp(c,"0")==0 || strcmp(c,"")==0) return RETURN_OK;
			for(int i=0;i<target.cantPortsToScan;i++){
				if(target.portsToScan[i].portNumber==strtol(c,NULL,10) && target.portsToScan[i].portStatus==PORT_OPENED) selectedPort=strtol(c,NULL,10);
			}
			if(selectedPort==0) show_message("\nInsert an opened port\n\n", 0, 0, ERROR_MESSAGE,FALSE);
			free(c);
		}while(selectedPort==0);
		portUnderHacking=selectedPort;
		if(target.portsToScan[get_port_index(portUnderHacking)].connectionType==UNKNOWN_CONN_TYPE){
			target.portsToScan[get_port_index(portUnderHacking)].connectionType=check_conn_type();
		}
		hack_port();
	}while(TRUE);
}




