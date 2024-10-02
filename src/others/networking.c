
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <readline/readline.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "libpcap.h"

void clean_ssl(SSL *ssl){
	if(ssl!=NULL){
		SSL_shutdown(ssl);
		SSL_certs_clear(ssl);
		SSL_clear(ssl);
		SSL_free(ssl);
	}
}

char * get_ttl_description(int ttlValue){
	switch(ttlValue){
	case 129 ... 255:
	return "Solaris-Cisco/Network";
	case 65 ... 128:
	return"Win";
	break;
	case 0 ... 64:
	return "*nix";
	default:
		return "???";
	}
}

static int get_public_ip(unsigned char **serverResp){
	struct hostent *he;
	struct in_addr **addrList;
	if((he=gethostbyname("api.ipify.org"))==NULL) return set_last_activity_error(GETADDRINFO_ERROR, "");
	addrList=(struct in_addr **) he->h_addr_list;
	if(addrList[0]==NULL) return set_last_activity_error(GETADDRINFO_ERROR, "");;
	char *msg="GET / HTTP/1.1\r\n"
			"Host: api.ipify.org\r\n"
			"user-agent: auditing-cybersecurity\r\n"
			"accept: */*\r\n"
			"connection: close\r\n\r\n";
	struct in_addr ip;
	ip.s_addr=inet_addr(inet_ntoa(*addrList[0]));
	int conn=0;
	int br=0;
	if((br=send_msg_to_server(&conn,ip,"api.ipify.org",443, SSL_CONN_TYPE, msg,strlen(msg),
			serverResp, BUFFER_SIZE_8K,0))<0) return RETURN_ERROR;
	close(conn);
	return br;
}

static void get_local_ip(char *buffer){
	int socketConn=socket(AF_INET,SOCK_DGRAM,0);
	setsockopt(socketConn, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	const char* dnsIp="1.1.1.1";
	int dns_port=53;
	struct sockaddr_in serv;
	memset(&serv,0,sizeof(serv));
	serv.sin_family=AF_INET;
	serv.sin_addr.s_addr=inet_addr(dnsIp);
	serv.sin_port=htons(dns_port);
	if(connect(socketConn,(const struct sockaddr*) &serv,sizeof(serv))<0) error_handling(SOCKET_CONNECTION_ERROR,TRUE);
	struct sockaddr_in name;
	socklen_t namelen=sizeof(name);
	if(getsockname(socketConn,(struct sockaddr*) &name, &namelen)<0) error_handling(GETSOCKNAME_ERROR,TRUE);
	const char *p=inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
	if(p==NULL) error_handling(INET_NTOP_ERROR,TRUE);
	close(socketConn);
}

int init_networking(){
	char errbuf[PCAP_ERRBUF_SIZE]="";
	pcap_if_t *devs=NULL, *dev=NULL;
	pcap_init(PCAP_CHAR_ENC_UTF_8,errbuf);
	pcap_findalldevs(&devs, errbuf);
	if(devs->name==NULL){
		pcap_freealldevs(devs);
		pcap_freealldevs(dev);
		return set_last_activity_error(DEVICE_NOT_FOUND_ERROR, "");
	}
	int cantDevs=0, selectedOpt=0;
	for(dev=devs;dev!=NULL;dev=dev->next){
		if((dev->flags & PCAP_IF_UP) && (dev->flags & PCAP_IF_RUNNING) && !(dev->flags & PCAP_IF_LOOPBACK)
				&& strcmp(dev->name, "any")!=0) cantDevs++;
	}
	if(cantDevs==0){
		pcap_freealldevs(devs);
		return set_last_activity_error(DEVICE_NOT_FOUND_ERROR, "");
	}
	printf("\n");
	if(cantDevs==1){
		snprintf(networkInfo.interfaceName,255,"%s",devs->name);
		printf("Only one device found. Using: %s%s%s\n",C_HWHITE, networkInfo.interfaceName, C_DEFAULT);
	}else{
		printf("Devices found:\n\n");
		int cont=1;
		for(dev=devs;dev!=NULL;dev=dev->next){
			if((dev->flags & PCAP_IF_UP) && (dev->flags & PCAP_IF_RUNNING) && !(dev->flags & PCAP_IF_LOOPBACK)
					&& strcmp(dev->name, "any")!=0){
				printf("\t%d) %s%s%s\n",cont, C_HWHITE, dev->name, C_DEFAULT);
				cont++;
			}
		}
		do{
			char *c=get_readline("\nSelect device number: ",FALSE);
			selectedOpt=strtol(c,NULL,10);
			free(c);
			if(selectedOpt<1 || selectedOpt>cantDevs) continue;
			break;
		}while(TRUE);
		int i=1;
		for(dev=devs;dev!=NULL;dev=dev->next,i++){
			if((dev->flags & PCAP_IF_UP) && (dev->flags & PCAP_IF_RUNNING) && !(dev->flags & PCAP_IF_LOOPBACK) && i==selectedOpt){
				snprintf(networkInfo.interfaceName,sizeof(networkInfo.interfaceName),"%s",dev->name);
				break;
			}
		}
	}
	pcap_freealldevs(devs);
	char addressPath[BUFFER_SIZE_512B]="";
	snprintf(addressPath,BUFFER_SIZE_512B, "/sys/class/net/%s/address", networkInfo.interfaceName);
	FILE *f=fopen(addressPath,"r");
	size_t len=20;
	if(f!=NULL) while(getline(&networkInfo.interfaceMac, &len,f)!=-1);
	if(f!=NULL) fclose(f);
	if(networkInfo.interfaceMac==NULL) return set_last_activity_error(DEVICE_MAC_NOT_FOUND_ERROR, "");
	networkInfo.interfaceMac[strlen(networkInfo.interfaceMac)-1]='\0';
	printf("\nDevice MAC: %s%s%s\n", C_HWHITE, networkInfo.interfaceMac, C_DEFAULT);
	sscanf(networkInfo.interfaceMac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&networkInfo.interfaceMacHex[0], &networkInfo.interfaceMacHex[1], &networkInfo.interfaceMacHex[2],
			&networkInfo.interfaceMacHex[3], &networkInfo.interfaceMacHex[4], &networkInfo.interfaceMacHex[5]);
	get_local_ip(networkInfo.interfaceIp);
	printf("\nLocal IP: %s%s%s\n", C_HWHITE, networkInfo.interfaceIp, C_DEFAULT);
	unsigned char *publicIp=NULL;
	int br=get_public_ip(&publicIp);
	if(br<1){
		printf("\nPublic IP: %sNo Internet connection%s\n",C_HRED,C_DEFAULT);
		networkInfo.internetAccess=FALSE;
	}else{
		char *buffer="";
		buffer=strstr((char *) publicIp,"\n\r\n");
		printf("\nPublic IP: %s", C_HWHITE);
		for(int i=3;i<strlen(buffer);i++) printf("%c", buffer[i]);
		networkInfo.internetAccess=TRUE;
		PRINT_RESET
	}
	free(publicIp);
	if (pcap_lookupnet(networkInfo.interfaceName, &networkInfo.net, &networkInfo.mask, errbuf)==-1) {
		show_message("Unable to getting the netmask.",0, 0, ERROR_MESSAGE, TRUE);
		networkInfo.net=networkInfo.mask=0;
	}
	networkInfo.netMask.s_addr=networkInfo.net&networkInfo.mask;
	printf("\nLocal network: %s%s%s\n", C_HWHITE, inet_ntoa(networkInfo.netMask), C_DEFAULT);
	networkInfo.netBroadcast.s_addr=networkInfo.netMask.s_addr | ~networkInfo.mask;
	printf("\nBroadcast: %s%s%s\n", C_HWHITE, inet_ntoa(networkInfo.netBroadcast), C_DEFAULT);
	printf("\nChecking updates: ");
	fflush(stdout);
	if(networkInfo.internetAccess){
		int latestVersion=check_updates();
		if(latestVersion==RETURN_ERROR){
			printf("%s%s",C_HRED,"connection error");
			PRINT_RESET;
		}else{
			if(latestVersion){
				printf("%sup-to-date",C_HGREEN);
			}else{
				printf("%sout-of-date. You can download the latest version from: https://github.com/Lucho-A/Auditing-Cybersecurity/releases/tag/Latest",C_HRED);
			}
		}
	}else{
		printf("%s%s",C_HRED,"Unable to check updates");
	}
	PRINT_RESET;
	printf("\nChecking Ollama server status: ");
	fflush(stdout);
	int ollamaStatus=ollama_check_service_status();
	if(ollamaStatus==RETURN_ERROR){
		printf("%s%s",C_HRED,"connection error");
		PRINT_RESET;
	}else{
		if(ollamaStatus){
			printf("%srunning",C_HGREEN);
		}else{
			printf("%snot available",C_HRED);
		}
	}
	PRINT_RESET;
	return RETURN_OK;
}

void show_opened_ports(){
	for(int i=0;i<ALL_PORTS;i++){
		if(target.ports[i].portStatus==PORT_OPENED) printf("%s  Port: %d \t(%s?)\n",C_HRED,i, target.ports[i].serviceName);
	}
	printf("%s",C_DEFAULT);
}

void show_filtered_ports(){
	for(int i=0;i<ALL_PORTS;i++){
		if(target.ports[i].portStatus==PORT_FILTERED) printf("%s  Port: %d \t(%s?)\n",C_HYELLOW,i, target.ports[i].serviceName);
	}
	printf("%s",C_DEFAULT);
}

int create_socket_conn(int *sk){
	struct timeval timeout;
	timeout.tv_sec=SOCKET_CONNECT_TIMEOUT_S;
	timeout.tv_usec=0;
	if((*sk=socket(AF_INET,SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR, "");
	setsockopt(*sk, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	setsockopt(*sk, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
	setsockopt(*sk, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
	struct sockaddr_in serverAddress;
	serverAddress.sin_family=AF_INET;
	serverAddress.sin_port=htons(portUnderHacking);
	serverAddress.sin_addr.s_addr=target.targetIp.s_addr;
	int flags = fcntl(*sk, F_GETFL, 0);
	fcntl(*sk, F_SETFL, flags | O_NONBLOCK);
	int resp=0;
	resp=connect(*sk,(struct sockaddr *)&serverAddress,sizeof(serverAddress));
	if(resp==0){
		fcntl(*sk, F_SETFL, flags);
		return RETURN_OK;
	}
	if(errno!=EINPROGRESS){
		fcntl(*sk,F_SETFL,flags);
		return set_last_activity_error(SOCKET_CONNECTION_ERROR, "");
	}
	fd_set writefds;
	FD_ZERO(&writefds);
	FD_SET(*sk,&writefds);
	resp=select(*sk+1,NULL,&writefds,NULL,&timeout);
	fcntl(*sk,F_SETFL,flags);
	if (resp<=0) return set_last_activity_error(SOCKET_CONNECTION_TIMEOUT_ERROR, "");
	return RETURN_OK;
}

int send_msg_to_server(int *sk, struct in_addr ip, char *url, int port, int type, char *msg,
		long int msgSize, unsigned char **serverResp, long int maxSizeResponse, long int extraTimeOut){
	*serverResp=malloc(maxSizeResponse);
	memset(*serverResp,0,maxSizeResponse);
	struct pollfd pfds[1];
	int numEvents=0,pollinHappened=0,bytesSent=0,contSendingAttemps=0;
	SSL *sslConn=NULL;
	do{
		if(type==UNKNOWN_CONN_TYPE) return set_last_activity_error(UNKNOW_CONNECTION_ERROR, "");
		struct sockaddr_in serverAddress;
		serverAddress.sin_family=AF_INET;
		serverAddress.sin_port=htons(port);
		serverAddress.sin_addr.s_addr=ip.s_addr;
		if(*sk==0){
			if((*sk=socket(AF_INET, SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR, "");
			setsockopt(*sk, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
		}
		int socketFlags = fcntl(*sk, F_GETFL, 0);
		fcntl(*sk, F_SETFL, socketFlags | O_NONBLOCK);
		int valResp=connect(*sk, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
		if(valResp<0 && errno!=EINPROGRESS) return set_last_activity_error(DEVICE_NOT_FOUND_ERROR, "");
		struct timeval tv;
		fd_set writefds;
		FD_ZERO(&writefds);
		FD_SET(*sk,&writefds);
		tv.tv_sec=SOCKET_CONNECT_TIMEOUT_S;
		tv.tv_usec=0;
		SSL_CTX *sslCtx=NULL;
		if(select(*sk+1,NULL,&writefds,NULL,&tv)<=0) return set_last_activity_error(SOCKET_CONNECTION_TIMEOUT_ERROR, "");
		if(type==SSL_CONN_TYPE){
			fcntl(*sk, F_SETFL, socketFlags);
			if((sslCtx=SSL_CTX_new(SSLv23_method()))==NULL){
				SSL_CTX_free(sslCtx);
				return set_last_activity_error(SSL_CONTEXT_ERROR, "");
			}
			//SSL_CTX_set_verify(sslCtx, SSL_VERIFY_PEER, NULL);
			//SSL_CTX_set_default_verify_paths(sslCtx);
			if((sslConn=SSL_new(sslCtx))==NULL){
				clean_ssl(sslConn);
				SSL_CTX_free(sslCtx);
				return set_last_activity_error(SSL_CONTEXT_ERROR, "");
			}
			if(!SSL_set_fd(sslConn,*sk)){
				clean_ssl(sslConn);
				SSL_CTX_free(sslCtx);
				return set_last_activity_error(SSL_FD_ERROR, "");
			}
			SSL_set_connect_state(sslConn);
			SSL_set_tlsext_host_name(sslConn, url);
			if(!SSL_connect(sslConn)){
				clean_ssl(sslConn);
				SSL_CTX_free(sslCtx);
				return set_last_activity_error(SSL_CONNECT_ERROR, "");
			}
			SSL_CTX_free(sslCtx);
		}
		fcntl(*sk, F_SETFL, O_NONBLOCK);
		pfds[0].fd=*sk;
		pfds[0].events=POLLOUT;
		numEvents=poll(pfds,1,SOCKET_SEND_TIMEOUT_MS);
		if(numEvents==0){
			if(contSendingAttemps==0){
				show_message("\n  Timeout sending message. Trying to re-connect and sending the message again...",0, errno, ERROR_MESSAGE, TRUE);
				contSendingAttemps++;
				continue;
			}
			show_message("  Second timeout (IP locked?). Returning...",0, errno, ERROR_MESSAGE, TRUE);
			return SENDING_PACKETS_ERROR;
		}
		pollinHappened=pfds[0].revents & POLLOUT;
		if(pollinHappened){
			switch(type){
			case SOCKET_CONN_TYPE:
			case SSH_CONN_TYPE:
				bytesSent=send(*sk, msg, msgSize, 0);
				break;
			case SSL_CONN_TYPE:
				bytesSent=SSL_write(sslConn, msg, msgSize);
				break;
			default:
				break;
			}
			if(bytesSent<=0){
				if(contSendingAttemps==0){
					show_message("\n  Error sending message. Trying to re-connect and sending the message again...",0, 0, ERROR_MESSAGE, TRUE);
					contSendingAttemps++;
					continue;
				}else{
					show_message("Error sending message (IP locked?). Returning...",0,0, ERROR_MESSAGE, TRUE);
					clean_ssl(sslConn);
					return set_last_activity_error(SENDING_PACKETS_ERROR, "");
				}
			}else{
				break;
			}
		}else{
			clean_ssl(sslConn);
			return POLLIN_ERROR;
		}
	}while(contSendingAttemps<2);
	int bytesReceived=0,totalBytesReceived=0;
	pfds[0].events=POLLIN;
	char buffer[BUFFER_SIZE_16K]="", *bufferHTTP=NULL;
	if((bufferHTTP=malloc(1))==NULL){
		clean_ssl(sslConn);
		return set_last_activity_error(MALLOC_ERROR, "");
	}
	bufferHTTP[0]='\0';
	int cont=0;
	do{
		memset(buffer,0,BUFFER_SIZE_16K);
		numEvents=poll(pfds, 1, SOCKET_RECV_TIMEOUT_MS + extraTimeOut);
		if(numEvents==0) break;
		pollinHappened=pfds[0].revents & POLLIN;
		if (pollinHappened){
			switch(type){
			case SOCKET_CONN_TYPE:
			case SSH_CONN_TYPE:
				bytesReceived=recv(*sk, buffer, BUFFER_SIZE_16K,0);
				break;
			case SSL_CONN_TYPE:
				bytesReceived=SSL_read(sslConn,buffer, BUFFER_SIZE_16K);
				break;
			default:
				break;
			}
			// info received
			if(bytesReceived>0){
				totalBytesReceived+=bytesReceived;
				bufferHTTP=realloc(bufferHTTP, totalBytesReceived+1);
				if(bufferHTTP==NULL){
					clean_ssl(sslConn);
					return set_last_activity_error(REALLOC_ERROR, "");
				}
				for(int i=0;i<bytesReceived;i++,cont++) bufferHTTP[cont]=buffer[i];
				continue;
			}
			// server OK closed the connection
			if(bytesReceived==0) break;
			// socket still open
			if(bytesReceived<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) continue;
			// error receiving
			if(bytesReceived<0 && (errno!=EAGAIN)){
				clean_ssl(sslConn);
				// reseted by peer
				free(bufferHTTP);
				return set_last_activity_error(RECEIVING_PACKETS_ERROR, "");
			}
		}else{
			free(bufferHTTP);
			return set_last_activity_error(POLLIN_ERROR, "");
		}
	}while(TRUE);
	for(int i=0;i<maxSizeResponse && i<totalBytesReceived;i++) (*serverResp)[i]=bufferHTTP[i];
	free(bufferHTTP);
	clean_ssl(sslConn);
	if(totalBytesReceived==0) return set_last_activity_error(ZERO_BYTES_RECV_ERROR, "");
	return totalBytesReceived;
}

void ip_to_hostname(char *ip, char *hostname){
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &sa.sin_addr);
	char host[1024], service[20];
	int valResp=getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof host, service, sizeof service, 0);
	(!valResp)?(snprintf(hostname,sizeof(host),"%s",host)):(snprintf(hostname,sizeof(host),"%s",""));
}

char* hostname_to_ip(char *hostname){
	struct hostent *he;
	struct in_addr **addr_list;
	if((he=gethostbyname(hostname))==NULL) return NULL;
	addr_list=(struct in_addr **) he->h_addr_list;
	for(int i=0;addr_list[i]!=NULL;i++) return inet_ntoa(*addr_list[i]);
	return NULL;
}

unsigned short csum(unsigned short *ptr,int nbytes){
	register long sum;
	unsigned short oddbyte;
	register short r;
	sum=0;
	while(nbytes>1){
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1){
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
	sum=(sum>>16)+(sum & 0xffff);
	sum=sum+(sum>>16);
	r=(short)~sum;
	return(r);
}

