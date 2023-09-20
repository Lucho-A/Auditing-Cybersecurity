
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <readline/readline.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "libpcap.h"

static void clean_ssl(SSL *ssl){
	if(ssl!=NULL){
		SSL_shutdown(ssl);
		SSL_certs_clear(ssl);
		SSL_clear(ssl);
		SSL_free(ssl);
	}
}

static void get_local_ip(char * buffer){
	int socketConn=socket(AF_INET,SOCK_DGRAM,0);
	setsockopt(socketConn, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	const char* kGoogleDnsIp="8.8.8.8";
	int dns_port=53;
	struct sockaddr_in serv;
	memset(&serv,0,sizeof(serv));
	serv.sin_family=AF_INET;
	serv.sin_addr.s_addr=inet_addr(kGoogleDnsIp);
	serv.sin_port=htons(dns_port);
	if(connect(socketConn,(const struct sockaddr*) &serv,sizeof(serv))<0) error_handling(TRUE);
	struct sockaddr_in name;
	socklen_t namelen=sizeof(name);
	if(getsockname(socketConn,(struct sockaddr*) &name, &namelen)<0) error_handling(TRUE);
	const char *p=inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
	if(p==NULL) error_handling(TRUE);
	close(socketConn);
}

int init_networking(){
	char errbuf[PCAP_ERRBUF_SIZE]="";
	pcap_if_t *devs=NULL, *dev=NULL;
	pcap_findalldevs(&devs, errbuf);
	if(devs->name==NULL) return set_last_activity_error(DEVICE_NOT_FOUND_ERROR, "");
	int cantDevs=0, selectedOpt=0;
	for(dev=devs;dev!=NULL;dev=dev->next){
		if((dev->flags & PCAP_IF_UP) && (dev->flags & PCAP_IF_RUNNING) && !(dev->flags & PCAP_IF_LOOPBACK) && strcmp(dev->name, "any")!=0) cantDevs++;
	}
	if(cantDevs==0) return set_last_activity_error(DEVICE_NOT_FOUND_ERROR, "");
	if(cantDevs==1){
		snprintf(networkInfo.interfaceName,255,"%s",devs->name);
		printf("Only one device found. Using: %s%s%s\n",C_HWHITE, networkInfo.interfaceName, C_DEFAULT);
	}else{
		printf("Devices found:\n\n");
		int cont=1;
		for(dev=devs;dev!=NULL;dev=dev->next){
			if((dev->flags & PCAP_IF_UP) && (dev->flags & PCAP_IF_RUNNING) && !(dev->flags & PCAP_IF_LOOPBACK) && strcmp(dev->name, "any")!=0){
				printf("\t%d) %s%s%s\n",cont, C_HWHITE, dev->name, C_DEFAULT);
				cont++;
			}
		}
		do{
			char *c=readline("\nSelect device number: ");
			selectedOpt=strtol(c,NULL,10);
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
	if (pcap_lookupnet(networkInfo.interfaceName, &networkInfo.net, &networkInfo.mask, errbuf)==-1) {
		show_message("Unable to getting the netmask.",0, 0, ERROR_MESSAGE, TRUE);
		networkInfo.net=networkInfo.mask=0;
	}
	networkInfo.netMask.s_addr=networkInfo.net&networkInfo.mask;
	printf("\nLocal network: %s%s%s\n", C_HWHITE, inet_ntoa(networkInfo.netMask), C_DEFAULT);
	networkInfo.netBroadcast.s_addr=networkInfo.netMask.s_addr | ~networkInfo.mask;
	printf("\nBroadcast: %s%s%s\n", C_HWHITE, inet_ntoa(networkInfo.netBroadcast), C_DEFAULT);
	return RETURN_OK;
}

int get_port_index(int port){
	for(int i=0;i<target.cantPortsToScan;i++){
		if(target.portsToScan[i].portNumber==port) return i;
	}
	return RETURN_ERROR;
}

void show_opened_ports(){
	for(int i=0;i<target.cantPortsToScan;i++){
		if(target.portsToScan[i].portStatus==PORT_OPENED) printf("%s  Port: %d \t(%s?)\n",C_HRED,target.portsToScan[i].portNumber, target.portsToScan[i].serviceName);
	}
	printf("%s",C_DEFAULT);
}

int create_socket_conn(int *socketConn){
	struct timeval timeout;
	timeout.tv_sec=SOCKET_CONNECT_TIMEOUT_S;
	timeout.tv_usec=0;
	if((*socketConn=socket(AF_INET,SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR, "");
	setsockopt(*socketConn, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	setsockopt(*socketConn, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
	setsockopt(*socketConn, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
	struct sockaddr_in serverAddress;
	serverAddress.sin_family=AF_INET;
	serverAddress.sin_port=htons(portUnderHacking);
	serverAddress.sin_addr.s_addr=target.targetIp.s_addr;
	if(connect(*socketConn,(struct sockaddr *)&serverAddress,sizeof(serverAddress))<0) return set_last_activity_error(SOCKET_CONNECTION_ERROR, "");
	return RETURN_OK;
}

int send_payloaded_msg_to_server(int *sk, char *payload, char *serverResp, int lenght){
	if(*sk==0) if(create_socket_conn(sk)==RETURN_ERROR) return RETURN_ERROR;
	int bytesSent=send(*sk,payload,lenght,0);
	if(bytesSent<=0) return set_last_activity_error(SENDING_PACKETS_ERROR, "");
	int bytesReceived=0;
	char buffer[BUFFER_SIZE_8K]={0};
	bytesReceived=recv(*sk, buffer, BUFFER_SIZE_8K,0);
	if(bytesReceived<0) return set_last_activity_error(RECEIVING_PACKETS_ERROR, "");
	for(int i=0;i<bytesReceived; i++) serverResp[i]=buffer[i];
	return bytesReceived;
}

int send_msg_to_server(struct in_addr ip, char *hostname, int port, int connType, char *localMsg, char **serverResp, long int sizeResponse, long int extraTimeOut){
	struct pollfd pfds[1];
	int numEvents=0,pollinHappened=0,bytesSent=0,contSendingAttemps=0;
	SSL *sslConn=NULL;
	int localSocketConn=0;
	*serverResp= malloc(sizeResponse * sizeof(**serverResp));
	//memset(*serverResp,0,sizeResponse * sizeof(char*));
	do{
		if(connType==UNKNOWN_CONN_TYPE) return set_last_activity_error(UNKNOW_CONNECTION_ERROR, "");
		struct sockaddr_in serverAddress;
		serverAddress.sin_family=AF_INET;
		serverAddress.sin_port=htons(port);
		serverAddress.sin_addr.s_addr=ip.s_addr;
		if((localSocketConn=socket(AF_INET, SOCK_STREAM, 0))<0) return set_last_activity_error(SOCKET_CREATION_ERROR, "");
		setsockopt(localSocketConn, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
		int socketFlags = fcntl(localSocketConn, F_GETFL, 0);
		fcntl(localSocketConn, F_SETFL, socketFlags | O_NONBLOCK);
		int valResp=connect(localSocketConn, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
		if(valResp<0 && errno!=EINPROGRESS) return set_last_activity_error(DEVICE_NOT_FOUND_ERROR, "");
		struct timeval tv;
		tv.tv_sec=0;
		tv.tv_usec=0;
		fd_set rFdset, wFdset;
		FD_ZERO(&rFdset);
		FD_SET(localSocketConn, &rFdset);
		wFdset=rFdset;
		tv.tv_sec=SOCKET_CONNECT_TIMEOUT_S;
		tv.tv_usec=0;
		if(select(localSocketConn+1,&rFdset,&wFdset,NULL,&tv)<=0) return set_last_activity_error(SOCKET_CONNECTION_TIMEOUT_ERROR, "");
		if(connType== SSL_CONN_TYPE){
			fcntl(localSocketConn, F_SETFL, socketFlags);
			SSL_CTX *sslCtx=NULL;
			if((sslCtx=SSL_CTX_new(SSLv23_method()))==NULL){
                SSL_CTX_free(sslCtx);
				return set_last_activity_error(SSL_CONTEXT_ERROR, "");
			}
			if((sslConn=SSL_new(sslCtx))==NULL){
				clean_ssl(sslConn);
				SSL_CTX_free(sslCtx);
				return set_last_activity_error(SSL_CONTEXT_ERROR, "");
			}
			if(!SSL_set_fd(sslConn, localSocketConn)){
				clean_ssl(sslConn);
				SSL_CTX_free(sslCtx);
				return set_last_activity_error(SSL_FD_ERROR, "");
			}
			SSL_set_connect_state(sslConn);
			//TODO
			if(hostname==NULL){
				SSL_set_tlsext_host_name(sslConn, target.strTargetURL);
			}else{
				SSL_set_tlsext_host_name(sslConn, hostname);
			}
			if(!SSL_connect(sslConn)){
				clean_ssl(sslConn);
				SSL_CTX_free(sslCtx);
				return set_last_activity_error(SSL_CONNECT_ERROR, "");
			}
			SSL_CTX_free(sslCtx);
		}
		fcntl(localSocketConn, F_SETFL, O_NONBLOCK);
		if(connType==UNKNOWN_CONN_TYPE) return set_last_activity_error(UNKNOW_CONNECTION_ERROR, "");
		if(strcmp(localMsg,"")==0 || localMsg==NULL) return RETURN_OK;
		pfds[0].fd=localSocketConn;
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
			switch(connType){
			case SOCKET_CONN_TYPE:
			case SSH_CONN_TYPE:
				bytesSent=send(localSocketConn, localMsg, strlen(localMsg), 0);
				break;
			case SSL_CONN_TYPE:
				bytesSent=SSL_write(sslConn, localMsg, strlen(localMsg));
				break;
			default:
				break;
			}
			if(bytesSent<=0){
				close(localSocketConn);
				if(contSendingAttemps==0){
					show_message("\n  Error sending message. Trying to re-connect and sending the message again...",0, 0, ERROR_MESSAGE, TRUE);
					contSendingAttemps++;
					continue;
				}else{
					show_message("Error sending message (IP locked?). Returning...",0,0, ERROR_MESSAGE, TRUE);
					close(localSocketConn);
					clean_ssl(sslConn);
					return set_last_activity_error(SENDING_PACKETS_ERROR, "");
				}
			}else{
				break;
			}
		}else{
			close(localSocketConn);
			clean_ssl(sslConn);
			return POLLIN_ERROR;
		}
	}while(contSendingAttemps<2);
	int bytesReceived=0,contI=0, totalBytesReceived=0;;
	pfds[0].events=POLLIN;
	char buffer[BUFFER_SIZE_16K]="";
	do{
		numEvents=poll(pfds, 1, SOCKET_RECV_TIMEOUT_MS + extraTimeOut);
		if(numEvents==0){
			close(localSocketConn);
			clean_ssl(sslConn);
			break;
		}
		pollinHappened = pfds[0].revents & POLLIN;
		if (pollinHappened){
			switch(connType){
			case SOCKET_CONN_TYPE:
			case SSH_CONN_TYPE:
				bytesReceived=recv(localSocketConn, buffer, BUFFER_SIZE_16K,0);
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
				if(contI>=sizeResponse){
					close(localSocketConn);
					break;
				}
				for(int i=0; contI<sizeResponse && i<bytesReceived; i++, contI++) (*serverResp)[contI]=buffer[i];
				continue;
			}
			// server OK closed the connection
			if(bytesReceived==0){
				close(localSocketConn);
				break;
			}
			// socket still open
			if(bytesReceived<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) continue;
			// error receiving
			if(bytesReceived<0 && (errno!=EAGAIN)){
				close(localSocketConn);
				clean_ssl(sslConn);
				// reseted by peer
				return set_last_activity_error(RECEIVING_PACKETS_ERROR, "");
			}
		}else{
			return set_last_activity_error(POLLIN_ERROR, "");
		}
	}while(TRUE);
	clean_ssl(sslConn);
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

char* hostname_to_ip(char * hostname){
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

