
#include "../others/networking.h"

#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "../auditing-cybersecurity.h"

int contClosedPorts=0;
int contOpenedPorts=0;
int endScanProcess=FALSE;

static void get_iana_service_name(int port, char *serviceName){
	struct servent *service_resp=getservbyport(htons(port), "tcp");
	(service_resp==NULL)?(strcpy(serviceName,"???")):(strcpy(serviceName, service_resp->s_name));
}

int scan_init(char *urlIp){
	printf("\n");
	if(inet_addr(urlIp)!=-1){
		printf("No need to resolve the IP (%s%s%s)\n\n",C_HWHITE,urlIp,C_DEFAULT);
		target.targetIp.s_addr=inet_addr(urlIp);
	}else{
		char *ip=hostname_to_ip(urlIp);
		if(ip==NULL){
			printf("URL (%s%s%s) resolved to: %sunable to resolve the host.%s \n\n",C_HWHITE,urlIp,C_DEFAULT,C_HRED,C_DEFAULT);
			exit(EXIT_SUCCESS);
		}
		printf("URL (%s%s%s) resolved to: %s%s%s \n\n",C_HWHITE,urlIp,C_DEFAULT,C_HWHITE,ip,C_DEFAULT);
		target.targetIp.s_addr=inet_addr(ip);
	}
	snprintf(target.strTargetURL,sizeof(target.strTargetURL),"%s",urlIp);
	snprintf(target.strTargetIp, sizeof(target.strTargetIp),"%s", inet_ntoa(*((struct in_addr*)&target.targetIp.s_addr)));
	ip_to_hostname(target.strTargetIp, target.strHostname);
	printf("Hostname: %s%s%s\n\n",C_HWHITE,target.strHostname,C_DEFAULT);
	FILE *ports=NULL;
	if(target.cantPortsToScan!=ALL_PORTS){
		if(open_file(resourcesLocation,"ports.txt", &ports)==RETURN_ERROR) return set_last_activity_error(OPENING_PORT_FILE_ERROR, "");
	}
	target.portsToScan= (struct Port *) malloc(target.cantPortsToScan * sizeof(struct Port));
	for(int i=0;i<target.cantPortsToScan;i++){
		if(target.cantPortsToScan==1){
			target.portsToScan[i].portNumber=singlePortToScan;
		}else{
			(target.cantPortsToScan==ALL_PORTS)?(target.portsToScan[i].portNumber=i):(fscanf(ports,"%d,",&target.portsToScan[i].portNumber));
		}
		target.portsToScan[i].portStatus=PORT_FILTERED;
		strcpy(target.portsToScan[i].operatingSystem,"");
		get_iana_service_name(target.portsToScan[i].portNumber, target.portsToScan[i].serviceName);
		target.portsToScan[i].connectionType=UNKNOWN_CONN_TYPE;
	}
	if(ports!=NULL) fclose(ports);
	printf("%s",C_DEFAULT);
	return RETURN_OK;
}

static void process_packets(unsigned char* buffer){
	struct iphdr *iph=(struct iphdr*) buffer;
	struct sockaddr_in source,dest;
	unsigned short iphdrlen;
	if(iph->protocol==6){
		struct iphdr *iph=(struct iphdr *)buffer;
		iphdrlen=iph->ihl*4;
		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
		memset(&source,0,sizeof(source));
		source.sin_addr.s_addr=iph->saddr;
		memset(&dest,0,sizeof(dest));
		dest.sin_addr.s_addr=iph->daddr;
		for(int i=0;i<target.cantPortsToScan;i++){
			if(target.portsToScan[i].portNumber==ntohs(tcph->source) && source.sin_addr.s_addr==target.targetIp.s_addr && target.portsToScan[i].portStatus==PORT_FILTERED){
				if(tcph->syn==1 && tcph->ack==1){
					target.portsToScan[i].portStatus=PORT_OPENED;
					switch(iph->ttl){
					case 129 ... 255:
					strcpy(target.portsToScan[i].operatingSystem,"Solaris - Cisco/Network");
					break;
					case 65 ... 128:
					strcpy(target.portsToScan[i].operatingSystem,"Win");
					break;
					case 0 ... 64:
					strcpy(target.portsToScan[i].operatingSystem,"*nix");
					break;
					default:
						strcpy(target.portsToScan[i].operatingSystem,"???");
						break;
					}
					contOpenedPorts++;
					printf(REMOVE_LINE);
					printf("Opened port found: %s%d\t%s\t%s%s",C_HRED,target.portsToScan[i].portNumber,
							target.portsToScan[i].operatingSystem,target.portsToScan[i].serviceName,C_DEFAULT);
					printf("\n"REMOVE_LINE);
					break;
				}
				if(tcph->rst==1){
					target.portsToScan[i].portStatus=PORT_CLOSED;
					contClosedPorts++;
					break;
				}
			}
		}
	}
}

static int reading_packets(){
	struct timeval timeout;
	timeout.tv_sec=1;
	timeout.tv_usec=0;
	int sockRaw, bytesRecv;
	socklen_t saddrSize;
	struct sockaddr saddr;
	unsigned char *buffer = (unsigned char *) malloc(65536);
	sockRaw=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	setsockopt(sockRaw, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
	if(sockRaw<0){
		free(buffer);
		return set_last_activity_error(SOCKET_CREATION_ERROR,"");
	}
	saddrSize=sizeof saddr;
	while(endScanProcess==FALSE){
		bytesRecv=recvfrom(sockRaw,buffer,65536,0,&saddr,&saddrSize);
		if(bytesRecv<0){
			free(buffer);
			return set_last_activity_error(RECEIVING_PACKETS_ERROR,"");
		}
		if(bytesRecv>0) process_packets(buffer);
	}
	free(buffer);
	close(sockRaw);
	return RETURN_OK;
}

static void * start_reading_packets(void *args){
	reading_packets();
	pthread_exit(NULL);
}

int scan_ports(){
	struct timespec tInit, tEnd;
	clock_gettime(CLOCK_REALTIME, &tInit);
	int socketConn=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(socketConn<0) return set_last_activity_error(SOCKET_CREATION_ERROR, "");
	setsockopt(socketConn, SOL_SOCKET, SO_BINDTODEVICE, networkInfo.interfaceName, strlen(networkInfo.interfaceName));
	char datagram[4096];
	struct iphdr *iph=(struct iphdr *) datagram;
	struct tcphdr *tcph=(struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in dest;
	struct PseudoHeader psh;
	memset(datagram,0,4096);
	iph->ihl=5;
	iph->version=4;
	iph->tos=0;
	iph->tot_len=sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id=htons(65432);
	iph->frag_off=htons(16384);
	iph->ttl=255; //spoofed
	iph->protocol=IPPROTO_TCP;
	iph->check=0;
	iph->saddr=inet_addr(networkInfo.interfaceIp);
	iph->daddr=target.targetIp.s_addr;
	iph->check=csum((unsigned short *) datagram, iph->tot_len >> 1);
	//tcph->source=htons(65000);
	//tcph->dest=htons(80);
	tcph->seq=htonl(1234567890);
	tcph->ack_seq=0;
	tcph->doff=sizeof(struct tcphdr)/4;
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window=htons(65535);
	tcph->check=0;
	tcph->urg_ptr=0;
	int one=1;
	const int *val=&one;
	if(setsockopt(socketConn,IPPROTO_IP,IP_HDRINCL,val,sizeof(one))<0) return set_last_activity_error(SOCKET_SETOPT_ERROR, "");
	pthread_t readingPacketsThread;
	if(pthread_create(&readingPacketsThread,NULL,&start_reading_packets,NULL)<0) return set_last_activity_error(THREAD_CREATION_ERROR, "");
	dest.sin_family=AF_INET;
	dest.sin_port=0;
	dest.sin_addr.s_addr=target.targetIp.s_addr;
	psh.source_address=inet_addr(networkInfo.interfaceIp);
	psh.dest_address=dest.sin_addr.s_addr;
	psh.protocol=IPPROTO_TCP;
	int contFilteredPortsChange=target.cantPortsToScan, endSendPackets=0, contFilteredPorts=0;
	Bool recheck=FALSE;
	while(endSendPackets!=PACKET_FORWARDING_LIMIT){
		int contF=1;
		for(int i=0;i<target.cantPortsToScan && cancelCurrentProcess==FALSE;i++){
			if(target.portsToScan[i].portStatus==PORT_FILTERED){
				if(!recheck){
					printf("\rQuerying port: %d (%d/%d)     ",target.portsToScan[i].portNumber, contF,contFilteredPortsChange);
				}else{
					printf("\rRe-querying port: %d (%d/%d)     ",target.portsToScan[i].portNumber, contF,contFilteredPortsChange);
				}
				fflush(stdout);
				tcph->source=htons(rand()%60000+1024);
				tcph->dest=htons(target.portsToScan[i].portNumber);
				tcph->check=0;
				psh.placeholder=0;
				psh.tcp_length=htons(sizeof(struct tcphdr));
				memcpy(&psh.tcp,tcph,sizeof(struct tcphdr));
				tcph->check=csum((unsigned short*) &psh,sizeof(struct PseudoHeader));
				if(sendto(socketConn,datagram,sizeof(struct iphdr)+sizeof(struct tcphdr),0,(struct sockaddr *) &dest,sizeof (dest))<0) return set_last_activity_error(SENDING_PACKETS_ERROR,"");
				usleep(sendPacketPerPortDelayUs);
				contF++;
			}
		}
		printf(REMOVE_LINE);
		printf(REMOVE_LINE);
		printf(REMOVE_LINE);
		usleep(SEND_PACKET_DELAY_US);
		if(cancelCurrentProcess) break;
		contFilteredPorts=target.cantPortsToScan-contOpenedPorts-contClosedPorts;
		if(contFilteredPorts==0) break;
		(contFilteredPortsChange==contFilteredPorts)?(endSendPackets++):(endSendPackets=0);
		contFilteredPortsChange=contFilteredPorts;
		contFilteredPorts=0;
		recheck=TRUE;
	}
	endScanProcess=TRUE;
	pthread_join(readingPacketsThread, NULL);
	contFilteredPorts=target.cantPortsToScan-contOpenedPorts-contClosedPorts;
	Bool anyPortShown=FALSE;
	if(cancelCurrentProcess==FALSE){
		for(int i=0;i<target.cantPortsToScan;i++){
			if(target.portsToScan[i].portStatus==PORT_OPENED){
				anyPortShown=TRUE;
				break;
			}
		}
		clock_gettime(CLOCK_REALTIME, &tEnd);
		double elapsedTime=(tEnd.tv_sec-tInit.tv_sec)+(tEnd.tv_nsec-tInit.tv_nsec)/1000000000.0;
		printf("%s",C_DEFAULT);
		if(anyPortShown) printf("\nThe identified service names are the IANA standards ones and could differ in practice.\n\n");
		printf("Scanned ports: %d in %.3lf secs\n\n",target.cantPortsToScan, elapsedTime);
		printf("%s",C_HGREEN);
		printf("\tClosed: %d\n", contClosedPorts);
		printf("%s",C_HYELLOW);
		printf("\tFiltered: %d\n",contFilteredPorts);
		printf("%s",C_HRED);
		printf("\tOpened: %d\n\n",contOpenedPorts);
	}
	close(socketConn);
	cancelCurrentProcess=FALSE;
	printf("%s",C_DEFAULT);
	return RETURN_OK;
}

