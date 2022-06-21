/*
 ============================================================================
 Name        : TCP Syn Port Scanner.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : TCP Syn Port Scanner developed in C, Ansi-style
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

char target[500]="";
int contClosedPorts=0;
int contOpenedPorts=0;
int contFilteredPorts=0;
int portStatus[65536]={-1};
int portsToScan[CANT_PORTS]={0};
int cantPortToScan=0;
int endProces=FALSE;

int main(int argc, char *argv[]){
	system("clear");
	printf("%s",CYAN);
	printf("\n*******************************************************\n");
	printf("\n%sTCP Syn Port Scanner by L.\n",HCYAN);
	printf("\n%sv1.0.5\n",CYAN);
	printf("\n*******************************************************\n");
	printf("%s",DEFAULT);
	if(getuid()!=0){
		show_error("\nYou must be root for running the program.\n",0);
		exit(EXIT_FAILURE);
	}
	int contFilteredPortsChange=-1, endSendPackets=0, i=0;
	struct timespec tInit, tEnd;
	switch(argc){
	case 3:
		if(strtol(argv[2],NULL,10)>0 && strtol(argv[2],NULL,10)<5001){
			int argOK=TRUE;
			snprintf(target,sizeof(target),"%s",argv[1]);
			cantPortToScan=strtol(argv[2],NULL,10);
			if(argOK==TRUE) break;
		}
		/* no break */
	default:
		printf("%s",WHITE);
		printf("\nUsage (as root): 'TCP Syn Port Scanner' ip|url cantPortToScan (1-5000)\n");
		printf("v.gr: 'TCP Syn Port Scanner' www.scanme.org 500\n\n");
		exit(EXIT_FAILURE);
	}
	clock_gettime(CLOCK_REALTIME, &tInit);
	FILE *f=NULL;
	if((f=fopen(PATH_TO_RESOURCES "Ports.txt","r"))==NULL){
		printf("%s",HRED);
		printf("fopen(%s) error: Error: %d (%s)\n", "Ports.txt", errno, strerror(errno));
		printf("%s",DEFAULT);
		exit(EXIT_FAILURE);
	}
	i=0;
	while(fscanf(f,"%d,",&portsToScan[i])!=EOF) i++;
	for(int i=0;i<cantPortToScan;i++) portStatus[portsToScan[i]]=-1;
	printf("%s",WHITE);
	time_t timestamp = time(NULL);
	struct tm tm = *localtime(&timestamp);
	printf("\nStarting TCP Syn Port Scanning... (%d/%02d/%02d %02d:%02d:%02d)\n\n",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	printf("%s",DEFAULT);
	int sk=socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
	if(sk<0){
		show_error("socket() error.", errno);
		exit(EXIT_FAILURE);
	}
	char datagram[4096];
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in  dest;
	struct pseudo_header psh;
	if(inet_addr(target) != -1){
		printf("It's not nesessary resolve the hostname (%s)\n",target);
		dest_ip.s_addr = inet_addr(target);
	}else{
		char *ip = hostname_to_ip(target);
		if(ip!=NULL){
			printf("URL (%s) resolved to: %s \n\n" , target , ip);
			dest_ip.s_addr = inet_addr( hostname_to_ip(target) );
		}
		else{
			printf("Unable to resolve hostname : %s\n\n" , target);
			exit(EXIT_FAILURE);
		}
	}
	int source_port = 43591;
	char source_ip[20];
	get_local_ip(source_ip);
	printf("Local source IP is %s \n\n",source_ip);
	memset(datagram,0,4096);
	//IP Header init
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons (54321);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr (source_ip);
	iph->daddr = dest_ip.s_addr;
	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
	//TCP Header init
	tcph->source = htons ( source_port );
	tcph->dest = htons (80);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr)/4;
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (14600);
	tcph->check = 0;
	tcph->urg_ptr = 0;
	int one = 1;
	const int *val = &one;
	if (setsockopt (sk, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
		printf ("setsockopt() error. Error: %d (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	char *threadMsg = "Sniffer Thread";
	pthread_t sniffer_thread;
	if(pthread_create(&sniffer_thread,NULL,receive_ack,(void*) threadMsg)<0){
		show_error("pthread_create() error.",errno);
		exit(EXIT_FAILURE);
	}
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	for(int i=0;i<cantPortToScan;i++) portStatus[portsToScan[i]]=0;
	while(endSendPackets!=PACKET_FORWARDING_LIMIT){
		for(i=0;i<cantPortToScan;i++){
			if(portStatus[portsToScan[i]]==0){
				contFilteredPorts++;
				tcph->dest=htons(portsToScan[i]);
				tcph->check=0;
				psh.source_address=inet_addr( source_ip );
				psh.dest_address=dest.sin_addr.s_addr;
				psh.placeholder=0;
				psh.protocol=IPPROTO_TCP;
				psh.tcp_length=htons(sizeof(struct tcphdr));
				memcpy(&psh.tcp,tcph,sizeof(struct tcphdr));
				tcph->check=csum((unsigned short*) &psh,sizeof(struct pseudo_header));
				if(sendto(sk,datagram,sizeof(struct iphdr)+sizeof(struct tcphdr),0,(struct sockaddr *) &dest,sizeof (dest))<0){
					show_error("Error sending syn packet.", errno);
					exit(EXIT_FAILURE);
				}
			}
		}
		sleep(1);
		(contFilteredPortsChange==contFilteredPorts)?(endSendPackets++):(endSendPackets=0);
		contFilteredPortsChange=contFilteredPorts;
		contFilteredPorts=0;
	}
	endProces=TRUE;
	pthread_join(sniffer_thread,NULL);
	contFilteredPorts=cantPortToScan-contOpenedPorts-contClosedPorts;
	struct servent *service_resp=NULL;
	char service_name[50]="";
	for(int i=0;i<cantPortToScan;i++){
		service_resp = getservbyport(ntohs(portsToScan[i]), "tcp");
		(service_resp==NULL)?(strcpy(service_name,"???")):(strcpy(service_name, service_resp->s_name));
		if(portStatus[portsToScan[i]]==PORT_OPENED){
			printf("%s",HRED);
			printf("Port %d \topened \t\t(%s)\n",portsToScan[i], service_name);
		}
		if(portStatus[portsToScan[i]]==PORT_FILTERED){
			printf("%s",HYELLOW);
			if(contFilteredPorts<10) printf("Port %d \tfiltered \t(%s)\n",portsToScan[i], service_name);
		}
		if(portStatus[portsToScan[i]]==PORT_CLOSED){
			printf("%s",HGREEN);
			if(contClosedPorts<10) printf("Port %d \tclosed \t\t(%s)\n",portsToScan[i], service_name);
		}
	}
	clock_gettime(CLOCK_REALTIME, &tEnd);
	double elapsedTime=(tEnd.tv_sec-tInit.tv_sec) + (tEnd.tv_nsec-tInit.tv_nsec) / 1000000000.0;
	printf("%s",DEFAULT);
	printf("\nThe identified service names are the IANA standards ones and could differ in practice.\n");
	printf("\nScanned ports: %d in %.3lf secs\n\n",cantPortToScan, elapsedTime);
	printf("%s",HGREEN);
	printf("\tClosed: %d\n", contClosedPorts);
	printf("%s",HYELLOW);
	printf("\tFiltered: %d\n",contFilteredPorts);
	printf("%s",HRED);
	printf("\tOpened: %d\n\n",contOpenedPorts);
	printf("%s",DEFAULT);
	char c[128]="n";
	int selectedPort=0;
	do{
		do{
			printf("%s",WHITE);
			selectedPort=0;
			printf("Insert port to hack (0 = exit, default): ");
			fgets(c,sizeof(c),stdin);
			if(strcmp(c,"0\n")==0 || strcmp(c,"\n")==0){
				printf("\n\n");
				exit(0);
			}
			(portStatus[strtol(c,NULL,10)]==PORT_OPENED)?(selectedPort=strtol(c,NULL,10)):(show_error("\nInsert an opened port\n", 0));
		}while(selectedPort==0);
		hack_port(dest_ip.s_addr,selectedPort);
	}while(TRUE);
}

int hack_port(in_addr_t ip, int port) {
	char c[128]="n";
	show_options(port);
	while(TRUE){
		printf("\n%s",DEFAULT);
		do{
			printf(": ");
			fgets(c,sizeof(c),stdin);
		}while(strcmp(c,"1.1\n")!=0 && strcmp(c,"1.2\n")!=0 && strcmp(c,"1.3\n")!=0
				&& strcmp(c,"1.4\n")!=0 && strcmp(c,"1.5\n")!=0 && strcmp(c,"2.1\n")!=0
				&& strcmp(c,"2.2\n")!=0 && strcmp(c,"2.3\n")!=0 && strcmp(c,"3.1\n")!=0
				&& strcmp(c,"3.2\n")!=0 && strcmp(c,"3.3\n")!=0 && strcmp(c,"4.1\n")!=0
				&& strcmp(c,"i\n")!=0
				&& strcmp(c,"s\n")!=0 && strcmp(c,"h\n")!=0 && strcmp(c,"c\n")!=0
				&& strcmp(c,"e\n")!=0);
		printf("\n");
		if(strcmp(c,"1.1\n")==0) port_grabbing(ip, port, HEADER_GRABBING);
		if(strcmp(c,"1.2\n")==0) port_grabbing(ip, port, SOCKET_GRABBING);
		if(strcmp(c,"1.3\n")==0) cert_grabbing(ip, port, "https");
		if(strcmp(c,"1.4\n")==0) cert_grabbing(ip, port, "sftp");
		if(strcmp(c,"1.5\n")==0) hack_web(ip, port, HEADER_GRABBING);
		if(strcmp(c,"2.1\n")==0) hack_web(ip, port, METHODS_ALLOWED_GRABBING);
		if(strcmp(c,"2.2\n")==0) hack_web(ip, port, SERVER_RESP_SPOOFED_HEADERS);
		if(strcmp(c,"2.3\n")==0) hack_web(ip, port, GET_WEBPAGES);
		if(strcmp(c,"3.1\n")==0) hack_ssh(ip, port);
		if(strcmp(c,"3.2\n")==0) hack_ftp(ip, port);
		if(strcmp(c,"3.3\n")==0) hack_mysql(ip, port,MYSQL_BRUTE_FORCE);
		if(strcmp(c,"4.1\n")==0) hack_buffer_overflow(ip, port, CODE_RED);
		if(strcmp(c,"i\n")==0) interactive_mode(ip, port);
		if(strcmp(c,"s\n")==0) system_call();
		if(strcmp(c,"h\n")==0) show_options(port);
		if(strcmp(c,"c\n")==0) return RETURN_OK;
		if(strcmp(c,"e\n")==0) exit(0);
	}
}

void show_options(int port){
	printf("%s",DEFAULT);
	printf("\nSelect the activity to be performed in port %s%d%s: \n\n", HRED, port, DEFAULT);
	printf("\t 1) Banner grabbing:\n");
	printf("\t 1.1) Banner grabbing by using HTTP headers (http/https)\n");
	printf("\t 1.2) Banner grabbing by using socket connection (any service)\n");
	printf("\t 1.3) MySQL Banner grabbing by using socket connection\n");
	printf("\t 1.4) TLS certificate grabbing (https)\n");
	printf("\t 1.5) TLS certificate grabbing (sftp/ssh)\n");
	printf("\t 1.6) Headers grabbing (http/https)\n\n");
	printf("\t 2) HTTP:\n");
	printf("\t 2.1) Evaluate HTTP methods allowed by server (http/https)\n");
	printf("\t 2.2) Evaluate server code responses with spoofed host headers (http/https)\n");
	printf("\t 2.3) Trying to get webpages and interesting files (http/https)\n\n");
	printf("\t 3) Brute Force:\n");
	printf("\t 3.1) Trying to perform logins by using brute force (sftp/ssh)\n");
	printf("\t 3.2) Trying to perform logins by using brute force (ftp)\n");
	printf("\t 3.3) Trying to perform logins by using brute force (mysql)\n\n");
	printf("\t 4) Buffer Overflow:\n");
	printf("\t 4.1) Trying to perform Code Red virus attack - Buffer Overflow (any -GET- service)\n\n");
	printf("\t 5) Others:\n");
	printf("\t i) Interactive mode (any service)\n");
	printf("\t s) System Call\n");
	printf("\t h) Show options\n");
	printf("\t c) Change port\n");
	printf("\t e) Exit\n");
}

void * receive_ack( void *ptr ){
	start_sniffer();
	return (void*)&RETURN_SNIFFER_OK;
}

int start_sniffer(){
	int sock_raw;
	socklen_t saddr_size;
	int data_size;
	struct sockaddr saddr;
	unsigned char *buffer = (unsigned char *)malloc(65536);
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(sock_raw < 0){
		show_error("socket() Error.", errno);
		fflush(stdout);
		exit(EXIT_FAILURE);
	}
	saddr_size = sizeof saddr;
	while(endProces==FALSE){
		data_size=recvfrom(sock_raw,buffer,65536,0,&saddr,&saddr_size);
		if(data_size<0){
			show_error("recvfrom() error.", errno);
			fflush(stdout);
			exit(EXIT_FAILURE);
		}
		if(data_size>0)	process_packet(buffer, data_size);
	}
	close(sock_raw);
	return RETURN_OK;
}

void process_packet(unsigned char* buffer, int size){
	struct iphdr *iph=(struct iphdr*)buffer;
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
		if(tcph->syn==1 && tcph->ack==1 && source.sin_addr.s_addr==dest_ip.s_addr && portStatus[ntohs(tcph->source)]==0){
			portStatus[ntohs(tcph->source)]=PORT_OPENED;
			contOpenedPorts++;
		}
		if(tcph->rst==1 && source.sin_addr.s_addr==dest_ip.s_addr && portStatus[ntohs(tcph->source)]==0){
			portStatus[ntohs(tcph->source)]=PORT_CLOSED;
			contClosedPorts++;
		}
	}
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

char* hostname_to_ip(char * hostname){
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
	if((he=gethostbyname(hostname))==NULL) return NULL;
	addr_list=(struct in_addr **) he->h_addr_list;
	for(i=0;addr_list[i]!=NULL;i++) return inet_ntoa(*addr_list[i]);
	return NULL;
}

void get_local_ip (char * buffer){
	int sk=socket (AF_INET, SOCK_DGRAM, 0);
	const char* kGoogleDnsIp="8.8.8.8";
	int dns_port=53;
	struct sockaddr_in serv;
	memset(&serv,0,sizeof(serv));
	serv.sin_family=AF_INET;
	serv.sin_addr.s_addr=inet_addr(kGoogleDnsIp);
	serv.sin_port=htons(dns_port);
	int resp=connect(sk,(const struct sockaddr*) &serv,sizeof(serv));
	if(resp!=0){
		show_error("connect() error.", errno);
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in name;
	socklen_t namelen=sizeof(name);
	resp=getsockname(sk,(struct sockaddr*) &name, &namelen);
	if(resp!=0){
		show_error("getsockname() error.",errno);
		exit(EXIT_FAILURE);
	}
	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
	if(p==NULL){
		show_error("inet_ntop() error.",errno);
		exit(EXIT_FAILURE);
	}
	close(sk);
}
