
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <readline/readline.h>
#include "../auditing-cybersecurity.h"
#include "libpcap.h"

pcap_t *monitorHandle=NULL;
struct bpf_program fp;

//#define AP_SSID "MyAccessPoint" // Replace with your own SSID
//#define AP_PASSPHRASE "MyPassphrase" // Replace with your own passphrase
//#define AP_IFNAME "wlx18d6c711ab7f" // Replace with the name of the access point interface

/*
int create_ap(){
	struct nl_sock *sock;
	    struct nl_msg *msg;
	    int if_index, ret;
	    uint32_t driver_id, flags;
	    struct nl_cb *cb;

	    sock = nl_socket_alloc();
	    if (!sock) {
	        fprintf(stderr, "Failed to allocate netlink socket.\n");
	        exit(EXIT_FAILURE);
	    }

	    genl_connect(sock);
	    if (ret < 0) {
	        fprintf(stderr, "Failed to connect to generic netlink socket: %s\n", nl_geterror(ret));
	        exit(EXIT_FAILURE);
	    }
	    driver_id = genl_ctrl_resolve(sock, "nl80211");
	        if (driver_id < 0) {
	            fprintf(stderr, "Failed to resolve nl80211 driver: %s\n", nl_geterror(driver_id));
	            exit(EXIT_FAILURE);
	        }

	        msg = nlmsg_alloc();
	        if (!msg) {
	            fprintf(stderr, "Failed to allocate netlink message.\n");
	            exit(EXIT_FAILURE);
	        }

	        if_index = if_nametoindex("wlan0"); // Replace with the name of the physical interface to be used for the access point
	        if (if_index == 0) {
	            fprintf(stderr, "Failed to get physical interface index: %s\n", strerror(errno));
	            exit(EXIT_FAILURE);
	        }
	        flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;

	            genlmsg_put(msg, 0, 0, driver_id, 0, flags, NL80211_CMD_NEW_INTERFACE, 0);

	            nla_put_string(msg, NL80211_ATTR_IFNAME, AP_IFNAME);
	            nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);

	return RETURN_OK;
}
 */
/*
void sending_arp_sniffing_packets(){
	u_long srcIP=inet_addr("192.168.1.1"), dstIP=inet_addr("192.168.1.255");
	u_char dstMAC[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	char errbuf[128]="";
	libnet_t *handle=libnet_init(LIBNET_LINK,networkInfo.interfaceName,errbuf);
	libnet_build_arp(1,0x0800,6,4,ARP_REPLY,networkInfo.interfaceMac,(u_char *) &srcIP,dstMAC,(u_char *) &dstIP,NULL,0,handle,0);
	libnet_build_ethernet(dstMAC,networkInfo.interfaceMac,0x0806,NULL,0,handle,0);
	while(!CANCEL_CURRENT_PROCESS){
		libnet_write(handle);
		usleep(SNIFFING_THREAD_DELAY);
	}
	libnet_destroy(handle);
}

void * start_sending_arp_sniffing_packets(void *ptr){
	sending_arp_sniffing_packets();
	return (void*)&RETURN_THREAD_OK;
}
*/
static void process_packet_monitor(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	static int count = 1;
	const struct sniffIp *ip;
	const struct sniffTcp *tcp;
	const char *payload;
	int sizeIp, sizeTcp, sizePayload;
	count++;
	ip=(struct sniffIp*)(packet+SIZE_ETHERNET);
	sizeIp=IP_HL(ip)*4;
	tcp=(struct sniffTcp*)(packet + SIZE_ETHERNET + sizeIp);
	sizeTcp=TH_OFF(tcp)*4;
	switch(ip->ip_p) {
	case IPPROTO_TCP:
		break;
	default:
		payload=(u_char *)(packet+SIZE_ETHERNET+sizeIp+sizeTcp);
		sizePayload=ntohs(ip->ip_len)-(sizeIp+sizeTcp);
		if(sizePayload>0) {
			printf("\n                 From: %s\n",inet_ntoa(ip->ip_src));
			printf("                   To: %s\n",inet_ntoa(ip->ip_dst));
			printf("            Src. port: %d\n",ntohs(tcp->th_sport));
			printf("            Dst. port: %d\n",ntohs(tcp->th_dport));
			printf("             Protocol: %d\n",ntohs(ip->ip_p));
			printf("  Payload (%d bytes): ",sizePayload);
			const u_char *ch=payload;
			printf("%s",C_HWHITE);
			for(int i=0;i<sizePayload;i++, ch++){
				if(isprint(*ch) || (*ch=='\n')) printf("%c", *ch);
			}
			printf("%s\n",C_DEFAULT);
			return;
		}
		break;
	}
	return;
}

static void monitor_start(){
	while(!cancelCurrentProcess) pcap_loop(monitorHandle, 1, process_packet_monitor, NULL);
	pcap_freecode(&fp);
	pcap_close(monitorHandle);
}

static void * start_monitor_packets(void *ptr){
	monitor_start();
	return (void*)&RETURN_THREAD_OK;
}

int v1(){
	char errbuf[PCAP_ERRBUF_SIZE]="";
	pcap_if_t *devs=NULL, *dev=NULL;
	pcap_findalldevs(&devs, errbuf);
	if(devs->name==NULL) return DEVICE_NOT_FOUND_ERROR;
	int cantDevs=0;
	for(dev=devs;dev!=NULL;dev=dev->next){
		if((dev->flags & PCAP_IF_UP) && (dev->flags & PCAP_IF_RUNNING)){
			printf("\t%d) %s%s%s\n",cantDevs+1, C_HWHITE, dev->name, C_DEFAULT);
			cantDevs++;
		}
	}
	int selectedOpt=0;
	do{
		char *c=NULL;
		c=readline("\nSelect device number: ");
		selectedOpt=strtol(c,NULL,10);
		if(selectedOpt<1 || selectedOpt>cantDevs) continue;
		break;
	}while(TRUE);
	int i=1;
	char *selectedIf=NULL;
	for(dev=devs;dev!=NULL;dev=dev->next,i++){
		if((dev->flags & PCAP_IF_UP) && (dev->flags & PCAP_IF_RUNNING) && i==selectedOpt){
			selectedIf=dev->name;
			break;
		}
	}
	char filterExp[BUFFER_SIZE_128B]="";
	//snprintf(filterExp, sizeof(filterExp), "type mgt");
	snprintf(filterExp, sizeof(filterExp), "src net 192.168.1.0/24");
	monitorHandle=pcap_open_live(selectedIf,SNAP_LEN,TRUE,100,errbuf);
	if(monitorHandle==NULL) return RETURN_ERROR;
	if(pcap_datalink(monitorHandle)!=DLT_EN10MB) return RETURN_ERROR;
	bpf_u_int32 net, mask;
	if(pcap_lookupnet(selectedIf, &net, &mask, errbuf) == -1){
		fprintf(stderr, "Can't get netmask for device wlan0\n");
		net=0;
		mask=0;
	}
	if(pcap_compile(monitorHandle,&fp,filterExp,0,net)==-1) printf("Error parsing filter");
	if(pcap_setfilter(monitorHandle,&fp)==-1) printf("Error installing filter");
	char *threadMsg="Monitor packets thread";
	pthread_t monitorPacketsThread;//, sendingArpSpoofedPacketsThread;
	if(pthread_create(&monitorPacketsThread,NULL,start_monitor_packets,(void*) threadMsg)<0) return THREAD_CREATION_ERROR;
	while(!cancelCurrentProcess);
	pthread_cancel(monitorPacketsThread);
	pcap_freealldevs(devs);
	return RETURN_OK;
}

int monitor(int type){
	switch(type){
	case OTHERS_MONITOR_IF:
		v1();
		break;
	default:
		break;
	}
	return RETURN_OK;
}
