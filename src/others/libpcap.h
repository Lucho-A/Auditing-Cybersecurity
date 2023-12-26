
#ifndef HEADERS_LIBPCAP_H_
#define HEADERS_LIBPCAP_H_

#define SNAP_LEN 65535
#define SIZE_ETHERNET 14
//#define ETHER_ADDR_LEN 6

#include <libnet.h>

struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];
	u_char  ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};
#define ARP_REQUEST 1
#define ARP_REPLY 2
typedef struct arphdr {
	u_int16_t htype;   						// Hardware Type
	u_int16_t ptype;    					// Protocol Type
	u_char hlen;        					// Hardware Address Length
	u_char plen;        					// Protocol Address Length
	u_int16_t oper;     					// Operation Code
	u_char sha[6];      					// Sender hardware address
	u_char spa[4];      					// Sender IP address
	u_char tha[6];      					// Target hardware address
	u_char tpa[4];      					// Target IP address
}arphdr_t;
struct sniffIp {
	u_char  ip_vhl;                 		// version << 4 | header length >> 2
	u_char  ip_tos;                 		// type of service
	u_short ip_len;                 		// total length
	u_short ip_id;                  		// identification
	u_short ip_off;                 		// fragment offset field
#define IP_RF 0x8000            			// reserved fragment flag
#define IP_DF 0x4000            			// don't fragment flag
#define IP_MF 0x2000            			// more fragments flag
#define IP_OFFMASK 0x1fff       			// mask for fragmenting bits
	u_char  ip_ttl;                 		// time to live
	u_char  ip_p;                   		// protocol
	u_short ip_sum;                 		// checksum
	struct  in_addr ip_src,ip_dst;  		// source and dest address
};
#define IP_HL(ip) 		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  		(((ip)->ip_vhl) >> 4)
typedef u_int tcp_seq;
struct sniffTcp {
	u_short th_sport;
	u_short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char  th_offx2;
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

#endif /* HEADERS_LIBPCAP_H_ */
