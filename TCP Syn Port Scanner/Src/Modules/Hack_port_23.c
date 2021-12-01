/*
 ============================================================================
 Name        : Check_port_23.c
 Author      : L.
 Version     : 1.0.4
 Copyright   : GNU General Public License v3.0
 Description : Check Port 23
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int hack_port_23(in_addr_t ip, int port, int scanType){
	// Port banner grabbing
	printf("%s", WHITE);
	printf("\nTrying to port grabbing...\n\n");
	printf("%s",BLUE);
	port_grabbing(ip, port);
	// CERT grabbing
	printf("%s", WHITE);
	printf("\nTrying to obtain certs...\n\n");
	printf("%s",BLUE);
	curl_global_init(CURL_GLOBAL_ALL);
	char url[50]="";
	snprintf(url,sizeof(url),"telnet://%s/",inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)));
	cert_grabbing(url);
	return 0;
}
