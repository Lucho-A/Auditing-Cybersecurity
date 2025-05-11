
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "../auditing-cybersecurity.h"

void show_intro(char *programName, char *version){
	system("clear");
	printf("%s",C_CYAN);
	printf("\n******************************************************");
	printf("\n");
	printf("\n%s%s (aka Mr.Anderson) v%s by L.%s",C_HCYAN,programName,version,C_CYAN);
	printf("\n");
	printf("\nhttps://lucho-a.github.io/");
	printf("\n");
	printf("\n******************************************************");
	printf("%s\n",C_DEFAULT);
}

void show_help(char *msgError){
	show_intro(PROGRAM_NAME, PROGRAM_VERSION);
	if(strcmp(msgError,"")!=0) show_message(msgError,0,0, ERROR_MESSAGE,true, false, false);
	printf("%s",C_WHITE);
	printf("\nUsage: auditing-cybersecurity OPTIONS\n");
	printf("\nOptions:\n\n");
	printf("-v | --version: show version.\n");
	printf("-h | --help: show this.\n");
	printf("-d | --discover: search for devices in the network.\n");
	printf("-f | --sniffing: capture packets from/to a device in the network/DoS ARP Flooding attack.\n");
	printf("-t | --target [string]: url|ip to scan.\n");
	printf("-P | --ports [int]: number of ports to scan (1-5000).\n");
	printf("-p | --port [int]: scan just one port.\n");
	printf("-a | --all: scan all (65535) ports.\n");
	printf("-s | --scan-delay [long int]: delay in us between sending packets. Default 0.\n");
	printf("-r | --resources-location [string]: path to resource files.\n");
	printf("-n | --no-intro: no 'Waking Up' intro.\n\n");
	printf("Examples: \n\n");
	printf("$ auditing-cybersecurity --discover --no-intro\n");
	printf("$ auditing-cybersecurity -t 192.168.1.23 -f -n\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -r /home/user/res/\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -P 500 -r /home/user/res/\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -P 100 --scan-delay 100000 -r /home/user/res/\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -P 30 -n -r /home/user/res/\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io --all --no-intro -r /home/user/res/\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -p 2221 -n -r /home/user/res/\n");
	printf("$ auditing-cybersecurity --help\n\n");
	printf("See https://github.com/lucho-a/auditing-cybersecurity for a full description.\n\n");
}

void show_intro_banner(){
	srand(time(0));
	char *msg="Wake up...";
	printf("%s", C_WHITE);
	printf("\n:~# ");
	fflush(stdout);
	usleep(2000000);
	printf("%s", C_HWHITE);
	for(int i=0;msg[i]!='\0';i++){
		usleep(rand()%200000 + 20000);
		printf("%c",msg[i]);
		fflush(stdout);
	}
	printf("%s", C_WHITE);
	printf("\n:~# ");
	fflush(stdout);
	usleep(2000000);
	msg="The Matrix has you";
	printf("%s", C_HWHITE);
	for(int i=0;msg[i]!='\0';i++){
		usleep(rand()%200000 + 20000);
		printf("%c",msg[i]);
		fflush(stdout);
	}
	usleep(500000);
	printf("%s\n", C_DEFAULT);
}
void show_result(char *result){
	int i=strlen(result);
	while(true){
		if(result[i-1]>=33){
			result[i]='\0';
			i--;
			break;
		}
		i--;
	}
	i=0;
	while(result[i]<33) i++;
	for(;result[i]!='\0';i++){
		if(isprint(result[i])) printf("%c", result[i]);
		if(result[i]=='\n') printf("\n");
		if(result[i]=='\t') printf("\t");
	}
}

int show_message(char *msg, int msgLenght, int errNum, int level, bool setParagraph, bool hexaFormat,
		bool oneLine){
	char *textColour=NULL;
	if(msgLenght==0) msgLenght=strlen(msg);
	switch(level){
	case OK_MESSAGE:
		textColour=C_HGREEN;
		break;
	case RESULT_MESSAGE:
		textColour=C_HWHITE;
		break;
	case INFO_MESSAGE:
		textColour=C_HWHITE;
		break;
	case WARNING_MESSAGE:
		textColour=C_HWHITE;
		break;
	case CRITICAL_MESSAGE:
		textColour=C_HRED;
		break;
	case ERROR_MESSAGE:
		printf("%s",C_HRED);
		if(errNum!=0){
			char errMsg[BUFFER_SIZE_1K]="";
			snprintf(errMsg, BUFFER_SIZE_1K, "%sError %d: %s", msg, errNum, strerror(errNum));
			(setParagraph)?(printf("\n%s\n", errMsg)):(printf("%s", errMsg));
			printf("%s",C_DEFAULT);
			return RETURN_ERROR;
		}else{
			(setParagraph)?(printf("\n%s\n", msg)):(printf("%s", msg));
			printf("%s",C_DEFAULT);
			return RETURN_ERROR;
		}
	default:
		break;
	}
	(setParagraph)?(printf("%s\n",textColour)):(printf("%s",textColour));
	if(hexaFormat){
		for(int i=0;i<msgLenght;i++){
			if(i%16==0) printf("\n");
			printf("%02X ",(unsigned char) msg[i]);
		}
	}else{
		if(oneLine){
			for(int i=0;i<msgLenght;i++)(isprint(msg[i]))?(printf("%c",msg[i])):(printf("·"));
		}else{
			for(int i=0;i<msgLenght;i++)(isprint(msg[i]) || msg[i]=='\n' || msg[i]=='\t')?(printf("%c",msg[i])):(printf("·"));
		}
	}
	(setParagraph)?(printf("\n%s",C_DEFAULT)):(printf("%s",C_DEFAULT));
	return RETURN_OK;
}

void show_options(){
	printf("\nSelect the activity to be performed in port %s%d%s: \n\n", C_HRED, portUnderHacking, C_DEFAULT);

	printf("\t1) %sAny%s service:\n",C_HWHITE, C_DEFAULT);
	printf("\t1.1)  Service info & responses grabbing");
	printf("\t1.2)  nMap Vulners scan");
	printf("\t\t1.3)  Search for nMap script");
	printf("\t\t1.4)  Run nMap script\n");
	printf("\t1.5)  Search for Msf module");
	printf("\t\t1.6)  Run Msf module");
	printf("\t\t1.7)  SQLmap query\n");
	printf("\t1.8)  DoS Syn Flood Attack");
	printf("\t\t1.9)  Sniffing (ARP Poisoning attack)/DoS ARP Flooding attack\n\n");

	printf("\t2) %sHTTP/HTTPS%s services:\n", C_HWHITE,C_DEFAULT);
	printf("\t2.1)  Header banner grabbing");
	printf("\t\t2.2)  TLS certificate grabbing (https)\n");
	printf("\t2.3)  Methods allowed by server");
	printf("\t\t2.4)  Responses with spoofed headers\n");
	printf("\t2.5)  Getting webpages and files");
	printf("\t2.6)  Others\n\n");

	printf("\t3)  %sSFTP/SSH%s services:\n", C_HWHITE,C_DEFAULT);
	printf("\t3.1)  Fingerprinting port");
	printf("\t\t3.2)  User enumeration\n");
	printf("\t3.3)  BFA");
	printf("\t\t\t\t3.4)  Metasploit Juniper SSH Backdoor\n\n");

	printf("\t4)  %sDNS%s service:", C_HWHITE,C_DEFAULT);
	printf("\t\t\t5) %sFTP%s service:", C_HWHITE,C_DEFAULT);
	printf("\t\t\t6) %sSMB%s service:", C_HWHITE,C_DEFAULT);
	printf("\t\t\t\t7) %sMySQL%s service:\n", C_HWHITE,C_DEFAULT);

	printf("\t4.1)  Dig");
	printf("\t\t\t\t5.1)  Anonymous login");
	printf("\t\t6.1)  Banner grabbing");
	printf("\t\t\t7.1)  Version Grabbing\n");
	printf("\t4.2)  DNS Banner");
	printf("\t\t\t5.2)  BFA");
	printf("\t\t\t6.2)  Metasploit Eternal Blue");
	printf("\t\t7.2)  BFA\n");
	printf("\t4.3)  Zone Transfer (Fierce)");
	printf("\t\t5.3)  Banner grabbing");
	printf("\t\t6.3)  BFA\n");
	printf("\t4.4)  DNS Enum\n\n");

	printf("\t8) %sSMTP%s service:", C_HWHITE,C_DEFAULT);
	printf("\t\t\t9) %sIMAP%s service:", C_HWHITE,C_DEFAULT);
	printf("\t\t10) %sLDAP%s service:", C_HWHITE,C_DEFAULT);
	printf("\t\t\t11) %sPOP3%s service:\n", C_HWHITE,C_DEFAULT);

	printf("\t8.1)  Enumeration");
	printf("\t\t\t9.1)  BFA");
	printf("\t\t\t10.1)  BFA");
	printf("\t\t\t\t11.1)  BFA\n");
	printf("\t8.2)  Relay test\n");
	printf("\t8.3)  BFA\n");
	printf("\t8.4)  Banner grabbing\n\n");

	printf("\t12) %sOracle%s service:", C_HWHITE,C_DEFAULT);
	printf("\t\t\t13) %sPostgresSQL%s service:", C_HWHITE,C_DEFAULT);
	printf("\t14) %sMSSql Server%s service:\n", C_HWHITE,C_DEFAULT);

	printf("\t12.1)  BFA");
	printf("\t\t\t\t13.1)  BFA");
	printf("\t\t\t14.1)  BFA\n");
	printf("\t\t\t\t\t\t\t\t\t\t14.2)  Metasploit MSSQL Shell\n\n");

	printf("\t%sOthers%s:\n", C_HWHITE,C_DEFAULT);
	printf("\to)  Show opened ports");
	printf("\t\t\td)  Show hosts");
	printf("\t\t\ti)  Interactive mode");
	printf("\t\t\tv)  CVE searching\n");
	printf("\tf)  Show filtered ports");
	printf("\t\t\ts)  System call");
	printf("\t\t\tt)  Traceroute");
	printf("\t\t\t\tw)  Whois\n");
	printf("\th)  Show activities");
	printf("\t\t\tc)  Change port");
	printf("\t\t\tq)  Exit\n\n");
}

