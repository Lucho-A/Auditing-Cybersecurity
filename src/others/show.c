
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
	if(strcmp(msgError,"")!=0) show_message(msgError,0,0, ERROR_MESSAGE,1);
	printf("%s",C_WHITE);
	printf("\nUsage: auditing-cybersecurity OPTIONS\n");
	printf("\nOptions:\n\n");
	printf("-v | --version: show version.\n");
	printf("-h | --help: show this.\n");
	printf("-u | --update: update.\n");
	printf("-d | --discover: search for devices in the network.\n");
	//printf("-m | --monitor: monitoring queries through an interface.\n");
	printf("-t | --target [string]: url|ip to scan.\n");
	printf("-P | --ports [int]: number of ports to scan (1-5000).\n");
	printf("-p | --port [int]: scan just one port.\n");
	printf("-a | --all: scan all (65535) ports.\n");
	printf("-s | --scan-delay [long int]: delay in us between sending packets. Default 0.\n");
	printf("-n | --no-intro: no 'Waking Up' intro.\n\n");
	printf("Examples: \n\n");
	printf("$ auditing-cybersecurity --discover --no-intro\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -P 500\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -P 100 --scan-delay 100000\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -P 30 -n -r /home/user/res/\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io --all --no-intro\n");
	printf("$ auditing-cybersecurity -t lucho-a.github.io -p 2221 -n\n");
	printf("$ sudo auditing-cybersecurity --update\n");
	printf("$ auditing-cybersecurity --help\n\n");
	printf("Note: usernames & passwords, and others useful files are located in /usr/share/auditing-cybersecurity/resources/\n\n");
	printf("Pls, see https://github.com/Lucho-A/Auditing-Cybersecurity for a full description.\n\n");
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
	while(TRUE){
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
		if(result[i]=='\n') printf("\n  ");
		if(result[i]=='\r') printf("  ");
		if(result[i]=='\t') printf("\t");
	}
}

int show_message(char *msg, int msgLenght, int errNum, int level, Bool setParagraph){
	char *textColour=NULL;
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
			(setParagraph)?(printf("\n  %s\n", errMsg)):(printf("  %s", errMsg));
			printf("%s",C_DEFAULT);
			return RETURN_ERROR;
		}else{
			(setParagraph)?(printf("\n  %s\n", msg)):(printf("  %s", msg));
			printf("%s",C_DEFAULT);
			return RETURN_ERROR;
		}
	default:
		break;
	}
	if(setParagraph){
		printf("%s\n  ",textColour);
		for(int i=0;i<msgLenght;i++)(isprint(msg[i]) || msg[i]=='\n' || msg[i]=='\t')?(printf("%c",msg[i])):(printf("·"));
		PRINT_RESET;
	}else{
		printf("%s",textColour);
		for(int i=0;i<msgLenght;i++)(isprint(msg[i]) || msg[i]=='\n' || msg[i]=='\t')?(printf("%c",msg[i])):(printf("·"));
		printf("%s",C_DEFAULT);
	}
	return RETURN_OK;
}

void show_options(){
	printf("\nSelect the activity to be performed in port %s%d%s: \n\n", C_HRED, portUnderHacking, C_DEFAULT);

	printf("\t1) %sAny%s service:\n",C_HWHITE, C_DEFAULT);
	printf("\t1.1)  Service info & responses grabbing");
	printf("\t1.2)  DoS Syn Flood Attack");
	printf("\t\t\t\t\t\t1.11)  CVE searching\n");
	printf("\t1.3)  nMap Vulners scan");
	printf("\t\t\t1.4)  Code Red buffer overflow\n");
	printf("\t1.5)  Search for Msf module");
	printf("\t\t1.6)  Run Msf module\n");
	printf("\t1.7)  Search for nMap script");
	printf("\t\t1.8)  Run nMap script\n");
	printf("\t1.9)  SQLmap query");
	printf("\t\t\t1.10) Sniffing (ARP Poisoning attack)/DoS ARP Flooding attack\n\n");

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
	printf("\t\t\tg)  ChatGPT\n");
	printf("\tf)  Show filtered ports");
	printf("\t\t\ts)  System call");
	printf("\t\t\tt)  Traceroute");
	printf("\t\t\t\tw)  Whois\n");
	printf("\th)  Show activities");
	printf("\t\t\tc)  Change port");
	printf("\t\t\tq)  Exit\n\n");
	//printf("\t d) Command description\n\n");
}

