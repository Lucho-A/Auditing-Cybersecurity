
#include <libssh2.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"
#include "../activities/activities.h"

void free_char_double_pointer(char ***p, size_t size){
	for(int i=0;i<size;i++) free((*p)[i]);
	free(*p);
	return;
}

char * get_readline(char *prompt, Bool addHistory){
	char *lineRead=(char *)NULL;
	if(lineRead){
		free(lineRead);
		lineRead = (char *)NULL;
	}
	lineRead=readline(prompt);
	if (lineRead && *lineRead && addHistory) add_history (lineRead);
	return (lineRead);
}

int request_quantity_threads(int threadsDefault){
	char prompt[BUFFER_SIZE_512B]="";
	snprintf(prompt, BUFFER_SIZE_512B,"  Insert quantity of thread (%d by default): ", threadsDefault);
	do{
		char *cantThreadsRequest=get_readline(prompt, FALSE);
		if(strcmp(cantThreadsRequest, "")!=0){
			int tt=strtol(cantThreadsRequest,NULL,10);
			if(tt<=0 || tt>MAX_THREADS){
				show_message("  Entered value not valid (1-100).\n",0, 0, ERROR_MESSAGE, TRUE);
				free(cantThreadsRequest);
				continue;
			}
			free(cantThreadsRequest);
			return tt;
		}
		free(cantThreadsRequest);
		return threadsDefault;
	}while(TRUE);
}
/*
void hexa_to_ascii(char *hexaMsg, char *resultMsg){
	//TODO
	resultMsg = (char *) malloc((strlen(hexaMsg)/2+1) * sizeof(char));
	for (int i=0;i<strlen(hexaMsg);i+=2){
		char byte[3];
		byte[0]=hexaMsg[i];
		byte[1]=hexaMsg[i+1];
		byte[2]='\0';
		int n=strtol(byte,NULL,16);
		printf("%c",n);
		sprintf(&resultMsg[i/2], "%c", (char)n);
	}
	resultMsg[strlen(hexaMsg)/2]='\0';
}
*/
