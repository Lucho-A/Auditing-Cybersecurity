
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

char * get_readline(char *prompt, bool addHistory){
	char *lineRead=(char *)NULL;
	if(lineRead){
		free(lineRead);
		lineRead=(char *)NULL;
	}
	lineRead=readline(prompt);
	if(lineRead && *lineRead && addHistory) add_history (lineRead);
	return (lineRead);
}

int request_quantity_threads(int threadsDefault){
	char prompt[BUFFER_SIZE_512B]="";
	snprintf(prompt, BUFFER_SIZE_512B,"  Insert quantity of thread (%d by default): ", threadsDefault);
	do{
		char *cantThreadsRequest=get_readline(prompt, false);
		if(strcmp(cantThreadsRequest, "")!=0){
			int tt=strtol(cantThreadsRequest,NULL,10);
			if(tt<=0 || tt>MAX_THREADS){
				show_message("  Entered value not valid (1-5000).\n",0, 0, ERROR_MESSAGE, true);
				free(cantThreadsRequest);
				continue;
			}
			free(cantThreadsRequest);
			return tt;
		}
		free(cantThreadsRequest);
		return threadsDefault;
	}while(true);
}
