/*
 ============================================================================
 Name        : TCP Syn Port Scanner Functions.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Common Functions
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int open_file(char *fileName, FILE **f){
	char file[256]="";
	snprintf(file,sizeof(file),"%s%s", PATH_TO_RESOURCES,fileName);
	if((*f=fopen(file,"r"))==NULL){
		printf("%s",HRED);
		printf("fopen(%s) error: Error: %d (%s)\n", fileName, errno, strerror(errno));
		printf("%s",DEFAULT);
		return -1;
	}
	int entries=0;
	char buffer[256]="";
	while(fscanf(*f, "%s ", buffer)!=EOF) entries++;
	rewind(*f);
	return entries;
}

void show_error(char *errMsg, int errnum){
	printf("%s",HRED);
	(errnum==0)?(printf("%s\n", errMsg)):(printf("%s Error %d (%s)\n", errMsg, errnum, strerror(errnum)));
	printf("%s",DEFAULT);
}
