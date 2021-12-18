/*
 ============================================================================
 Name        : .c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description :
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner.h"

int system_call(void){
	char cmd[128]="\n";
	do{
		printf("%s",DEFAULT);
		printf("System Call (;;=exit): ");
		fgets(cmd,sizeof(cmd),stdin);
		if(strcmp(cmd,";;\n")==0){
			printf("%s\n",DEFAULT);
			return RETURN_OK;
		}
		printf("%s\n",BLUE);
		system(cmd);
	}while(TRUE);
}
