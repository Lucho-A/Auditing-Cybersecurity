
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <readline/history.h>
#include "../auditing-cybersecurity.h"
#include "../others/networking.h"

int system_call(char *cmdArg){
	if(cmdArg!=NULL && strcmp(cmdArg,"")!=0){
		system(cmdArg);
		return RETURN_OK;
	}
	FILE *f=NULL;
	char **stringTemplates=NULL;
	int totalStrings=open_file_str(PATH_TO_RESOURCES, "system_strings_template.txt", &f, &stringTemplates);
	if(totalStrings==RETURN_ERROR) return set_last_activity_error(OPENING_FILE_ERROR, "");
	fclose(f);
	do{
		char *cmd=get_readline("![#]=templates,;=exit)-> ", TRUE);
		if(strcmp(cmd,";")==0) break;
		if(strcmp(cmd,"!")==0){
			for(int i=0;i<totalStrings;i++) printf("\n  %d) %s", i+1, stringTemplates[i]);
			printf("\n\n");
			continue;
		}
		if(cmd[0]=='!' && strlen(cmd)>1){
			char buf[BUFFER_SIZE_32B]="";
			for(int i=1;i<strlen(cmd);i++) buf[i-1]=cmd[i];
			long int selectedOpt=strtol(buf,NULL,10);
			if(selectedOpt<1 || selectedOpt>totalStrings){
				show_message("Option not valid\n",0, 0, ERROR_MESSAGE, TRUE);
				continue;
			}
			char msg[BUFFER_SIZE_1K]="";
			format_strings_from_files(stringTemplates[selectedOpt-1], stringTemplates[selectedOpt-1]);
			snprintf(msg,sizeof(msg), stringTemplates[selectedOpt-1], target.strTargetURL, portUnderHacking);
			add_history(msg);
			continue;
		}
		printf("%s\n",C_HWHITE);
		system(cmd);
		PRINT_RESET;
	}while(TRUE);
	free_char_double_pointer(stringTemplates, totalStrings);
	clear_history();
	return RETURN_OK;
}
