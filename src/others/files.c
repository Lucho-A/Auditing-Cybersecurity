
#include <stdlib.h>
#include <string.h>
#include "../auditing-cybersecurity.h"

int open_file(char *pathToResource, char *filename, FILE **f){
	char *fullPath=malloc(strlen(pathToResource)+strlen(filename)+1);
	memset(fullPath,0,strlen(pathToResource)+strlen(filename)+1);
	snprintf(fullPath, strlen(pathToResource)+strlen(filename)+1,"%s%s", pathToResource, filename);
	if((*f=fopen(fullPath,"r"))==NULL){
		free(fullPath);
		return RETURN_ERROR;
	}
	int entries=0;
	char *line=NULL;
	size_t len=0;
	while((getline(&line, &len, *f))!=-1) entries++;
	free(line);
	free(fullPath);
	rewind(*f);
	return entries;
}

int open_file_str(char *pathToResource, char *filename, FILE **f, char ***s){
	int entries=open_file(pathToResource, filename, f);
	if(entries==RETURN_ERROR) return RETURN_ERROR;
	*s = (char**) malloc(entries * sizeof(char*)+1);
	memset(*s,0,entries * sizeof(char*)+1);
	size_t len=0;
	char *line=NULL;
	int i=-1;
	while((getline(&line, &len, *f))!=-1){
		(*s)[++i] = malloc(strlen(line)+1);
		snprintf((*s)[i],strlen(line)+1,"%s",line);
		((*s)[i])[strlen((*s)[i])-1]='\0';
	}
	rewind(*f);
	return entries;
}

int read_usernames_and_password_files(struct BfaInfo *bfaInfo, char *usernamesFilename, char * passwordsFilename){
	int i=0;
	FILE *f=NULL;
	if((bfaInfo->totalUsernames=open_file(PATH_TO_RESOURCES, usernamesFilename,&f))==RETURN_ERROR) return set_last_activity_error(OPENING_FILE_ERROR,"");
	bfaInfo->usernames = (char **) malloc(bfaInfo->totalUsernames * sizeof(char*));
	for (int i=0;i<bfaInfo->totalUsernames;i++) bfaInfo->usernames[i]=NULL;
	size_t len=0;
	char *line=NULL;
	i=-1;
	while((getline(&line, &len, f))!=-1){
		bfaInfo->usernames[++i]= malloc(strlen(line)+1);
		snprintf(bfaInfo->usernames[i],strlen(line)+1,"%s",line);
		bfaInfo->usernames[i][strlen(bfaInfo->usernames[i])-1]=0;
	}
	fclose(f);
	if((bfaInfo->totalPasswords=open_file(PATH_TO_RESOURCES,passwordsFilename,&f))==RETURN_ERROR) return set_last_activity_error(OPENING_FILE_ERROR,"");
	bfaInfo->passwords = (char **) malloc(bfaInfo->totalPasswords * sizeof(char*));
	for (int i=0;i<bfaInfo->totalPasswords;i++) bfaInfo->passwords[i]=NULL;
	i=-1;
	while((getline(&line, &len, f))!=-1){
		bfaInfo->passwords[++i]= malloc(strlen(line)+1);
		snprintf(bfaInfo->passwords[i],strlen(line)+1,"%s",line);
		bfaInfo->passwords[i][strlen(bfaInfo->passwords[i])-1]=0;
	}
	free(line);
	fclose(f);
	return bfaInfo->totalUsernames*bfaInfo->totalPasswords;
}

void format_strings_from_files(char *from, char *dest){
	int contChars=0;
	for(int i=0;i<strlen(from);i++, contChars++){
		if(from[i]=='\\'){
			switch(from[i+1]){
			case '0':
				dest[contChars]='\0';
				break;
			case 'n':
				dest[contChars]='\n';
				break;
			case 'r':
				dest[contChars]='\r';
				break;
			case '\\':
				dest[contChars]='\\';
				break;
			case 'a':
				dest[contChars]='\a';
				break;
			case 'b':
				dest[contChars]='\b';
				break;
			case 'f':
				dest[contChars]='\f';
				break;
			case 't':
				dest[contChars]='\t';
				break;
			case 'v':
				dest[contChars]='\v';
				break;
			case '\'':
				dest[contChars]='\'';
				break;
			case '"':
				dest[contChars]='\"';
				break;
			case '?':
				dest[contChars]='\?';
				break;
			default:
				dest[contChars]=from[i];
				continue;
			}
			i++;
		}else{
			dest[contChars]=from[i];
		}
	}
	dest[contChars]='\0';
}
