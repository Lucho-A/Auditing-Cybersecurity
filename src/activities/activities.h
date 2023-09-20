/*
 * activities.h
 *
 *  Created on: 14 sep. 2023
 *      Author: luch-l
 */

#ifndef HEADERS_ACTIVITIES_H_
#define HEADERS_ACTIVITIES_H_

int arp(int);
int any(int);
int mssql(int);
int mysql(int);
int oracle(int);
int postgres(int);
int pop3(int);
int ldap(int);
int imap(int);
int ftp(int);
int smtp(int);
int smb(int);
int dns(int);
int http(int);
int ssh(int);
int others(int);
int bfa_init(int, char *, char *, int);
void *bfa_check_users(void *arg);

int ftp_check_user(char *userName, char *password);
int ssh_check_user(char *userName, char *password);
int mssql_check_user(char *userName, char *password);
int mysql_check_user(char *userName, char *password);
int oracle_check_user(char *userName, char *password);
int postgres_check_user(char *userName, char *password);
int smb_check_user(char *userName, char *password);

int bfa_imap_ldap_pop3_smtp_ftp(int service);

#endif /* HEADERS_ACTIVITIES_H_ */
