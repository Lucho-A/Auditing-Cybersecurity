### auditing-cybersecurity-v1.3.2

Updated:  2025/05/15 <br>
Severity: low

FEATURE:
- 1.1, i    -> (experimental) allows sending messages using ToR service (1)

IMPROVEMENT:
- added parameter '--f | --sniffing' for allowing carry out 1.9) (Sniffing/DoS ARP Flooding attack) to IPs without opened ports.

BUG_FIXED:
- v    -> fixed no returning results
- fixed buffer overflow when hostname more than 50 characters
- some memory leaks solved

OTHERS:
- updated libOCl
- when prompting, two followed spaces for adding a tab ('\t').
- minor changes, code optimized & code cleaned-up

(1) Setting the server ip and port, was added into 'setting.txt' file

### auditing-cybersecurity-v1.3.1

Updated: 2024-10-28 <br>
Severity: medium

BUG_FIXED:
- 1.9    -> fixed return when the ip is not found into network
- i) 1.1)-> fixed no responses from websites that requires setting explicit hostname (SSL);

IMPROVEMENT:
- cancelling & cleaning procedures optimized
- -d     -> (experimental) threading optimized and safer
- 1.9    -> (experimental) threading optimized and safer
- 1.9    -> (experimental) broadcasting improved
- 2.5    -> (under evaluation) improved the robustness of the algorithm
- SIGHUP & SIGQUIT handled

OTHERS:
- minor changes, code optimized & code cleaned-up

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.3.0

Updated: 2024-10-20 <br>
Severity: medium

BUG_FIXED:
- crl-c doesn't stop Ollama responses fixed
- 2.5    -> not showing send/recv errors fixed
- 2.5    -> timeout added
- 2.5    -> (under evaluation) handling SSL errors that arise when high quantity of threads is selected.
- -d     -> cancelling issues solved

IMPROVEMENT:
- 2.5    -> shows location redirected (for performance, it doesn't check if the file exist in the redirected location).
- -d     -> (experimental) removes duplicated entries (tested with a Class C network, only)

OTHERS:
- Ollama lib updated
- multiline in prompt allowed (alt+enter)
- error handling changes (threading safer)
- minor changes, code optimized & code cleaned-up

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.9

Updated: 2024-10-15 <br>
Severity: medium

BUG_FIXED:
- 1.9, 2.6, s   -> fixed no entering command issue
- v)   -> fixed CVE searching (under evaluation changing API)
- 6.2) execution fixed

FEATURE:
- information about public ip (from api.ipify.org) is shown.
- (experimental) when the program asks for an activity, the prompt will query to Ollama server (SSL) if the prompt doesnt match with any option
- 6.1) improved
- 6.3) improved
- 7.1) improved

OTHERS:
- g) activity (ChatGPT) removed.
- CVE searching moved to Others) -> v)
- 1.3) in order to avoid using 'locate'/'updatedb', the searching is just performed into '/usr/share/nmap/scripts'
- the resource file called 'chatgpt.txt' was replaced by 'settings.txt'. Also, this file will/could be used for setting global parameters.
- minor changes, code optimized & code cleaned-up

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.8

Updated: 2024-04-14 <br>
Severity: medium

BUG_FIXED:
- 2.3   -> fixed false -
- 6.2   -> fixed false +

FEATURE:
- _(UNDER EVALUATION)_ When performing BFA on certain port/services, the activity asks for performing only a "test user login". The idea here is evaluating the variation coefficient associated with the elapsed time between login attempts. If this value is closer to 0 (lesser than 10% in practice), this implies that the login time between queries is quiet homogeneous. The algorithm in this case, evaluate if a login attempt for each user is not in line with the average elapsed time value (20% higher) and report it. Context: once a time, there were several issues and vulnerabilities regarding with this. In short, if a user exist, the service delayed a bit more the response than if the user doesn't. A well-security-design in this regard, for example, could implement randomly delays in order to avoid this issue. Nowadays, is quiet weird find a service with this vulnerability but, who knows...

IMPROVEMENT:
- f)    -> activity added for listing the filtered ports.
- Now, it's possible to query any port, independently if was scanned or not. In fact, if no port/s is/are specified (nor '-p', '-P', nor '-a'), the scanning is skipped and just the requesting for a port is asked.

OTHERS:
- in order to avoid, nah I mean, evaluate hhaha ids/ips/firewalls setups, with '-s | --scan-delay' is possible to specify the delay (in microseconds) between port scans. For example "--scan-delay 1000000" send one packet/port per second. Default value 0.
- because previous comment, the evolution of the scanning is shown during the scan (only if '-s'!=0 -default-) and the algorithm was optimized (_under evaluation_).
- opened ports are shown on-the-fly. Removed listing filtered & closed ports (see 'f)' for filtered ones).
- scans/re-scans can be canceled.
- the default "resource" folder was removed, and '-r' option is now mandatory.
- update ODPI-C library. Just for the records, note that ODPI-C does require Oracle Client libraries: https://odpi-c.readthedocs.io/en/latest/user_guide/installation.html
- due to personal goals & scoping, the development of the program will begin to slow down. So, deb package wont be delivered anymore, and the program, let's say, is going to be in a permanent development stage. So, at the moment, won't have new "official" releases, and automatic updates are stand-by.
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.7:"Mar de las Pampas" hhahah (such amazing place... counting the days for returning)

SHA2-256(auditing-cybersecurity_1.2_7.deb)=22e647522d8db007d11df72e3f2551a05b4a59924b16292751c90e61255f102f

SHA2-256(auditing-cybersecurity_1.2_7-amd64.tar.gz)=ca484435f5d54dd006fbe8233e15d905911bf3f75b18625b51d5ee83b3de37cd

Updated: 2024-01-03
Severity: high

BUG_FIXED:
- a lot.

BUG_KNOWN:
- also, a lot... too much for describing them without my lawyer present... hhhaha (nah, not too much, I hope)

IMPROVEMENT:
- '-r | --resources-location': option added (optional) for specifying the path to resources files. Default: '/usr/share/auditing-cybersecurity/resources/'.
- 7.2   -> showing results improved.
- 7.2   -> timeouting set (5") if can't connect to server.
- 1.6   -> set DOMAIN var for exploits.
- 1.10  -> sending spoofed packet delay changed to 10000000us (10 secs.). Determine the best value (aka. not flooding & not losing packets) for this can be pretty tricky. It depends on the network, the device, the protocol involved, etc. Anyway, I just recommend start with a high value and decrease it, if necessary, and/or evaluate the timing of the device (host) with a tool like wireshark, and then, set a value according to it.
- 1.10  -> the activity ask for logging into a file the information sniffed (separated by tabulations).
- 1.10  -> shown traffic to any port of the host, and only if the bytes received > 1.
- 8.3   -> enabled.
- 8.3/9.1/10.1/11.1  -> the activity ask for a domain in order to concatenate it to usernames.

OTHERS:
- g     -> speed response increased.
- g     -> timeouting increased.
- g     -> keep the last user & assistant message for improving the chat experience.
- 1.11  -> decreased buffersize & increased timeouting to 30 secs.
- 12.1  -> because installing oracle dependencies can be tricky, I included the Oracle source file for compiling and integrating jointly with the program.
- supporting hexadecimal string bug fixed
- command arguments changed (see '-h').
- code alignment, minor changes, code optimized & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.6

Updated: 2023-07-17
Severity: medium

BUG_FIXED:
- 1.11	-> fixed string parsing.
- 2.3	-> fixed showing info.
- g		-> fixed string parsing.

OTHERS:
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.5

Updated: 2023-07-17
Severity: medium

FEATURE:
- 1.11	-> added activity for, since given an string, searching CVE's into www.opencve.io.

BUG_FIXED:
- g		-> fixed string parsing.

OTHERS:
- validate sudo/root when '--updating'.
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.4

Updated: 2023-07-16
Severity: medium

FEATURE:

- g		-> in order to start to integrate the program with AI, I added an activity for chatting with OpenAI. In '/usr/share/auditing-cybersecurity/resources/chatgpt.txt' you can enter the API key. In addition, 'max_tokens' and 'temperature' can be set editing that file. The model used is 'gpt-3.5-turbo', and the system role "Act as IT auditor, security and cybersecurity professional.". (1)

(1) Just for the records, I was experimenting with different settings, models, and I didn't find substantial response differences by using and settings the 'system' role. However, all of this are constantly evolving and, let's face it, it's pretty funny hhaha.

OTHERS:
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.3

Updated: 2023-07-14
Severity: medium

IMPROVEMENT:
- 2.2   -> validate the 'not after' and 'not before' cert dates against the current day, and show the info in more human readable way.

BUG_FIXED:
- 2.4   -> fixed show information.
- 5.2   -> fixed user & pass not found when error 500 arise.

OTHERS:
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.2

UUpdated: 2023-07-12
Severity: medium

FEATURE:

- '--update': in order to simplify the updating process of the program, I added the option '--update'. The command download the latest version into '/usr/share/### auditing-cybersecurity/' from Github, install it using 'apt-get', and remove it.
- 5.3 	-> added FTP banner grabbing.

IMPROVEMENT:

- improved retrieving data from server.

BUG_FIXED:
- 7.2	-> fixed identify user & password.
- 13.1	-> fixed identify user & password (try to access to 'postgres' database).
- 6.1	-> fixed segmentation fault crash (when no supported dialects were found).

OTHERS:
- 6.1	-> v3 identification not supported at the moment.
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.1

Updated: 2023-07-07
Severity: medium

FEATURE:
- 2.6	-> now, like '1.9', 'i', or 's', in order to organize useful http/https commands, the activity reads a file 'http_commands.txt' (with '!'), and add to history prompt the command !# selected. As usual, into the file, '%s' (in first place) add the URL, and '%d' add the port.

BUG_FIXED:
- 2.5	-> fixed no showing results

OTHERS:
- 2.6	-> removed (Whatweb)
- 2.7	-> removed (Nikto)
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.2.0

Updated: 2023-07-04
Severity: high

FEATURE:

IMPROVEMENT:
- 6.1	-> SMBv2 and v3 grabbing implemented (beta/under-testing)

BUG_FIXED:
- 2.1	-> fixed show result
- 7.1	-> fixed server version detection.
- fixed SSL port detection.

OTHERS:
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.9

Updated: 2023-05-16
Severity: medium

FEATURE:
- 6.1	-> I was researching and working on the SMB protocol in order to come up with eventual DoS/scanners/exploit hack procedures, and because I prefer evaluate separately SMBv1 than v2 or v3 ('smb_version' msfconsole evaluates some aspects, like capabilities or preferred dialect, among others, jointly). At the moment, I developed a service banner grabbing for SMBv1, only. So, I still keep the 'smb_version' msfconsole scanner execution because SMBv2/3, and debugging (double checking results).
- 6.1	-> The banner grabbing, also try to perform anonymous login. In case of success, list the resources allowed.
- 8.4	-> added SMTP Banner grabbing.

BUG_FIXED:
1.8		-> solved script executions.
- solved no responses (or partial ones) when '0x00' into string payload responses exist (filled with '·').
- no printable responses characters printed like '·'.

OTHERS:
- handling errors improved.
- minor changes & code cleaned-up.
- for sure, others I don't remember hhaha

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.8

Updated: 2023-05-07
Severity: medium

IMPROVEMENT:
- 1.6 	-> changed "run" by "exploit" msf command.
- 5.2 	-> algorithm optimized.
- added thread requests for several BFA's procedures.

FEATURE:
- 7.1	-> added MySQL service version grabbing.

BUG_FIXED:
- 6.3	-> fixed user and password login attempting.

BUG_KNOWN:
- 7.2	-> fails for older <= 5.0.51 MySQL versions.

OTHERS:
- 3.3	-> create a new connection for each login attempt in order to avoid blocking.
- 8.3	-> disable because it's under revision. (1)
- i		-> instead of %s or %d, shows the ip or port in history.
- for practicality, I split the file "usernames_ftp_ssh.txt" in two files, one for each service.
- minor changes & code cleaned-up.

(1) Btw, sorry for back and forth but a lot of unexpected situations arise depending of the service version, implementation, etc. (threading issues, code exceptions, implementations not RFC aligned, etc.).

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.7

Updated: 2023-04-17
Severity: MEDIUM

FEATURES:
- 1.9	-> similar to (i) and (s) options, now, because there are so many different useful sqlmap's commands, and in order to have separated these sort of commands from the rest, the activity reads a file ("sql_commands.txt") entering '!', and add the '!#' string (where # is the number of the string in the file) to the prompt history (up and down arrows). Additionally, asks and adds the 'url' and '--cookie' options (optional).
- 5.1	-> added option for attempting login as "anonymous" (using 'ftplib' functions).

IMPROVEMENT:
- i		-> like (s) or (1.9) you can add two variable identificators into the strings file ("interactive_strings_templates.txt"). A first '%s'=IP, and a second '%d'=port-under-hacking.
- 1.6	-> added 'set ForceExploit true'.
- 2.1	-> try to show the header and it doesn't matter if 'server' header is included.
- 2.3	-> removed
- 5.2	-> improved algorithm using "sockets" instead of "libcurl". In addition, requests the quantity of threads to be used.

BUG_FIXED:

- (s)(i)-> fixed errors when trying to edit commands longer than one line. Apparently, 'readline()' have some issues managing bracket included into the prompt. For this reason, setting colors could be tricky. Anyway, in order to simple fix this, I changed the prompt for these and other activities.
- fixed copying new resources files post-installation.

OTHERS:
- command's history removed when activity change.
- showing results doesn't repeat the "Percentage completed" each new result (at the moment, only implemented in some activities).
- menu re-organization
- error handling optimized
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.6

Updated 2023-04-13:
Update Severity: MEDIUM

IMPROVEMENT:
- no asking for interface when only one is found.
- s		-> now, when editing some template command, the edition is stored in the command's history.
- 2.1	-> replaced libcurl by socket procedures.
- 2.5	-> improved the http request adding "user-agent", and "accept" headers.
- 2.5	-> added code 204.
- 2.6	-> increased performance allowing entering the number of threads to be used (100 by default... anxious I?? hhahah) and optimized the connection algorithm.

BUG_FIXED:

- 2.6	-> solved false positives because redirect issues.
- fixed error handling when receiving socket packets.

OTHERS:
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.5

Updated 2023-04-10:
Update Severity: MEDIUM

IMPROVEMENT:
- now, it's possible to select other than wireless interfaces, for instance, VPN's. Additionally, it was removed "loopback", and "any" options.
- [-d | --discover] in order to avoid overcharging the network and cpu, a rate refresh was include (20 secs).
- d		-> show information only once.
- 1.10	-> MAC searching improved.

BUG_FIXED:
- [-d | --discover] fixed error sending packets.

OTHERS:
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.4

Updated 2023-04-09:

FEATURES:
- Now, the program check if more than one wireless device is up and running, and allows choosing which one will be used for performing the activities (not necessarily apply for system commands, msfconsole, nmap, etc.).

IMPROVEMENT:
- show more network information at start.
- [-d | --discover] (should be) available for networks class A and B.
- [-d | --discover] in order to have more control of devices connected to the network, this option permanently scan the network until crl+c.
- option added (d) to activities for discovering hosts (--discover) until crl+c.
- 1.10	-> Now, it's possible to cheat/hack just one ip of the network.
- 1.10	-> changed default sending packets delay to 350000.

BUG_FIXED:
- 1.10	-> fixed cancelling thread.
- 1.10	-> fixed ip to cheat validation.

OTHERS:
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.3

Updated 2023-04-01:

IMPROVEMENTS:
- [-d | --discover] algorithm improved.
- 1.6   -> in order to allow compatibility with more modules, the activity set more vars: RHOSTS, RPORT (optional), LHOST, SRVHOST, USER_FILE, and PASS_FILE (the names of this files have changed. Now: msf_users.txt, and msf_passwords.txt.).
- in order to avoid unnecessary trails in logs, I changed the ssh connection banner ("SSH-2.0-Mr.Anderson", pretty obvious, right hahaha) for a a fake one ("SSH-2.0-OpenSSH_for_Windows_8.1").

BUG_FIXED:
- 1.1   -> fixed "Connection supported" information error for Cloudflare server SSL ports, by changing SSL negotiation method.
- 2.2   -> because failures getting cert info from Cloudflare servers (and from some sites/web-services, etc.) using libcurl, I replaced the code by an own one (using libssl functions instead).
- 1.8   -> fixed error when adding script/script-path to execute.

OTHERS:
- for standards, the name of the resource files have been changed to lowercase. Pls, take this into consideration, and rename your files BEFORE updating. You can easily solve this by executing:
```
cd /usr/share/### auditing-cybersecurity/resources/; rename 'y/A-Z/a-z/' *
```
- minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.2

Updated 2023-01-31:
- FEATURE:  [-d | --discover] argument option added for (ARP) discovering devices (IP & MAC) in the local network. At the moment, only class C networks are supported). Example usage: auditing-cybersecurity [-d | --discover] [--no-intro]
- OTHERS:   minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.1

Updated 2023-01-28:
- IMPROVEMENT:	the installation doesn't overwrite the existent resource files (finally! hahahh)
- IMPROVEMENT:	format output results improved.
- BUG_FIXED:	i	->	fixed wrong close connection timing.
- BUG_FIXED:	1.10	->	fixed no-aborting when crl+c pressed.
- IMPROVEMENT:	signal catches improved.
- OTHERS:       improved socket request timing.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.1.0

Update: 2023-01-26 (1.1.0):
- IMPROVEMENT:	2.6	->	redirect 301 is contemplated.
- BUG_FIXED:	1.5	->	fixed validation ';' on exit
- FEATURE:      1.10	->	now, it's possible sniffing (by ARP poisoning) the port under hacking (libpcap0.8, libnet1). (1)
- OTHERS:       minor changes & code cleaned-up.

(1) At the moment, some procedures, like setting your interface in 'promiscuous' mode, and allowing 'forwarding' firewall rule must be done manually. On the other hand, the routine not only has an obvious impact in the 'confidentiality' dimension of the information, but in the 'availability' also. Moreover, the activity allows to enter the delay between sending packets, so you can perform a DoS ARP flooding attack, also. So, plsssss, in line with the objective of the program, the main idea is using this and the rest of the other tests for evaluating the existence, or not, of controls in place, as well, their effectiveness. Use it under your own and exclusive responsibility.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.0.9

Updated 2023-01-21 (1.0.9):
- IMPROVEMENT:    1.1  ->    text in the file (socket_banner_grabbing_strings.txt) can (and must) be written with standard ANSI C escape sequence. Enter, or execute procedure, do not add '\n' nor any other character. So, you should end the strings with '\n', '\r\n\r\n' (HTTP), etc. Hexa, Octal, and Unicode sequence are not supported. 
- FEATURE:        2.6  ->    similar to 'i', now, it's possible to select between different 'GET' query templates (getting_webpages.txt). 
- FEATURE:        s    ->    similar to 'i', now, it's possible to add (editing 'system_strings_template.txt') "favorites" commands. It can be used %s (in first place) for adding the ip under revision, and %d for adding the port. ! show the list, and !# add the (#) selected command to the history with the vars added. In the file, you don't need to end the commands with '\n'. 
- IMPROVEMENT:    i    ->    idem 1.1 (interactive_strings_templates.txt).
- BUG_FIXED:      i    ->    fixed input validation when '!#' is selected.
- BUG_FIXED:      4.3  ->    replace argument '--dns-servers' by '--domain' 
- BUG_FIXED:      I'm not sure exactly why, but it seems that the mysterious bug was solved hhahaha
- OTHERS:         minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.0.8

Updated 2023-01-19 (1.0.8):
- OTHERS:        for privacy and avoid suspicious, now, the update checking is against the latest GitHub released tag instead of using an own web-service.
- BUG_FIXES:     close connections improved avoiding some crashes.
- BUG_UNKNOWN:   arising aaall the time hhahah
- OTHERS:        minor changes & code cleaned-up.

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.0.7

Updated 2023-01-18 (1.0.7):
- BUG_FIXED:   i    -> controlled error when (first) message is  sent.
- IMPROVEMENT: i    -> history, auto-complete (using tab), command templates, and editing message available. Now, it's possible to edit commands (for example, by using arrows, del, etc.), and looking for previous commands executed (libreadline). Also, it's possible to look for command templates by reading a file (for editing: 'interactive_strings_templates.txt'). '!' show the list (strings in file), and '!#' add the # command to the history (up/down arrows). (1)
- IMPROVEMENT: s    -> idem previous description.
- OTHERS: minor changes & code cleaned-up.

(1) You can set the behavior of this by editing ~/.inputrc (see: man readline)

------------------------------------------------------------------------------------------------------
### auditing-cybersecurity-v1.0.6

Updated 2023-01-16 (1.0.6):
- IMPROVEMENT:	1.1  -> show only responses not empty.
- IMPROVEMENT:	1.1  -> show type connections supported (Socket/SSL/SSH).
- IMPROVEMENT:	3.x  -> identified and abort the processes if the IP could have been blocked.
- IMPROVEMENT:	3.1  -> Now, perform banner, algorithm , hash, and authentication methods fingerprinting over the port.
- BUG_FIXED:	3.1  -> fixed segmantation fault when running the activity over no-SSH ports.
- OTHERS:		6.1  -> Remove setting RPORT option.
- FEATURES:		14.1 -> BFA over MsSQL Server ports (libodbc2) *
- IMPROVEMENT: 	i    -> show only responses not empty.
- OTHERS:		moved 7.2 to 14.2
- BUG_FIXED:	by setting timeout, fixed SSH Handshake stuck in some ports
- OTHERS: 		minor changes, code cleaned-up, and color scheme changes
- OTHERS:	12.1 -> if you get "DPI-1047: Cannot locate a 64-bit Oracle Client library" error, pls, refer to https://oracle.github.io/odpi/doc installation.html#linux. Attached, latest deb and rpm versions.

* Note: if you have some troubles for install this library, pls, refer to: https://learn.microsoft.com/en-us/sql/connect/odbc/linux-mac/installing-the-microsoft-odbc-driver-for-sql-server?view=sql-server-ver16

------------------------------------------------------------------------------------------------------
1.0.5:

Updated 2023-Jan-09 (1.0.5):
- BUG_FIXED:	1.1 -> fixed using escape characters ('\r','\n')
- IMPROVEMENT:	1.1 -> show if suppport SSL
- BUG_FIXED: 	1.4 -> fixed string termination characters
- IMPROVEMENT: 	2.3 -> improved efficiency replacing libCurl by socket
- IMPROVEMENT: 	2.4 -> improved efficiency replacing libCurl by socket
- IMPROVEMENT: 	2.5 -> improved efficiency replacing libCurl by socket. Now, it's possible to edit the spoofed hosts by editing file
- BUG_FIXED: 	2.6 -> fixed buffer overflow
- BUG_FIXED: 	2.6 -> now, it's possible to get info from 'https' (SSL) ports (libSSL).
- IMPROVEMENT: 	2.6 -> improved efficiency replacing libCurl by socket. Additionally, in order to avoid over charging the view, the activity only show those file that exist in server (code 200 OK). Do not perform forwarding, so it's recommended to test, also, this activity for port 443 if opened.
- BUG_FIXED: 	3.2 -> add set USER_LIST option using 'usernames_FTP_SSH.txt' file (however, I'm working in an own algorithm because this exploit isn't too much reliable (sooo much false positives)
- BUG_FIXED: 	3.3 -> removed close session when no session was created (segmentation fault)
- IMPROVEMENT: 	3.3 -> improved algorithm efficiency
- IMPROVEMENT: 	i   -> now, it's possible to send messages to any SSL port
- BUG_FIXED: 	socket buffer overflow
- IMPROVEMENT: 	socket blocking and no-blocking logic
- OTHERS: 		minor changes & code cleaned-up

Note: Maybe, you want to backup the resource files previous update if you edited them. Keep in mind that an update suppose overwritting those files.

------------------------------------------------------------------------------------------------------
1.0.4:

Updated 2022-Dec-02 (1.0.4):
- IMPROVEMENT: improve socket timeouting
- IMPROVEMENT: banner grabbing (1.1) send others messages than "\n". Changeables by editing file resource.
- FEATURE: allow performing BFA on Samba service (libsmbclient)
- BUG_FIXES: Check updates
- BUG_FIXES: Interactive mode buffer overflow
- OTHERS: in order to align the program to standars, I changed the package and the progam name. So, uninstall the previous one before/after install this version.

------------------------------------------------------------------------------------------------------
1.0.3:

Updated 2022-Nov-27 (1.0.3):
- IMPROVEMENT: increase SEND_PACKET_DELAY for more reliability (all ports scanned in +- 25")
- FEATURE: allow scanning just one port (useful for knew-uncommon-ports testing)
- FEATURE: allow performing BFA on PostgresSQL service (libpq5)
- BUG_FIXES: None
- OTHERS: minor changes & code cleaned-up

------------------------------------------------------------------------------------------------------
1.0.2:
- checkupdates
- oracle bfa (libdopic)

------------------------------------------------------------------------------------------------------
