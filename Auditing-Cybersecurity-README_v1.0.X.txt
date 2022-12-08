Auditing-Cybersecurity

Cybersecurity framework developed in C, Ansi-style

Intended for auditing/security assessment, the program scan by using a TCP Stealth mode, the X top risk ports of a server (max. 5000) or all ports, and, eventually, it carries out some hacking procedures (port banner grabbing, CERT grabbing, BFA, DoS, Metasploits, nMap scripts, etc.) on opened ports by running own code (using, mainly: sockets, libSSH2, and libCurl) and/or the latest free third-party softwares (for instance: Dig, Nikto, Fierce, nMap, Metasploit, SQLMap, among others).

The main objective of the program is provide a framework with the essentials commands/tools for ensuring, by their use, a well-knowledge of the effectiveness and efficiency of the implemented controls, in order to evaluate the residual risk of an assessment.

Installation:

Download the file, and use apt-get for resolving dependencies:

	- sudo apt-get install ./auditingcybersecurity_X.X_X.deb

Optional (recommended) if you want to run third-parties softwares:

	- sudo apt-get install nmap metasploit-framework sqlmap whatweb nikto fierce dnsenum traceroute whois

Then:

	- sudo Auditing-Cybersecurity --help

Finally, I recommend you to edit the different brute force attack usernames & password files, HTTP grabbing files, etc. located into:

	- cd /usr/share/Auditing-Cybersecurity/resources/

Usage & command arguments:

Usage (as root): Auditing-Cybersecurity [-h] ip|url cantPortsToScan(1-5000) |-a |-p port [-n]

-a | --all: Scan all (65535) ports. Take +- 25".
-p | --port: Scan just one port.
-h | --help: Show this.
-n | --no-intro: No 'Waking Up' intro.

Examples: 

$ sudo Auditing-Cybersecurity lucho-a.ddns.net 500
$ sudo Auditing-Cybersecurity lucho-a.ddns.net 30 -n
$ sudo Auditing-Cybersecurity lucho-a.ddns.net --all --no-intro
$ sudo Auditing-Cybersecurity lucho-a.ddns.net -p 2221 -n
# Auditing-Cybersecurity -h

Brief descriptions of activities:

1.1) Open a socket connection and send msgs in order to get a response. In addtion, evaluate the ttl value in IP header for establishing the probable OS
1.2) Generate a random IP source, and send (until the user cancel with crl+c) syn flag TCP/IP packets without finishing or closing the connection. As usual, use it under your own risk ;)
1.3) Call: nmap -sV -p [port] --script vulners [ip]
1.4) Open a socket connection and send a Code Red string
1.5) Search into msfconsole modules.
1.6) Execute a msfconsole module with set RHOSTS [IP], and RPORT [port] (command under revision because absent of set parameters needed for some modules)
1.7) Search into nMap scripts
1.8) Execute an nMap script
1.9) Execute SQLMap with: --forms --batch --crawl=10 --cookie=jsessionid=54321 --level=5 --risk=3
2.1) Look into the header for 'server' entries
2.2) Try to get the certification info from the server
2.3) Try to obtain the header information
2.4) Try to obtain the methods allowed by the server
2.5) Evaluate the code response having sent requests with spoofed host information in the header
2.6) Request files, like 'index.html', 'robots.txt', etc. to the server
2.7) Call: whatweb -a 3 [IP]:[port]
2.8) Call: nikto -h [IP]:[port]
3.1) Try to get the certification info from the server
3.2) Execute 'ssh_enumusers' msfconsole module
3.3) Try to guess user and passwords accounts
3.4) Execute 'juniper_backdoor' msfconsole module
4.1) Call: dig axfr @[URL]
4.2) Call: dig version.bind CHAOS TXT @[URL]
4.3) Call: fierce --dns-servers [URL]
4.4) Call: dnsenum --enum [URL]
5.1) Try to guess user and passwords accounts
6.1) Execute 'smb_version' msfconsole module
6.2) Execute 'ms17_010_eternalblue' msfconsole module
7.1) Execute 'juniper_backdoor' msfconsole module
7.2) Execute 'mssql_payload' msfconsole module
8.1) Execute 'smtp_ntlm_domain' msfconsole module
8.2) Execute 'smtp_relay' msfconsole module
8.3) Try to guess user and passwords accounts
9.1) Try to guess user and passwords accounts
10.1) Try to guess user and passwords accounts
11.1) Try to guess user and passwords accounts
12.1) Try to guess user and passwords accounts. Note: take into consideration that, by default, Oracle databases lock user's account after 3 (three) failed login attemps, so you can easily block account by running this activity
13.1) Try to guess user and passwords accounts

Others:
o) Show the opened ports identified during the scan
i) Open a socket allowing sending any msg to the server
s) Allow to execute any console command
t) Call: traceroute [IP]
h) Show the availables activities to perform
w) Call: whois [IP]
c) Allow changing the port to hack
q) Quit program
