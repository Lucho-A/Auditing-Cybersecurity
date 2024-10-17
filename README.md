# Auditing-Cybersecurity (aka Mr. Anderson)
Cybersecurity framework developed in C, Ansi-style

Intended for auditing/security assessment, the program scan by using a TCP Stealth mode, the X top risk ports of a server (max. 5000) or all ports, and, eventually, it carries out some hacking procedures (port banner grabbing, CERT grabbing, BFA, DoS, Metasploits, nMap scripts, etc.) on opened ports by running own code (using, mainly: sockets, libpcap, libnet, libSSH2, and libCurl, among others libraries) and/or the latest free third-party softwares (for instance: Dig, Fierce, nMap, Metasploit, SQLMap, among others).

The main objective of the program is provide a framework with the essentials commands/tools for ensuring, by their use, a well-knowledge of the effectiveness and efficiency of the implemented controls, in order to evaluate the residual risk of an assessment.

Finally, just mention that, since v1.2.4, I started to incorporate AI into the program in order to support a revision and conclusions.

Note (v1.2.8: 20240414): due to personal goals & scoping, the development of the program will begin to slow down.

<!-- ### BTW
For those folks who ask me if I will release the source code: yes, I will. Two reasons stop me right now: in first place, I'm not fully comfortable with the code. I've been re-organizing it, I have a lot of ideas, etc.. In second place (first?), I've been looking for a job since 2 years ago, I've had more than 40 interviews, and I didn't getting hire!, so, I’m not sure why I should give my work to the society for free if this shameless society is incapable to give a job to me! hhahah... anyway, as I said: take me patience, I will ;)
-->
### Changelog
_Follow the rabbit..._

[(\\(\\<br>( -.-)<br>o_(")(")](https://github.com/Lucho-A/Auditing-Cybersecurity/blob/master/CHANGELOG.md)
### Installation
<!--
[Download](https://github.com/Lucho-A/Auditing-Cybersecurity/releases/latest) the file, and use apt-get for resolving dependencies:
```
sudo apt-get install ./auditing-cybersecurity_X.X_X.deb
```
Note: if you already have installed the program, since v1.2.2, it's possible to perform the update executing:
```
sudo auditing-cybersecurity --update
```
-->
#### Dependencies:
```
sudo apt-get install libcurl4-gnutls-dev libssh2-1-dev libmysqlclient-dev libc6-dev libpq-dev libsmbclient-dev libssl3 libodbc2 libreadline-dev libpcap0.8-dev libnet1-dev libftp-dev unixodbc-dev libesmtp-dev
```
Note: ODPI-C does require Oracle Client libraries: https://odpi-c.readthedocs.io/en/latest/user_guide/installation.html

#### Compilation:
```
git clone https://github.com/lucho-a/Auditing-Cybersecurity.git
```
```
cd Auditing-Cybersecurity/src
```
```
gcc -o "auditing-cybersecurity" auditing-cybersecurity.c auditing-cybersecurity.h  others/* ports/* activities/* libs/libodpi/* libs/libOCL/* -lsmbclient -lnet -lpcap -lreadline -lm -lodbc -lcrypto -lssl -lcurl -lssh2 -lpq -lmysqlclient -lftp -lesmtp
```
```
set -e
```
```
sudo setcap CAP_NET_RAW=+eip auditing-cybersecurity
```
Optional (recommended) third-party software's:
```
sudo apt-get install nmap metasploit-framework sqlmap fierce dnsenum traceroute whois
```
Then, you will need "resource" files in order to perform the scanning, and specifying the different brute force attack usernames & password files, HTTP grabbing files, etc.: [link](https://github.com/Lucho-A/Auditing-Cybersecurity/tree/master/default_resources_files)

Finally:
```
auditing-cybersecurity --help
```
<!--
### Bonus Track
I backed up a WSL2 Ubuntu (22.04) image that I created for testing purposes. You can download it if you want:
```
ftp ftp://wsl_images:wsl_images@lucho-a.ddns.net:2121/wsl_images/wsl2-ubuntu-2204-lab-v1_0_0.tar
```
- (sudoer) system user: **mr-anderson:mr-anderson**

Althought there are few intentional issues in certain services, the vm does not pretend to be a kind of "challenge" for anybody, nor a complete testing environment, but only a kind of (backup) starting point for setting-up a testing lab under WSL2 system.

BTW, into the user's home, there is an script for setting up the network in case you've set a bridge connection before.
-->
<!-- ### Documentation about activity descriptions -->
<!-- You can find a brief description [here](https://github.com/Lucho-A/Auditing-Cybersecurity/blob/master/Auditing-Cybersecurity-README_v1.0.3.txt). -->
### Bugs known/unknown
Arising all the time.
### Documentation
_(Under development)_
### Feedback
Any doubt, suggestion or feedback, pls, just contact me.
<!--
### Screenshots:
<p align="center">

![imagen](https://github.com/Lucho-A/Auditing-Cybersecurity/assets/40904281/1ad0e052-b377-4976-a43b-fe4bd2839c31)

![imagen](https://github.com/Lucho-A/Auditing-Cybersecurity/assets/40904281/0918ffd8-451d-4b18-82fb-65899a567f11)

![imagen](https://github.com/Lucho-A/Auditing-Cybersecurity/assets/40904281/0c8bf57a-3efe-43b9-97a4-987444d0a7e9)

![imagen](https://github.com/Lucho-A/Auditing-Cybersecurity/assets/40904281/5d5b6d75-ff67-4806-a274-e95bda58469d)

![imagen](https://github.com/Lucho-A/Auditing-Cybersecurity/assets/40904281/7adfdfb6-63c2-44bc-8bd0-75806f81dba1)

</p>
-->
