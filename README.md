# Auditing-Cybersecurity
Cybersecurity framework developed in C, Ansi-style

Intended for auditing/security assessment, the program scan by using a TCP Stealth mode, the X top risk ports of a server (max. 5000) or all ports, and, eventually, it carries out some hacking procedures (port banner grabbing, CERT grabbing, BFA, DoS, Metasploits, nMap scripts, etc.) on opened ports by running own code (using, mainly: sockets, libSSH2, and libCurl) and/or the latest free third-party softwares (for instance: Dig, Nikto, Fierce, nMap, Metasploit, SQLMap, among others). 

The main objective of the program is provide a framework with the essentials commands/tools for ensuring, by their use, a well-knowledge of the effectiveness and efficiency of the implemented controls, in order to evaluate the residual risk of an assessment.

### Installation
Download the file, and use apt-get for resolving dependencies:
```
sudo apt-get install ./auditingcybersecurity_1.0_2.deb
```
Optional (recommended) if you want to run third-parties softwares:
```
sudo apt-get install nmap metasploit-framework sqlmap whatweb nikto fierce dnsenum traceroute whois
```
Then:
```
sudo Auditing-Cybersecurity --help
```
Finally, I recommend you to edit the different brute force attack usernames & password files, HTTP grabbing files, etc. located into:
```
cd /usr/share/Auditing-Cybersecurity/resources/
```
### Documentation about activity descriptions
_(Under development)_
### Feedback
Any doubt, suggestion or feedback, pls, just contact me.

Have fun!

### Screenshots:
<p align="center">
<image src=https://user-images.githubusercontent.com/40904281/203682762-fd4e5a9a-1198-4787-9aee-a1b146a91cb6.png>
<image src=https://user-images.githubusercontent.com/40904281/203682947-e159e999-e5ab-4842-b6b6-58c6e8324373.png>
<image src=https://user-images.githubusercontent.com/40904281/203682987-3244b6a2-5f34-4c6e-b314-23e108430a79.png>
</p>

Examples:

<p align="center">
<video src="https://user-images.githubusercontent.com/40904281/177245945-6bf3ead6-f04d-44d4-8b78-b8dad5701785.mp4" autoplay loop muted> </video>
</p>

<p align="center">
<video src="https://user-images.githubusercontent.com/40904281/177363811-5113a632-c9cb-4620-9fdb-95c08645c802.mp4" autoplay loop muted> </video>
</p>
