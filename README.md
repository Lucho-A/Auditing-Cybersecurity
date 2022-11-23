# Auditing-Cybersecurity
Cybersecurity framework developed in C, Ansi-style

Intended for auditing/security assessment, the program scan by using a TCP Stealth mode, the X top risk ports of a server (max. 5000) or all ports, and, eventually, it carries out some hacking procedures (port banner grabbing, CERT grabbing, BFA, DoS, Metasploits, nMap scripts, etc.) on opened ports by running own code (using, mainly: sockets, libSSH2, and libCurl) and/or the latest free third-party softwares (for instance: Dig, Nikto, Fierce, nMap, Metasploit, SQLMap, among others). 

The main objective of the program is provide a framework with the essentials commands/tools for ensuring, by their use, a well-knowledge of the effectiveness and efficiency of the implemented controls, in order to evaluate the residual risk of an assessment.

### Installation
Download the file, and use apt-get for resolving dependencies:
```
sudo apt-get install ./auditingcybersecurity_1.0_2.deb
```
Optional (recommended) if you want to run third-parties sofwares:
```
sudo apt-get install nmap metasploit-framework sqlmap whatweb nikto fierce dnsenum traceroute whois
```
Then:
```
sudo Auditing-Cybersecurity --help
```
Finally, I recommend you to edit the different brute force attack usernames & password files, HTTP grabbing files, etc. located into /usr/share/Auditing-Cybersecurity/resources/

Any doubt, question or feedback, pls, just contact me.

Have fun!

### Screenshots:
<p align="center">
  <img src="https://user-images.githubusercontent.com/40904281/189545286-e5327404-3d63-4073-8bef-efd66270ff39.png"/>
  <img src="https://user-images.githubusercontent.com/40904281/189545322-daca1b4b-3bed-43c3-8379-88d8bbe457db.png"/>
  <img src="https://user-images.githubusercontent.com/40904281/189545354-29e2da3e-6b6c-4c5e-947b-7e6464a1b708.png"/>
</p>

Examples:

<p align="center">
<video src="https://user-images.githubusercontent.com/40904281/177245945-6bf3ead6-f04d-44d4-8b78-b8dad5701785.mp4" autoplay loop muted> </video>
</p>

<p align="center">
<video src="https://user-images.githubusercontent.com/40904281/177363811-5113a632-c9cb-4620-9fdb-95c08645c802.mp4" autoplay loop muted> </video>
</p>
