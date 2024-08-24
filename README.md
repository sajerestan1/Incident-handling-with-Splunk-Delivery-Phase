# Incident-handling-with-Splunk-Delivery-Phase

![image](https://github.com/user-attachments/assets/0a82988e-3292-406e-9cb2-305d8203e6ae)


## Project Report: Investigating the Cyber Attack on Wayne Enterprises

### Overview

Wayne Enterprises recently experienced a significant cyber attack, where attackers infiltrated their network, compromised their web server, and defaced their website, http://www.imreallynotbatman.com. The website was altered to display a message saying, "YOUR SITE HAS BEEN DEFACED," along with the attackers' trademark. I was engaged as a Security Analyst to investigate the incident, identify the root cause, and trace all attacker activities within their network.
Delivery Phase

During the delivery phase of the investigation, the attackers created and delivered malware to gain initial access to the network, evade defenses, and further exploit vulnerabilities. I identified various IP addresses, domains, and email addresses associated with the adversary. The investigation focused on using Threat Hunting platforms and OSINT (Open Source Intelligence) sites to find any malware linked with the attackers.

### OSINT and Threat Intelligence Platforms

I used the following OSINT sites to gather intelligence on the attackers:

  ThreatMiner: I began the investigation by searching for the IP address 23.22.63.114 on ThreatMiner. This search revealed three files associated with the IP, one of which had a hash value of c99131e0169171935c5ac32615ed6261 and was flagged as malicious. Further analysis of this hash provided critical metadata and insights into the file's behavior.
  
  Reference: ThreatMiner Analysis
        
![image](https://github.com/user-attachments/assets/6211200b-d40d-48bb-aeb2-a4d7419e0c8f)

![image](https://github.com/user-attachments/assets/70406d3c-28aa-4560-9ce8-f36d4d928710)


### VirusTotal:

I utilized VirusTotal to search for the identified hash, c99131e0169171935c5ac32615ed6261. The platform provided detailed metadata about the malware, further confirming its malicious nature.
        Reference: VirusTotal Report

![image](https://github.com/user-attachments/assets/3d977ddf-46c1-4f63-9b80-539beb138632)

![image](https://github.com/user-attachments/assets/951165d2-3164-4aa7-b429-27422c7082ed)




### Hybrid-Analysis: 

Hybrid-Analysis offered a comprehensive behavior analysis of the identified malware. This platform provided critical information, including network communication, DNS requests, contacted hosts, MITRE ATT&CK mapping, and more. The detailed analysis was crucial in understanding the malware's actions post-execution.
  
  Reference: Hybrid-Analysis Report
  
![image](https://github.com/user-attachments/assets/75cd7898-a5f3-4e36-9d5f-f060d22905b2)

![image](https://github.com/user-attachments/assets/29a3ff0c-6651-4a87-908c-3a6bc748ae71)




Key Findings

  ### Question 1:

  #### What is the HASH of the Malware associated with the APT group?

  ![image](https://github.com/user-attachments/assets/9d78feeb-bd97-4664-92d0-2e2f70e9ebab)

  HASH of the Malware: The hash associated with the malware linked to the APT group is c99131e0169171935c5ac32615ed6261.

  ### Question 2:
  #### What is the name of the Malware associated with the Poison Ivy Infrastructure?

  ![image](https://github.com/user-attachments/assets/a44627d0-24a0-495e-8adc-b056c76a8041)

  Malware Name: The malware associated with the Poison Ivy infrastructure was identified as MirandaTateScreensaver.scr.exe.

Conclusion

In this investigation, I successfully mapped the attacker's activities across the seven phases of the Cyber Kill Chain, demonstrating a comprehensive understanding of the attack vectors and methods used by the adversaries. By leveraging OSINT and Threat Intelligence platforms, I was able to trace the attack back to a specific APT group and identify the tools and techniques they used to infiltrate Wayne Enterprises.
Experience Gained

This project enhanced my ability to utilize various Threat Hunting platforms and OSINT tools to investigate cyber attacks. I gained hands-on experience in identifying malware, analyzing its behavior, and correlating findings with threat intelligence sources. The investigation also deepened my understanding of the Cyber Kill Chain and the methodologies employed by advanced persistent threats (APTs).
Benefits

The investigation provided Wayne Enterprises with crucial insights into the nature of the attack, enabling them to strengthen their defenses and prevent future incidents. For me, the project was an invaluable experience that honed my skills in incident response, malware analysis, and threat intelligence gathering. This project not only enhanced my technical capabilities but also reinforced the importance of a proactive approach to cybersecurity, ensuring that networks are continuously monitored, and vulnerabilities are promptly addressed.
