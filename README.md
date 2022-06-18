# Privilage Escalation Handbook
This is what I learnt TryHackMe's Jr Penetration Tester Path's privilage escalation modules

# Linux Privilage Escalation

# Enumeration
< Find Hostname >
  - hostname

< Find uname >
  - uname -a `for all information`
---------------------
Function Shortcut

- Kernel Name	-s
- Kernel Release	-r
- Kernel Version*	-v
- Network Node Name (Hostname)	-n
- Machine architecture	-m
- Processor architecture	-p
- Hardware Platform (OS architecture)	-i
- Operating System	-o
---------------------

< /proc/version > `provides information about the target system processes.`
 
< /etc/issues > `This file usually contains some information about the operating system but can easily be customized or changes.`
 
 < The “ps” command provides a few useful options. >
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
 
# Automated Enumeration Tools

  - LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
  - LinEnum: https://github.com/rebootuser/LinEnum
  - LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
  - Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration
  - Linux Priv Checker: https://github.com/linted/linuxprivchecker

# Privilege Escalation: Kernel Exploits

  - Find version of system
  - Exploit-db: https://www.exploit-db.com
  - linux kernel: https://www.linuxkernelcves.com/cves
  - Google: https://www.google.com
  - Searchsploit
  
# Privilege Escalation: Sudo

  - sudo -l: `Check root privilages`
  - GTFObin: https://gtfobins.github.io/

# Privilege Escalation: SUID

  - find / -type f -perm -04000 -ls 2>/dev/null: `list files that have SUID or SGID bits set.`
  - GTFObin: https://gtfobins.github.io/
  *If you can view /etc/shadow and /etc/passwd, can copy to attacker machine and use JohnTheRipper to find credentials*
  - unshadow passwd.txt shadow.txt > passwords.txt
  *If you can write to /etc/passwd*
  - openssl passwd -1 salt THM password1
  - add "root:/bin/bash" to end of user in /etc/passwd

# Privilege Escalation: Capabilities
