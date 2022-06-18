# Privilage Escalation Handbook
This is what I learnt TryHackMe's Jr Penetration Tester Path's privilage escalation modules

# Linux Privilage Escalation

# Enumeration
*Find Hostname
 - hostname

*Find uname
- uname -a 
 - for all information
---------------------
Function	Shortcut
---------------------
- Kernel Name	-s
- Kernel Release	-r
- Kernel Version*	-v
- Network Node Name (Hostname)	-n
- Machine architecture	-m
- Processor architecture	-p
- Hardware Platform (OS architecture)	-i
- Operating System	-o
---------------------

*/proc/version
 - provides information about the target system processes.
 
*/etc/issues
 \__ This file usually contains some information about the operating system but can easily be customized or changes.
 
*The “ps” command provides a few useful options.
 \__ ps -A: View all running processes
 \__ ps axjf: View process tree (see the tree formation until ps axjf is run below)
 \__ ps aux: The aux option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.
 
*env
 \__ show environmental variables.
 \__ The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.
 
*sudo -l
 \__ The target system may be configured to allow users to run some (or all) commands with root privileges.
 
*history
 \__ can give us some idea about the target system

*netstat
 \__ netstat -a: shows all listening ports and established connections.
 \__ netstat -at or netstat -au can also be used to list TCP or UDP protocols respectively.
 \__ netstat -l: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)
 \__ netstat -s: list network usage statistics by protocol (below) This can also be used with the -t or -u options to limit the output to a specific protocol.
 \__ netstat -tp: list connections with the service name and PID information.
 \__ netstat -i: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”.

*find
 \__ find . -name flag1.txt: find the file named “flag1.txt” in the current directory
 \__ find /home -name flag1.txt: find the file names “flag1.txt” in the /home directory
 \__ find / -type d -name config: find the directory named config under “/”
 \__ find / -type f -perm 0777: find files with the 777 permissions (files readable, writable, and executable by all users)
 \__ find / -perm a=x: find executable files
 \__ find /home -user frank: find all files for user “frank” under “/home”
 \__ find / -mtime 10: find files that were modified in the last 10 days
 \__ find / -atime 10: find files that were accessed in the last 10 day
 \__ find / -cmin -60: find files changed within the last hour (60 minutes)
 \__ find / -amin -60: find files accesses within the last hour (60 minutes)
 \__ find / -size 50M: find files with a 50 MB size
 \__ find / -writable -type d 2>/dev/null: Find world-writeable folders
 \__ find / -perm -222 -type d 2>/dev/null: Find world-writeable folders
 \__ find / -perm -o w -type d 2>/dev/null: Find world-writeable folders
 \__ find / -name perl*
 \__ find / -name python*
 \__ find / -name gcc*
 \__ find / -perm -u=s -type f 2>/dev/null: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.
 
 
