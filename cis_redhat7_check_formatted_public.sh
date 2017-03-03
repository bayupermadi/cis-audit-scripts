#!/bin/bash -
#CIS Security Audit Script
#Date: 3-1-17
#Author: Matt Wilson
#This script will run LEVEL ONE checks on the Center for Internet Security
#checklist. It will dump the report to /root/cis_report.txt for review.
#The output results can be crosschecked for their status and the sysadmin
#responsible can determine if the change can be made or not.

echo "*********************************************************"
echo "CIS Security Audit Script"
echo "Red Hat 7"
echo "Auditing for LEVEL ONE hardening"
echo "Output can be found in /root/cis_report.txt"
echo "NOTE: Run only in a bash shell"
echo ""
echo "WARNING: This script is only for Red Hat 7, please use correct script"
echo "for target operating system"
echo "*********************************************************"

exec > >(tee "/root/cis_report.txt") 2>&1

echo "CIS Security Audit Report"
echo "*DATE*"
date
echo "*OS*"
/etc/redhat-release
echo "*KERNEL*"
uname -a 
echo "*HOST*"
hostname
echo ""
echo "******1.1.1 Disable Unused File Systems******"
echo ""
echo ""

echo "1.1.1.1 Ensure mounting of cramfs filesystems is disabled"
echo "$ modprobe -n -v cramfs"
modprobe -n -v cramfs
echo "$ lsmod | grep -c cramfs"
lsmod | grep -c cramfs

echo "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled"
echo "$ modprobe -n -v freevxfs"
modprobe -n -v freevxfs
echo "$ lsmod | grep -c freevxfs"
lsmod | grep -c freevxfs

echo "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled"
echo "$ modprobe -n -v jffs2"
modprobe -n -v jffs2
echo "$ lsmod | grep -c jffs2"
lsmod | grep -c jffs2

echo "1.1.1.4 Ensure mounting of hfs filesystems is disabled"
echo "$ modprobe -n -v hfs"
modprobe -n -v hfs
echo "$ lsmod | grep -c hfs"
lsmod | grep -c hfs

echo "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled"
echo "$ modprobe -n -v hfsplus"
modprobe -n -v hfsplus
echo "$ lsmod | grep -c hfsplus"
lsmod | grep -c hfsplus

echo "1.1.1.6 Ensure mounting of squashfs filesystems is disabled"
echo "$ modprobe -n -v squashfs"
modprobe -n -v squashfs
echo "$ lsmod | grep -c squashfs"
lsmod | grep -c squashfs

echo "1.1.1.7 Ensure mounting of udf filesystems is disabled"
echo "$ modprobe -n -v udf"
modprobe -n -v udf
echo "$ lsmod | grep -c udf"
lsmod | grep -c udf

echo "1.1.1.8 Ensure mounting of FAT filesystems is disabled"
echo "$ modprobe -n -v vfat"
modprobe -n -v vfat
echo "$ lsmod | grep -c vfat"
lsmod | grep -c vfat

echo ""
echo "1.1.3 , 1.1.4 , 1.1.5"
echo "Check nodev,nosuid,noexec are set on /tmp"
echo ""

echo "$ mount | grep /tmp"
mount | grep /tmp

echo ""
echo "1.1.8 , 1.1.9 , 1.1.10"
echo "Check nodev,nosuid,noexec are set on /var/tmp"
echo ""

echo "$ mount | grep /tmp"
mount | grep /var/tmp


echo ""
echo "1.1.14"
echo "Check nodev is set on /home"
echo ""

echo "$ mount | grep /home"
mount | grep /home

echo ""
echo "1.1.15 , 1.1.16 , 1.1.17"
echo "Check nodev,nosuid,noexec are set on /dev/shm"
echo ""

echo "$ mount | grep /dev/shm"
mount | grep /dev/shm

echo ""
echo "******1.2 Configure Software Updates******"
echo ""

echo ""
echo "1.2.4"
echo "Ensure Red Hat Network or Subscription Manager connection is configured"
echo ""

echo "$ subscription-manager identity"
subscription-manager identity

echo ""
echo "******1.3 Filesystem Integrity Checking******"
echo ""

echo ""
echo "1.3.1"
echo "Check if AIDE is installed"
echo ""

echo "$ rpm -q aide"
rpm -q aide

echo ""
echo "1.3.2"
echo "Check if filesystem is regularly checked"
echo ""

echo "$ crontab -u root -l | grep aide"
crontab -u root -l | grep aide

echo "$ grep -r aide /etc/cron.* /etc/crontab"
grep -r aide /etc/cron.* /etc/crontab

echo ""
echo "******1.4 Secure Boot Settings******"
echo ""

echo ""
echo "1.4.1"
echo "Check if permissions on bootloader config are configured"
echo ""

echo "$ stat /boot/grub2/grub.cfg"
stat /boot/grub2/grub.cfg

echo ""
echo "1.4.2"
echo "Check if bootloader password is set"
echo ""

echo "$ grep '"^set superusers"' /boot/grub2/grub.cfg"
grep "^set superusers" /boot/grub2/grub.cfg

echo "$ grep '"^password"' /boot/grub2/grub.cfg"
grep "^password" /boot/grub2/grub.cfg

echo ""
echo "1.4.3"
echo "Check if authentication is required for single user mode"
echo ""

echo "$ grep /sbin/sulogin /usr/lib/systemd/system/rescue.service"
grep /sbin/sulogin /usr/lib/systemd/system/rescue.service

echo "$ grep /sbin/sulogin /usr/lib/systemd/system/emergency.service"
grep /sbin/sulogin /usr/lib/systemd/system/emergency.service

echo ""
echo "******1.5 Additional Process Hardening******"
echo ""

echo ""
echo "1.5.1"
echo "Check if core dumps are restricted"
echo ""

echo "$ grep '"hard core"' /etc/security/limits.conf /etc/security/limits.d/*"
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*

echo "$ sysctl fs.suid_dumpable"
sysctl fs.suid_dumpable

echo ""
echo "1.5.2"
echo "Check if XD/NX support is enabled"
echo ""

echo "$ dmesg | grep NX"
dmesg | grep NX

echo ""
echo "1.5.3"
echo "Check if address space layout randomization (ASLR) is enabled"
echo ""

echo "$ sysctl kernel.randomize_va_space"
sysctl kernel.randomize_va_space

echo ""
echo "1.5.4"
echo "Check if prelink is disabled"
echo ""

echo "$ rpm -q prelink"
rpm -q prelink

echo ""
echo ""******1.6 Mandatory Access Controls******
echo ""

echo ""
echo "1.6.2"
echo "Check if SELinux is installed"
echo ""

echo "$ rpm -q libselinux"
rpm -q libselinux

echo ""
echo ""******1.8 Ensure updates, patches and additional security software are installed******
echo ""

echo "$ yum check-update"
yum check-update


echo ""
echo ""******2.2 Special Purpose Services******""
echo ""

echo ""
echo "2.2.1"
echo ""
echo "2.2.1.1 Check if time synchronization is in use"
echo ""

echo "$ rpm -q ntp"
rpm -q ntp

echo ""
echo "2.2.1.2 Check if ntp is properly configured"
echo ""

echo "$ grep '"^restrict"' /etc/ntp.conf"
grep "^restrict" /etc/ntp.conf

echo "$ grep '"^server"' /etc/ntp.conf"
grep "^server" /etc/ntp.conf

echo "$ grep '"^OPTIONS"' /etc/sysconfig/ntpd"
grep "^OPTIONS" /etc/sysconfig/ntpd

echo "$ grep '"^ExecStart"' /usr/lib/systemd/system/ntpd.service"
grep "^ExecStart" /usr/lib/systemd/system/ntpd.service


echo ""
echo "2.2.3"
echo "Ensure AVAHI server is not enabled"
echo ""

echo "$ systemctl is-enabled avahi-daemon"
systemctl is-enabled avahi-daemon

echo ""
echo "2.2.4"
echo "Ensure CUPS is not enabled"
echo ""

echo "$ systemctl is-enabled cups"
systemctl is-enabled cups

echo ""
echo "2.2.5"
echo "Ensure DHCP server is not enabled"
echo ""

echo "$ systemctl is-enabled dhcpd"
systemctl is-enabled dhcpd

echo ""
echo "2.2.6"
echo "Ensure LDAP server is not enabled"
echo ""

echo "$ systemctl is-enabled slapd"
systemctl is-enabled slapd

echo ""
echo "2.2.8"
echo "Ensure DNS server is not enabled"
echo ""

echo "$ systemctl is-enabled named"
systemctl is-enabled named

echo ""
echo "2.2.9"
echo "Ensure FTP server is not enabled"
echo ""

echo "$ systemctl is-enabled vsftpd"
systemctl is-enabled vsftpd

echo ""
echo "2.2.10"
echo "Ensure HTTP server is not enabled"
echo ""

echo "$ systemctl is-enabled httpd"
systemctl is-enabled httpd

echo ""
echo "2.2.11"
echo "Ensure IMAP and POP3 server is not enabled"
echo ""

echo "$ systemctl is-enabled dovecot"
systemctl is-enabled dovecot

echo ""
echo "2.2.12"
echo "Ensure SAMBA server is not enabled"
echo ""

echo "$ systemctl is-enabled smb"
systemctl is-enabled smb

echo ""
echo "2.2.13"
echo "Ensure HTTP Proxy server is not enabled"
echo ""

echo "$ systemctl is-enabled squid"
systemctl is-enabled squid

echo ""
echo "2.2.14"
echo "Ensure SNMP server is not enabled"
echo ""

echo "$ systemctl is-enabled snmpd"
systemctl is-enabled snmpd

echo ""
echo "2.2.15"
echo "Ensure mail transfer agent is configured for loca-only mode"
echo ""

echo "$ netstat -an | grep LIST | grep '":25[[:space:]]"'"
netstat -an | grep LIST | grep ":25[[:space:]]"

echo ""
echo "2.2.16"
echo "Ensure NIS server is not enabled"
echo ""

echo "$ systemctl is-enabled ypserv"
systemctl is-enabled ypserv

echo ""
echo "2.2.17"
echo "Ensure rsh server is not enabled"
echo ""

echo "$ systemctl is-enabled rsh.socket"
systemctl is-enabled rsh.socket

echo "$ systemctl is-enabled rlogin.socket"
systemctl is-enabled rlogin.socket

echo "$ systemctl is-enabled rexec.socket"
systemctl is-enabled rexec.socket

echo ""
echo "2.2.18"
echo "Ensure telnet server is not enabled"
echo ""

echo "$ systemctl is-enabled telnet.socket"
systemctl is-enabled telnet.socket

echo ""
echo "2.2.19"
echo "Ensure tftp server is not enabled"
echo ""

echo "$ systemctl is-enabled tftp.socket"
systemctl is-enabled tftp.socket

echo ""
echo "2.2.20"
echo "Ensure rsync server is not enabled"
echo ""

echo "$ systemctl is-enabled rsyncd"
systemctl is-enabled rsyncd

echo ""
echo "2.2.21"
echo "Ensure talk server is not enabled"
echo ""

echo "$ systemctl is-enabled ntalk"
systemctl is-enabled ntalk

echo ""
echo "******3.2 Network Parameters******"
echo ""

echo ""
echo "3.2.1"
echo "Check source routed packets are not accepted"
echo ""

echo "$ sysctl net.ipv4.conf.all.accept_source_route"
sysctl net.ipv4.conf.all.accept_source_route
echo "$ sysctl net.ipv4.conf.default.accept_source_route"
sysctl net.ipv4.conf.default.accept_source_route

echo ""
echo "3.2.2"
echo "Check ICMP redicrects are not accepted"
echo ""

echo "$ sysctl net.ipv4.conf.all.accept_redirects"
sysctl net.ipv4.conf.all.accept_redirects
echo "$ sysctl net.ipv4.conf.default.accept_redirects"
sysctl net.ipv4.conf.default.accept_redirects

echo ""
echo "3.2.3"
echo "Check secure ICMP redirects are not accepted"
echo ""

echo "$ sysctl net.ipv4.conf.all.secure_redirects"
sysctl net.ipv4.conf.all.secure_redirects
echo "$ sysctl net.ipv4.conf.default.secure_redirects"
sysctl net.ipv4.conf.default.secure_redirects

echo ""
echo "3.2.4"
echo "Check if suspicious packets are logged"
echo ""

echo "$ sysctl net.ipv4.conf.all.log_martians"
sysctl net.ipv4.conf.all.log_martians
echo "$ sysctl net.ipv4.conf.default.log_martians"
sysctl net.ipv4.conf.default.log_martians

echo ""
echo "******3.3 IPv6******"
echo ""

echo ""
echo "3.3.3"
echo "Check if ipv6 is disabled"
echo ""

echo "$ modprobe -c | grep ipv6"
modprobe -c | grep ipv6

echo ""
echo "******3.6 Firewall Configuration******"
echo ""

echo ""
echo "3.6.1"
echo "Check if iptables is installed"
echo ""

echo "$ rpm -q iptables"
rpm -q iptables

echo ""
echo "******4.2.1 Configure rsyslog******"
echo ""

echo ""
echo "4.2.1.1"
echo "Check if rsyslog is enabled"
echo ""

echo "$ systemctl is-enabled rsyslog"
systemctl is-enabled rsyslog

echo ""
echo "4.2.1.2"
echo "Check if logging is configured"
echo ""

echo "$ ls -al /var/log"
ls -al /var/log

echo ""
echo "******5.2 SSH Server Configuration******"
echo ""

echo ""
echo "5.2.1"
echo "Check if permissions on /etc/ssh/sshd_config are configured"
echo ""

echo "$ stat /etc/ssh/sshd_config"
stat /etc/ssh/sshd_config

echo ""
echo "5.2.2"
echo "Check if SSH protocal is set to 2"
echo ""

echo "$ grep '"^Protocol"' /etc/ssh/sshd_config"
grep "^Protocol" /etc/ssh/sshd_config

echo ""
echo "5.2.3"
echo "Check if SSH LogLevel is set to INFO"
echo ""

echo "$ grep '"^LogLevel"' /etc/ssh/sshd_config"
grep "^LogLevel" /etc/ssh/sshd_config

echo ""
echo "5.2.4"
echo "Check if SSH X11 forwarding is disabled"
echo ""

echo "$ grep '"^X11Forwarding"' /etc/ssh/sshd_config"
grep "^X11Forwarding" /etc/ssh/sshd_config

echo ""
echo "5.2.11"
echo "Check if only approved ciphers are used"
echo ""

echo "$ grep '"Ciphers"' /etc/ssh/sshd_config"
grep "Ciphers" /etc/ssh/sshd_config

echo ""
echo "******6.1 System File Permissions******"
echo ""

echo ""
echo "6.1.2"
echo "Check if permissions on /etc/passwd are configured"
echo ""

echo "$ stat /etc/passwd"
stat /etc/passwd

echo ""
echo "6.1.3"
echo "Check if permissions on /etc/shadow are configured"
echo ""

echo "$ stat /etc/shadow"
stat /etc/shadow

echo ""
echo "6.1.4"
echo "Check if permissions on /etc/group are configured"
echo ""

echo "$ stat /etc/group"
stat /etc/group

echo ""
echo "6.1.5"
echo "Check if permissions on /etc/gshadow are configured"
echo ""

echo "$ stat /etc/gshadow"
stat /etc/gshadow

echo ""
echo "6.1.6"
echo "Check if permissions on /etc/passwd- are configured"
echo ""

echo "$ stat /etc/passwd-"
stat /etc/passwd-

echo ""
echo "6.1.7"
echo "Check if permissions on /etc/shadow- are configured"
echo ""

echo "$ stat /etc/shadow-"
stat /etc/shadow-

echo ""
echo "6.1.8"
echo "Check if permissions on /etc/group- are configured"
echo ""

echo "$ stat /etc/group-"
stat /etc/group-

echo ""
echo "6.1.9"
echo "Check if permissions on /etc/gshadow- are configured"
echo ""

echo "$ stat /etc/gshadow-"
stat /etc/gshadow-

echo ""
echo "******6.2 User and Group Settings******"
echo ""

echo ""
echo "6.2.5"
echo "Check if root is the only UID 0 account"
echo ""

echo "$ cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'"
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'

