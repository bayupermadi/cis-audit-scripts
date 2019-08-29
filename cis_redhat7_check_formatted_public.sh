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

exec > "/root/cis_report.txt"

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

modules=(cramfs freevxfs freevxfs jffs2 hfsplus squashfs udf vfat)
a=1
for i in "${modules[@]}";
do 
    modprobe=`modprobe -n -v $i`
    lsmod=`lsmod | grep $i`
    if [ "$modprobe" == "install /bin/true" ] || [ "$lsmod" == "" ];
        then
            echo "1.1.1.$a;Ensure mounting of $i filesystems is disabled;OK"
        else
            echo "1.1.1.$a;Ensure mounting of $i filesystems is disabled;WARNING"
    fi
    a=$(($a+1));
done;

mounted=(nodev nosuid noexec)
partition=(/tmp /var/tmp /dev/shm)
for i in "${partition[@]}";
do 
    if [ "$i" == "/tmp" ]; then a=3
    elif [ "$i" == "/var/tmp" ]; then a=8
    else a=15
    fi

    for x in "${mounted[@]}";
    do
        check=`mount | grep $i | grep $x`
        if [ "$check" != "" ] ;
            then
                echo "1.1.$a;Ensure $x option set on $i partition;OK"
            else
                echo "1.1.$a;Ensure $x option set on $i partition;WARNING"
        fi
        a=$(($a+1));
    done;
done;

mounted="nodev"
partition="/home"
check=`mount | grep $mounted | grep $partition`
if [ "$check" != "" ] ;
    then
        echo "1.1.14;Ensure $mounted option set on $partition partition;OK"
    else
        echo "1.1.14;Ensure $mounted option set on $partition partition;WARNING"
fi

echo ""
echo "******1.2 Configure Software Updates******"
echo ""

check=`subscription-manager identity | grep -E "org name|org ID"`
if [ "$check" != "" ] ;
    then
        echo "1.2.4;Ensure Red Hat Network or Subscription Manager connection is configured;OK"
    else
        echo "1.2.4;Ensure Red Hat Network or Subscription Manager connection is configured;WARNING"
fi

echo ""
echo "******1.3 Filesystem Integrity Checking******"
echo ""

check=`rpm -q aide`
if [ "$check" != "package aide is not installed" ] ;
    then
        echo "1.3.1;Ensure AIDE is installed;OK"
    else
        echo "1.3.1;Ensure AIDE is installed;WARNING"
fi

check1=`crontab -u root -l | grep aide`
check2=`grep -r aide /etc/cron.* /etc/crontab`
if [ "$check1" != "" ] || [ "$check2" != "" ];
    then
        echo "1.3.2;Ensure filesystem integrity is regularly checked;OK"
    else
        echo "1.3.2;Ensure filesystem integrity is regularly checked;WARNING"
fi

echo ""
echo "******1.4 Secure Boot Settings******"
echo ""

check1=`stat /boot/grub2/grub.cfg | grep Access`
if [ "$check1" != "" ];
    then
        echo "1.4.1;Ensure permissions on bootloader config are configured;OK"
    else
        echo "1.4.1;Ensure permissions on bootloader config are configured;WARNING"
fi

check1=`grep /sbin/sulogin /usr/lib/systemd/system/rescue.service | grep ExecStart`
check2=`grep /sbin/sulogin /usr/lib/systemd/system/emergency.service | grep ExecStart`
if [ "$check1" != "" ] || [ "$check2" != "" ];
    then
        echo "1.4.3;Ensure authentication required for single user mode;OK"
    else
        echo "1.4.3;Ensure authentication required for single user mode;WARNING"
fi

echo ""
echo "******1.5 Additional Process Hardening******"
echo ""

check1=`grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*`
check2=`sysctl fs.suid_dumpable`
if [ "$check1" != "" ] || [ "$check2" != "" ];
    then
        echo "1.5.1;Ensure core dumps are restricted;OK"
    else
        echo "1.5.1;Ensure core dumps are restricted;WARNING"
fi


check1=`dmesg | grep NX | grep protection`
if [ "$check1" != "" ];
    then
        echo "1.5.2;Ensure XD/NX support is enabled;OK"
    else
        echo "1.5.2;Ensure XD/NX support is enabled;WARNING"
fi

check1=`sysctl kernel.randomize_va_space | awk '{print $3}'`
if [ "$check1" == "2" ];
    then
        echo "1.5.3;Ensure XD/NX support is enabled;OK"
    else
        echo "1.5.4;Ensure XD/NX support is enabled;WARNING"
fi

check1=`rpm -q prelink`
if [ "$check1" == "package prelink is not installed" ];
    then
        echo "1.5.4;Ensure prelink is disabled;OK"
    else
        echo "1.5.4;Ensure prelink is disabled;WARNING"
fi

echo ""
echo ""******1.6 Mandatory Access Controls******
echo ""

check1=`rpm -q libselinux | grep selinux`
if [ "$check1" != "" ];
    then
        echo "1.6.2;Ensure SELinux is installed;OK"
    else
        echo "1.6.2;Ensure SELinux is installed;WARNING"
fi

echo ""
echo ""******2.2 Special Purpose Services******""
echo ""

check1=`rpm -q ntp | grep ntp`
if [ "$check1" != "package ntp is not installed" ];
    then
        echo "2.2.1.1;Ensure time synchronization is in use;OK"
    else
        echo "2.2.1.1;Ensure time synchronization is in use;WARNING"
fi

check1=`grep '"^restrict"' /etc/ntp.conf`
check2=`grep '"^(server|pool)"' /etc/ntp.conf`
check3=`grep '"^OPTIONS"' /etc/sysconfig/ntpd`
check4=`grep '"^ExecStart"' /usr/lib/systemd/system/ntpd.service`
if [ "$check1" != "" ] || [ "$check2" != "" ] || [ "$check3" != "" ] || [ "$check4" != "" ];
    then
        echo "2.2.1.2;Ensure ntp is configured;OK"
    else
        echo "2.2.1.2;Ensure ntp is configured;WARNING"
fi

services=(avahi-daemon cups dhcpd slapd named vsftpd httpd dovecot smb squid snmpd ypserv telnet.socket tftp.socket rsyncd ntalk)
svc_name=(AVAHI CUPS DHCP LDAP DNS FTP HTTP IMAP/POP3 SAMBA HTTP-Proxy SNMP NIS telnet tftp rsync talk)
a=3
loop=0
for i in "${services[@]}";
do 
    if [ "$i" == "named" ]; then a=8; 
    elif [ "$i" == "ypserv" ]; then a=16; 
    elif [ "$i" == "telnet.socket" ]; then a=18; 
    fi;

    check=`systemctl is-enabled $i`
    if [ "$check" == "" ] ;
        then
            echo "2.2.$a;Ensure ${svc_name[$loop]} Server is not enabled;OK"
        else
            echo "2.2.$a;Ensure ${svc_name[$loop]} Server is not enabled;WARNING"
    fi
    a=$(($a+1));
    loop=$(($loop+1));
done;

check1=`netstat -an | grep LIST | grep ":25[[:space:]]" | grep 127.0.0.1`
if [ "$check1" != "" ];
    then
        echo "2.2.15;Ensure mail transfer agent is configured for local-only mode;OK"
    else
        echo "2.2.15;Ensure mail transfer agent is configured for local-only mode;WARNING"
fi

check1=`systemctl is-enabled rsh.socket`
check2=`systemctl is-enabled rlogin.socket`
check3=`systemctl is-enabled rexec.socket`
if [ "$check1" != "" ] || [ "$check2" != "" ] || [ "$check3" != "" ];
    then
        echo "2.2.17;Ensure rsh server is not enabled;OK"
    else
        echo "2.2.17;Ensure rsh server is not enabled;WARNING"
fi

echo ""
echo "******3.2 Network Parameters******"
echo ""

check1=`sysctl net.ipv4.conf.all.accept_source_route | awk '{print $3}'`
check2=`sysctl net.ipv4.conf.default.accept_source_route | awk '{print $3}'`
if [ "$check1" == "0" ] && [ "$check2" == "0" ];
    then
        echo "3.2.1;Ensure source routed packets are not accepted;OK"
    else
        echo "3.2.1;Ensure source routed packets are not accepted;WARNING"
fi

check1=`sysctl net.ipv4.conf.all.accept_redirects | awk '{print $3}'`
check2=`sysctl  net.ipv4.conf.default.accept_redirects | awk '{print $3}'`
if [ "$check1" == "0" ] && [ "$check2" == "0" ];
    then
        echo "3.2.2;Ensure ICMP redirects are not accepted;OK"
    else
        echo "3.2.2;Ensure ICMP redirects are not accepted;WARNING"
fi

check1=`sysctl net.ipv4.conf.all.secure_redirects | awk '{print $3}'`
check2=`sysctl net.ipv4.conf.default.secure_redirects | awk '{print $3}'`
if [ "$check1" == "0" ] && [ "$check2" == "0" ];
    then
        echo "3.2.3;Ensure secure ICMP redirects are not accepted;OK"
    else
        echo "3.2.3;Ensure secure ICMP redirects are not accepted;WARNING"
fi

check1=`sysctl net.ipv4.conf.all.log_martians | awk '{print $3}'`
check2=`sysctl net.ipv4.conf.default.log_martians | awk '{print $3}'`
if [ "$check1" == "1" ] && [ "$check2" == "1" ];
    then
        echo "3.2.4;Ensure suspicious packets are logged;OK"
    else
        echo "3.2.4;Ensure suspicious packets are logged;WARNING"
fi

echo ""
echo "******3.6 Firewall Configuration******"
echo ""

check1=`rpm -q iptables`
if [ "$check1" != "package iptables is not installed" ] ;
    then
        echo "3.6;Ensure iptables is installed;OK"
    else
        echo "3.6;Ensure iptables is installed;WARNING"
fi

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

