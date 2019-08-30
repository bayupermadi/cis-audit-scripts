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
echo "Output can be found in /root/cis_report.csv"
echo "NOTE: Run only in a bash shell"
echo ""
echo "WARNING: This script is only for Red Hat 7, please use correct script"
echo "for target operating system"
echo "*********************************************************"

exec > "/root/cis_report.csv"

echo "NAME; CIS Security Audit Report"
echo -n "DATE; "
date
echo -n "OS;"
cat /etc/redhat-release
echo -n "KERNEL;"
uname -a 
echo -n "HOST;"
hostname

echo ""
echo "No;Scope;Status"
echo "1.1.1;Disable Unused File Systems"

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

echo "1.2;Configure Software Updates"

check=`subscription-manager identity | grep -E "org name|org ID"`
if [ "$check" != "" ] ;
    then
        echo "1.2.4;Ensure Red Hat Network or Subscription Manager connection is configured;OK"
    else
        echo "1.2.4;Ensure Red Hat Network or Subscription Manager connection is configured;WARNING"
fi


echo "1.3;Filesystem Integrity Checking;"

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


echo "1.4;Secure Boot Settings;"


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


echo "1.5;Additional Process Hardening;"


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


echo "1.6;Mandatory Access Controls;"

check1=`rpm -q libselinux | grep selinux`
if [ "$check1" != "" ];
    then
        echo "1.6.2;Ensure SELinux is installed;OK"
    else
        echo "1.6.2;Ensure SELinux is installed;WARNING"
fi

echo ""
echo "2.2;Special Purpose Services"

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
echo "3.2;Network Parameters;"

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

echo "3.6;Firewall Configuration;"

check1=`rpm -q iptables`
if [ "$check1" != "package iptables is not installed" ] ;
    then
        echo "3.6;Ensure iptables is installed;OK"
    else
        echo "3.6;Ensure iptables is installed;WARNING"
fi

echo ""
echo "4.2.1;Configure rsyslog;"

check1=`systemctl is-enabled rsyslog`
if [ "$check1" == "enabled" ] ;
    then
        echo "4.2.1.1;Ensure rsyslog Service is enabled;OK"
    else
        echo "4.2.1.1;Ensure rsyslog Service is enabled;WARNING"
fi

echo ""
echo "5.2;SSH Server Configuration;"

check1=`systemctl is-enabled rsyslog`
if [ "$check1" == "enabled" ] ;
    then
        echo "4.2.1.1;Ensure rsyslog Service is enabled;OK"
    else
        echo "4.2.1.1;Ensure rsyslog Service is enabled;WARNING"
fi

check1=`stat /etc/ssh/sshd_config | grep Uid | awk '{print $2}'`
if [ "$check1" == "(0600/-rw-------)" ] ;
    then
        echo "5.2.1;Ensure permissions on /etc/ssh/sshd_config are configured;OK"
    else
        echo "5.2.1;Ensure permissions on /etc/ssh/sshd_config are configured;WARNING"
fi

check1=`stat /etc/ssh/sshd_config | grep Uid | awk '{print $2}'`
if [ "$check1" == "(0600/-rw-------)" ] ;
    then
        echo "5.2.1;Ensure permissions on /etc/ssh/sshd_config are configured;OK"
    else
        echo "5.2.1;Ensure permissions on /etc/ssh/sshd_config are configured;WARNING"
fi

check1=`grep "^Protocol" /etc/ssh/sshd_config`
if [ "$check1" == "Protocol 2" ] ;
    then
        echo "5.2.2;Ensure SSH Protocol is set to 2;OK"
    else
        echo "5.2.2;Ensure SSH Protocol is set to 2;WARNING"
fi

check1=`grep "^LogLevel" /etc/ssh/sshd_config`
if [ "$check1" == "LogLevel INFO" ] ;
    then
        echo "5.2.3;Ensure SSH LogLevel is set to INFO;OK"
    else
        echo "5.2.3;Ensure SSH LogLevel is set to INFO;WARNING"
fi

check1=`grep "^X11Forwarding" /etc/ssh/sshd_config`
if [ "$check1" == "X11Forwarding no" ] ;
    then
        echo "5.2.4;Ensure SSH X11 forwarding is disabled;OK"
    else
        echo "5.2.4;Ensure SSH X11 forwarding is disabled;WARNING"
fi

check1=`grep "Ciphers" /etc/ssh/sshd_config`
if [ "$check1" == "Ciphers aes256-ctr,aes192-ctr,aes128-ctr" ] ;
    then
        echo "5.2.11;Ensure only approved MAC algorithms are used;OK"
    else
        echo "5.2.11;Ensure only approved MAC algorithms are used;WARNING"
fi

echo ""
echo "6.1;System File Permissions;"

file=(passwd shadow group gshadow passwd- shadow- group- gshadow-)
permission=("(0644/-rw-r--r--)" "(0000/----------)" "(0644/-rw-r--r--)" "(0000/----------)" "(0644/-rw-------)" "(0000/----------)" "(0644/-rw-------)" "(0000/----------)")
a=2
loop=0
for i in "${file[@]}";
do 
    check=`stat /etc/$i | grep Uid | awk '{print $2}'`
    if [ "$check" == "${permission[$loop]}" ] ;
        then
            echo "6.1.$a;Ensure permissions on /etc/$i are configured;OK"
        else
            echo "6.1.$a;Ensure permissions on /etc/$i are configured;WARNING"
    fi
    a=$(($a+1));
    loop=$(($loop+1));
done;

echo "6.2;User and Group Settings;"

check=`cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'`
if [ "$check" == "root" ] ;
    then
        echo "6.2.5;Ensure root is the only UID 0 account;OK"
    else
        echo "6.2.5;Ensure root is the only UID 0 account;WARNING"
fi

