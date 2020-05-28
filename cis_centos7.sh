#!/bin/bash -
#CIS Security Audit Script
#Date: 3-1-17
#Author: Bayu Permadi
#This script will run only scored checks on the Center for Internet Security
#checklist. It will dump the report to /root/cis_report.csv for review.
#The output results can be crosschecked for their status and the sysadmin
#responsible can determine if the change can be made or not.

echo "*********************************************************"
echo "CIS Security Audit Script"
echo "CentOS 7"
echo "Auditing for LEVEL ONE hardening"
echo "Output can be found in /root/cis_report.csv"
echo "NOTE: Run only in a bash shell"
echo ""
echo "WARNING: This script is only for CentOS 7, please use correct script"
echo "for target operating system"
echo "*********************************************************"

exec > "/root/cis_report.csv"

echo "NAME;CIS Security Audit Report"
echo -n "DATE;"
date
echo -n "OS;"
cat /etc/redhat-release
echo -n "KERNEL;"
uname -a 
echo -n "HOST;"
hostname

echo ""
echo "No;Scope;Status"
echo "1;Initial Setup"
echo "1.1;Filesystem Configuration"
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

mount=(/tmp /var /var/tmp /var/log /var/log/audit /home)
number=(2 6 7 11 12 13)
a=0
for i in "${mount[@]}";
do 
    check=`mount | grep $i`
    if [ "$check" != " " ];
        then
            echo "1.1.${number[$a]};Ensure separate partition exists for $i;OK"
        else
            echo "1.1.${number[$a]};Ensure separate partition exists for $i;WARNING"
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

check=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null`
if [ "$check" == "" ] ;
    then
        echo "1.1.21;Ensure sticky bit is set on all world-writable directories;OK"
    else
        echo "1.1.21;Ensure sticky bit is set on all world-writable directories;WARNING"
fi

check=`systemctl is-enabled autofs`
if [ $? == 1 ] ;
    then
        echo "1.1.22;Disable Automounting;OK"
    else
        echo "1.1.22;Disable Automounting;WARNING"
fi

echo "1.2;Configure Software Updates"
check=`grep ^gpgcheck /etc/yum.conf`
if [ "$check" == "gpgcheck=1" ] ;
    then
        echo "1.2.2;Ensure gpgcheck is globally activated;OK"
    else
        echo "1.2.2;Ensure gpgcheck is globally activated;WARNING"
fi;


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


check1=`stat /boot/grub2/grub.cfg | grep Uid | awk '{print $2}'`
if [ "$check1" == "(0600/-rw-------)" ];
    then
        echo "1.4.1;Ensure permissions on bootloader config are configured;OK"
    else
        echo "1.4.1;Ensure permissions on bootloader config are configured;WARNING"
fi

check1=`grep "^GRUB2_PASSWORD" /boot/grub2/grub.cfg`
if [ "$check1" != "" ];
    then
        echo "1.4.2;Ensure bootloader password is set;OK"
    else
        echo "1.4.2;Ensure bootloader password is set;WARNING"
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

echo "1.6 Mandatory Access Control"
echo "1.6.1 Configure SELinux"
check1=`grep "^\s*linux" /boot/grub2/grub.cfg | grep selinux=0`
if [ "$check1" == "" ];
    then
        echo "1.6.1.1;Ensure SELinux is not disabled in bootloader configuration;OK"
    else
        echo "1.6.1.1;Ensure SELinux is not disabled in bootloader configuration;WARNING"
fi

check1=`getenforce`
if [ "$check1" == "Enforcing" ];
    then
        echo "1.6.1.2;Ensure the SELinux state is enforcing;OK"
    else
        echo "1.6.1.2;Ensure the SELinux state is enforcing;WARNING"
fi

check1=`grep SELINUXTYPE=targeted /etc/selinux/config`
if [ $? == 0 ];
    then
        echo "1.6.1.3;Ensure SELinux policy is configured;OK"
    else
        echo "1.6.1.3;Ensure SELinux policy is configured;WARNING"
fi

check1=`rpm -q setroubleshoot`
if [ $? == 1 ];
    then
        echo "1.6.1.4;Ensure SETroubleshoot is not installed;OK"
    else
        echo "1.6.1.4;Ensure SETroubleshoot is not installed;WARNING"
fi

check1=` rpm -q mcstrans`
if [ $? == 1 ];
    then
        echo "1.6.1.5;Ensure the MCS Translation Service (mcstrans) is not installed;OK"
    else
        echo "1.6.1.5;Ensure the MCS Translation Service (mcstrans) is not installed;WARNING"
fi

check1=` ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF }'`
if [ "$check1" == "" ];
    then
        echo "1.6.1.6;Ensure no unconfined daemons exist;OK"
    else
        echo "1.6.1.6 Ensure no unconfined daemons exist;WARNING"
fi

check1=`rpm -q libselinux`
if [ "$check1" != "" ];
    then
        echo "1.6.2;Ensure SELinux is installed;OK"
    else
        echo "1.6.2;Ensure SELinux is installed;WARNING"
fi

echo "1.7 Warning Banners"
echo "1.7.1 Command Line Warning Banners"

check1=`egrep '(\\v|\\r|\\m|\\s)' /etc/motd`
if [ "$check1" == "" ];
    then
        echo "1.7.1.1;Ensure message of the day is configured properly;OK"
    else
        echo "1.7.1.1;Ensure message of the day is configured properly;WARNING"
fi

check1=`stat /etc/issue | grep "644" | grep "root"`
if [ $? == 0 ];
    then
        echo "1.7.1.5;Ensure permissions on /etc/issue are configured;OK"
    else
        echo "1.7.1.5;Ensure permissions on /etc/issue are configured;WARNING"
fi

check1=`cat /usr/share/dconf/profile/gdm | grep -E "user-db:user|system-db:gdm|file-db:/usr/share/gdm/greeter-dconf-defaults" | wc -l`
check2=`cat /etc/dconf/db/gdm.d/01-banner-message | grep -E "[org/gnome/login-screen]|banner-message-enable=true|banner-message-text=" | wc -l`
if [ "$check1" != 0 ] && [ "$check2" != 0 ];
    then
        echo "1.7.2;Ensure GDM login banner is configured;OK"
    else
        echo "1.7.2;Ensure GDM login banner is configured;WARNING"
fi

#################################

echo ""
echo "2.1;inetd Services"
a=1
service=(chargen daytime discard echo time)
for x in "${service[@]}";
do
    check1=`systemctl is-enabled $x-dram`
    check2=`systemctl is-enabled $x-stream`
    if [ "$check1" == "" ] && [ "$check2" == "" ]; 
        then
            echo "2.1.$a;Ensure $x services are not enabled;OK"
        else
            echo "2.1.$a;Ensure $x services are not enabled;WARNING"
    fi
    a=$(($a+1));
done;

check1=`systemctl is-enabled tftp`
if [ "$check1" == "" ]; 
    then
        echo "2.1.6;Ensure tftp server is not enabled;OK"
    else
        echo "2.1.6;Ensure tftp server is not enabled;WARNING"
fi

check1=`systemctl is-enabled xinetd`
if [ "$check1" == "" ]; 
    then
        echo "2.1.7;Ensure xinetd is not enabled;OK"
    else
        echo "2.1.7;Ensure xinetd is not enabled;WARNING"
fi

echo "2.2;Special Purpose Services"
echo "2.2.1;Time Synchronization"
check1=`rpm -q ntp | grep ntp`
if [ "$check1" != "package ntp is not installed" ];
    then
        echo "2.2.1.1;Ensure time synchronization is in use;OK"
    else
        echo "2.2.1.1;Ensure time synchronization is in use;WARNING"
fi

check1=`grep '"^restrict"' /etc/ntp.conf`
check2=`grep -E "server|pool" /etc/ntp.conf`
check3=`grep -- "-u ntp:ntp" /usr/lib/systemd/system/ntpd.service /etc/sysconfig/ntpd`
if [ "$check1" != "" ] || [ "$check2" != "" ] || [ "$check3" != "" ] || [ "$check4" != "" ];
    then
        echo "2.2.1.2;Ensure ntp is configured;OK"
    else
        echo "2.2.1.2;Ensure ntp is configured;WARNING"
fi

check1=`grep -E "server|pool" /etc/chrony.conf`
check2=`grep -- '-u chrony' /etc/sysconfig/chronyd`
if [ "$check1" != "" ] && [ "$check2" != "" ];
    then
        echo "2.2.1.3;Ensure chrony is configured;OK"
    else
        echo "2.2.1.3;Ensure chrony is configured;WARNING"
fi

check1=`rpm -qa xorg-x11*`
if [ "$check1" == "" ];
    then
        echo "2.2.2;Ensure X Window System is not installed;OK"
    else
        echo "2.2.2;Ensure X Window System is not installed;WARNING"
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
    if [ "$check" == "disabled" ] ;
        then
            echo "2.2.$a;Ensure ${svc_name[$loop]} Server is not enabled;OK"
        else
            echo "2.2.$a;Ensure ${svc_name[$loop]} Server is not enabled;WARNING"
    fi
    a=$(($a+1));
    loop=$(($loop+1));
done;

check1=`systemctl is-enabled nfs`
check2=`systemctl is-enabled nfs-server`
check3=`systemctl is-enabled rpcbind`
if [ "$check1" == "disabled" ] && [ "$check2" == "disabled" ] && [ "$check3" == "disabled" ] ;
    then
        echo "2.2.7;Ensure NFS and RPC are not enabled;OK"
    else
        echo "2.2.7;Ensure NFS and RPC are not enabled;WARNING"
fi

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
if [ "$check1" == "disabled" ] && [ "$check2" == "disabled" ] && [ "$check3" == "disabled" ];
    then
        echo "2.2.17;Ensure rsh server is not enabled;OK"
    else
        echo "2.2.17;Ensure rsh server is not enabled;WARNING"
fi

echo "2.3;Service Clients"
a=1
loop=0
service=(ypbind rsh talk telnet openldap-clients)
name=(NIS rsh talk telnet LDAP)
for x in "${service[@]}";
do
    check1=`rpm -q $x`
    if [ "$check1" == "package $x is not installed" ]; 
        then
            echo "2.3.$a;Ensure ${name[$loop]} client is not installed;OK"
        else
            echo "2.3.$a;Ensure ${name[$loop]} client is not installed;WARNING"
    fi
    a=$(($a+1));
    loop=$(($loop+1));
done;

echo ""
echo "3;Network Configuration"
echo "3.1;Network Parameters (Host Only);"
check1=`sysctl net.ipv4.ip_forward | awk '{print $3}'`
if [ "$check1" == "0" ];
    then
        echo "3.1.1;Ensure IP forwarding is disabled;OK"
    else
        echo "3.1.1;Ensure IP forwarding is disabled;WARNING"
fi

check1=`sysctl net.ipv4.conf.all.send_redirects | awk '{print $3}'`
check2=`sysctl net.ipv4.conf.default.send_redirects | awk '{print $3}'`
if [ "$check1" == "0" ] && [ "$check2" == "0" ];
    then
        echo "3.1.2;Ensure packet redirect sending is disabled;OK"
    else
        echo "3.1.2;Ensure packet redirect sending is disabled;WARNING"
fi

echo "3.2;Network Parameters (Host and Router);"

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

check1=`sysctl net.ipv4.icmp_echo_ignore_broadcasts  | awk '{print $3}'`
if [ "$check1" == "1" ];
    then
        echo "3.2.5;Ensure broadcast ICMP requests are ignored;OK"
    else
        echo "3.2.5;Ensure broadcast ICMP requests are ignored;WARNING"
fi

check1=`sysctl net.ipv4.icmp_ignore_bogus_error_responses  | awk '{print $3}'`
if [ "$check1" == "1" ];
    then
        echo "3.2.6;Ensure bogus ICMP responses are ignored ;OK"
    else
        echo "3.2.6;Ensure bogus ICMP responses are ignored ;WARNING"
fi

check1=`sysctl net.ipv4.conf.all.rp_filter  | awk '{print $3}'`
check2=`sysctl net.ipv4.conf.default.rp_filter  | awk '{print $3}'`
if [ "$check1" == "1" ] && [ "$check1" == "1" ];
    then
        echo "3.2.7;Ensure Reverse Path Filtering is enabled;OK"
    else
        echo "3.2.7;Ensure Reverse Path Filtering is enabled;WARNING"
fi

check1=`sysctl net.ipv4.tcp_syncookies | awk '{print $3}'`
if [ "$check1" == "1" ];
    then
        echo "3.2.8;Ensure TCP SYN Cookies is enabled;OK"
    else
        echo "3.2.8;Ensure TCP SYN Cookies is enabled;WARNING"
fi

echo "3.3;IPv6;"
check1=`sysctl net.ipv6.conf.all.accept_ra | awk '{print $3}'`
check2=`sysctl net.ipv6.conf.default.accept_ra | awk '{print $3}'`
if [ "$check1" == 0 ] && [ "$check2" == 0 ];
    then
        echo "3.3.1;Ensure IPv6 router advertisements are not accepted;OK"
    else
        echo "3.3.1;Ensure IPv6 router advertisements are not accepted;WARNING"
fi

check1=`sysctl net.ipv6.conf.all.accept_redirects | awk '{print $3}'`
check2=`sysctl net.ipv6.conf.default.accept_redirects | awk '{print $3}'`
if [ "$check1" == 0 ] && [ "$check2" == 0 ];
    then
        echo "3.3.2;Ensure IPv6 redirects are not accepted;OK"
    else
        echo "3.3.2;Ensure IPv6 redirects are not accepted;WARNING"
fi

echo "3.4;TCP Wrappers;"
check1=`rpm -q tcp_wrappers`
if [ "$check1" != "package tcp_wrappers is not installed" ];
    then
        echo "3.4.1;Ensure TCP Wrappers is installed;OK"
    else
        echo "3.4.1;Ensure TCP Wrappers is installed;WARNING"
fi

echo "3.4.2;Ensure /etc/hosts.allow is configured;WARNING;ignored - access would handled by firewall"
echo "3.4.3;Ensure /etc/hosts.deny is configured;WARNING;ignored - access would handled by firewall"


check1=`stat /etc/hosts.allow | grep Uid | awk '{print $2}'`
if [ "$check1" == "(0644/-rw-r--r--)" ];
    then
        echo "3.4.4;Ensure permissions on /etc/hosts.allow are configured;OK"
    else
        echo "3.4.4;Ensure permissions on /etc/hosts.allow are configured;WARNING"
fi

check1=`stat /etc/hosts.deny | grep Uid | awk '{print $2}'`
if [ "$check1" == "(0644/-rw-r--r--)" ];
    then
        echo "3.4.5;Ensure permissions on /etc/hosts.deny are configured;OK"
    else
        echo "3.4.5;Ensure permissions on /etc/hosts.deny are configured;WARNING"
fi

echo "3.6;Firewall Configuration;"

echo "3.6.1;Ensure iptables is installed;WARNING;ignored - server user firewalld instead iptables"
echo "3.6.2;Ensure default deny firewall policy;WARNING;ignored - server user firewalld instead iptables"
echo "3.6.3;Ensure loopback traffic is configured;WARNING;ignored - server user firewalld instead iptables"
echo "3.6.5;Ensure firewall rules exist for all open ports;WARNING;ignored - server user firewalld instead iptables"

echo ""
echo "4;Logging and Auditing"
echo "4.1;Configure System Accounting"
echo "4.1.1;Configure Data Retention;"
echo "4.1.1.2;Ensure system is disabled when audit logs are full;WARNING;ignored - server need to keep running"
echo "4.1.1.3;Ensure audit logs are not automatically deleted;ignored - retention should be used for log housekeeping"

check1=`systemctl is-enabled auditd`
if [ "$check1" == "enabled" ] ;
    then
        echo "4.1.2;Ensure auditd service is enabled;OK"
    else
        echo "4.1.2;Ensure auditd service is enabled;WARNING"
fi

echo "4.2;Configure logging"
echo "4.2.1;Configure rsyslog;"

check1=`systemctl is-enabled rsyslog`
if [ "$check1" == "enabled" ] ;
    then
        echo "4.2.1.1;Ensure rsyslog Service is enabled;OK"
    else
        echo "4.2.1.1;Ensure rsyslog Service is enabled;WARNING"
fi

check1=`rpm -q rsyslog`
check2=`rpm -q syslog-ng`
if [ "$check1" != "package rsyslog is not installed" ] || [ "$check2" != "package syslog-ng is not installed" ];
    then
        echo "4.2.3;Ensure rsyslog or syslog-ng is installed;OK"
    else
        echo "4.2.3;Ensure rsyslog or syslog-ng is installed;WARNING"
fi

echo ""
echo "5;Access, Authentication and Authorization"
echo "5.1;Configure cron;"
check1=`systemctl is-enabled crond`
if [ "$check1" == "enabled" ];
    then
        echo "5.1.1;Ensure cron daemon is enabled;OK"
    else
        echo "5.1.1;Ensure cron daemon is enabled;WARNING"
fi
echo "5.2;SSH Server Configuration;"

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

check1=`grep "PermitEmptyPasswords" /etc/ssh/sshd_config`
if [ "$check1" == "PermitEmptyPasswords no" ] ;
    then
        echo "5.2.9;Ensure SSH PermitEmptyPasswords is disabled;OK"
    else
        echo "5.2.9;Ensure SSH PermitEmptyPasswords is disabled;WARNING"
fi

check1=`grep "Ciphers" /etc/ssh/sshd_config | grep -v key`
if [ "$check1" == "Ciphers aes256-ctr,aes192-ctr,aes128-ctr" ] ;
    then
        echo "5.2.12;Ensure only approved ciphers are used;OK"
    else
        echo "5.2.12;Ensure only approved ciphers are used;WARNING"
fi
check1=`grep "ClientAliveInterval" /etc/ssh/sshd_config`
check2=`grep "ClientAliveCountMax" /etc/ssh/sshd_config`
if [ "$check1" == "ClientAliveInterval 300" ] && [ "$check2" == "ClientAliveCountMax 0" ]  ;
    then
        echo "5.2.13;Ensure SSH Idle Timeout Interval is configured;OK"
    else
        echo "5.2.13;Ensure SSH Idle Timeout Interval is configured;WARNING"
fi

check1=`grep "Banner" /etc/ssh/sshd_config`
if [ "$check1" == "Banner /etc/issue.net" ];
    then
        echo "5.2.16;Ensure SSH warning banner is configured;OK"
    else
        echo "5.2.16;Ensure SSH warning banner is configured;WARNING"
fi

echo ""
echo "6.1;System File Permissions;"

file=(passwd shadow group gshadow passwd- shadow- group- gshadow-)
permission=("(0644/-rw-r--r--)" "(0000/----------)" "(0644/-rw-r--r--)" "(0000/----------)" "(0644/-rw-r--r--)" "(0000/----------)" "(0644/-rw-r--r--)" "(0000/----------)")
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

check=`cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'`
if [ "$check" == "" ] ;
    then
        echo "6.2.1;Ensure password fields are not empty;OK"
    else
        echo "6.2.1;Ensure password fields are not empty;WARNING"
fi

check=`grep '^\+:' /etc/passwd`
if [ "$check" == "" ] ;
    then
        echo "6.2.2;Ensure no legacy "+" entries exist in /etc/passwd;OK"
    else
        echo "6.2.2;Ensure no legacy "+" entries exist in /etc/passwd;WARNING"
fi

check=`grep '^\+:' /etc/shadow`
if [ "$check" == "" ] ;
    then
        echo "6.2.3;Ensure no legacy "+" entries exist in /etc/shadow;OK"
    else
        echo "6.2.3;Ensure no legacy "+" entries exist in /etc/shadow;WARNING"
fi

check=`grep '^\+:' /etc/group`
if [ "$check" == "" ] ;
    then
        echo "6.2.4;Ensure no legacy "+" entries exist in /etc/group;OK"
    else
        echo "6.2.4;Ensure no legacy "+" entries exist in /etc/group;WARNING"
fi


check=`cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'`
if [ "$check" == "root" ] ;
    then
        echo "6.2.5;Ensure root is the only UID 0 account;OK"
    else
        echo "6.2.5;Ensure root is the only UID 0 account;WARNING"
fi

