#!/bin/bash

readp() {
    read -p "$1" $2
}

[[ $EUID -ne 0 ]] && su='sudo' 

lsattr /etc/passwd /etc/shadow >/dev/null 2>&1
chattr -i /etc/passwd /etc/shadow >/dev/null 2>&1
chattr -a /etc/passwd /etc/shadow >/dev/null 2>&1
lsattr /etc/passwd /etc/shadow >/dev/null 2>&1

prl=$(grep PermitRootLogin /etc/ssh/sshd_config)
pa=$(grep PasswordAuthentication /etc/ssh/sshd_config)

if [[ -n $prl && -n $pa ]]; then
    readp "自定义root密码:" mima
    if [[ -n $mima ]]; then
        echo root:$mima | $su chpasswd root
        $su sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
        $su sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
        $su service sshd restart
        echo "VPS当前用户名：root"
        echo "vps当前root密码：$mima"
    else
        echo "未输入相关字符，启用root账户或root密码更改失败"
    fi
else
    echo "当前VPS不支持root账户或无法自定义root密码，建议先执行sudo -i进入root账户后再执行脚本"
fi

rm -rf root.sh
