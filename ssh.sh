#!/bin/bash

# 确保脚本以root用户执行
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# 修改/root/.ssh/authorized_keys，移除特定的限制字符串
sed -i '1s/no-port.*exit [0-9]\+" //' /root/.ssh/authorized_keys

# 修改/etc/ssh/sshd_config，启用公钥认证和允许root登录
sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

# 重启SSHD服务
systemctl restart sshd

echo "SSH configuration updated and SSHD service restarted."
