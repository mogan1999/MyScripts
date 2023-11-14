#!/bin/bash

# 检查目录是否存在
if [ ! -d "/etc/wireguard" ]; then
  echo "directory does not exist."
  exit 1
fi

# 检查目录下文件是否存在
if [ ! -f "/etc/wireguard/warp.conf" ]; then
  echo "file does not exist."
  exit 1
fi

# 使用sed命令替换字符串
sed -i 's/DNS = 1.1.1.1,8.8.8.8,8.8.4.4,2606:4700:4700::1111,2001:4860:4860::8888,2001:4860:4860::8844/8.8.8.8,8.8.4.4,2001:4860:4860::8888,2001:4860:4860::8844/g' /etc/wireguard/warp.conf
# 输出替换结果
echo "Replacement done."
