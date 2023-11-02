#!/bin/bash

# 检查/etc/XrayR目录是否存在
if [ ! -d "/etc/XrayR" ]; then
  echo "/etc/XrayR directory does not exist."
  exit 1
fi

# 检查/etc/XrayR/config.yml文件是否存在
if [ ! -f "/etc/XrayR/config.yml" ]; then
  echo "/etc/XrayR/config.yml file does not exist."
  exit 1
fi

# 使用sed命令替换字符串
sed -i 's/SpeedLimit: 50/SpeedLimit: 48/g' /etc/XrayR/config.yml

# 输出替换结果
echo "Replacement done."
