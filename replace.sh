#!/bin/bash

# 检查目录是否存在
if [ ! -d "/etc/XrayR" ]; then
  echo "directory does not exist."
  exit 1
fi

# 检查目录下文件是否存在
if [ ! -f "/etc/XrayR/config.yml" ]; then
  echo "file does not exist."
  exit 1
fi

# 使用sed命令替换字符串
sed -i 's/SpeedLimit: 100/SpeedLimit: 0/g' /etc/XrayR/config.yml 

# 输出替换结果
echo "Replacement done."
