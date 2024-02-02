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

# 先使用sed命令替换BufferSize
sed -i 's/BufferSize: 256/BufferSize: 1024/g' /etc/XrayR/config.yml

# 使用awk命令替换ApiKey
awk '
    /ApiHost: "https:\/\/api\.xjbjc\.xyz"/ { print; getline; if(/ApiKey: "daded812312325cd4"/) sub(/daded847b123123b25cd4/, "a5204af69234234224193"); print; next }
    { print }
' /etc/XrayR/config.yml > /tmp/temp_config.yml && mv /tmp/temp_config.yml /etc/XrayR/config.yml

# 输出替换结果
echo "Replacement done."
