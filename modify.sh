#!/bin/bash

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
   echo "该脚本必须以root身份运行" 1>&2
   exit 1
fi

# 定义文件路径
SERVICE_FILE="/etc/systemd/system/nezha-agent.service"

# 检查文件是否存在
if [ ! -f "$SERVICE_FILE" ]; then
    echo "服务文件不存在: $SERVICE_FILE"
    exit 1
fi

# 使用sed命令替换字符串
sed -i 's/monitor.1.fun/status.2.fun/g' $SERVICE_FILE

# 执行daemon-reload
systemctl daemon-reload

# 重启nezha-agent服务
systemctl restart nezha-agent.service

echo "替换完成，并重启了nezha-agent服务。"
