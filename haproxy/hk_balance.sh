#!/bin/bash

# 检查是否以root用户运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请以root用户运行此脚本"
    exit 1
fi

# 更新包列表并安装HAProxy
echo "更新包列表并安装HAProxy..."
apt-get update
apt-get install -y haproxy

# 下载配置文件
CONFIG_URL="https://raw.githubusercontent.com/mogan1999/MyScripts/master/haproxy/hk_haproxy.cfg"
CONFIG_PATH="/etc/haproxy/haproxy.cfg"

echo "下载配置文件到 ${CONFIG_PATH}..."
curl -o ${CONFIG_PATH} ${CONFIG_URL}

# 检查下载是否成功
if [ $? -ne 0 ]; then
    echo "配置文件下载失败，请检查URL是否正确"
    exit 1
fi

# 重启HAProxy服务
echo "重启HAProxy服务..."
systemctl restart haproxy

# 检查HAProxy服务状态
echo "检查HAProxy服务状态..."
systemctl status haproxy
systemctl enable haproxy
# 打印成功消息
echo "HAProxy已成功安装并配置开启启动。"

exit 0

