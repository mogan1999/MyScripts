#!/bin/bash

echo "检测VPS是否开启BBR..."

# 检查内核版本是否支持BBR
kernel_version=$(uname -r)
if [[ "$(uname -r | awk -F'.' '{print $1"."$2}')" < "4.9" ]]; then
    echo "当前内核版本为 $kernel_version，不支持BBR。请升级内核到 4.9 或更高版本。"
    exit 1
fi

# 检查是否启用了BBR
bbr_status=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
bbr_enabled=$(lsmod | grep bbr)

if [[ "$bbr_status" == "bbr" && -n "$bbr_enabled" ]]; then
    echo "BBR 已启用。"
else
    echo "BBR 未启用。"
fi

# 检测是否可以手动启用BBR
echo "运行以下命令以启用BBR（如果支持）："
echo "sudo sysctl -w net.ipv4.tcp_congestion_control=bbr"
echo "sudo sysctl -w net.core.default_qdisc=fq"
