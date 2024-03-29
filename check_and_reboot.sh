#!/bin/bash

echo "开始检测网络连接..."

# 尝试执行curl命令检测网络连接，设置超时时间为5秒
# 直接检测网络连接，不再检查WireGuard服务或接口
if curl -m 5 ip.gs; then
    echo "网络连接成功，脚本退出。"
else
    echo "网络连接失败，准备重启系统..."
    sudo reboot now
fi
