#!/bin/bash

# 定义脚本下载位置
SCRIPT_PATH="/usr/local/bin/check_and_reboot.sh"
SERVICE_PATH="/etc/systemd/system/check_and_reboot.service"

# 下载脚本
curl -o ${SCRIPT_PATH} https://raw.githubusercontent.com/mogan1999/MyScripts/master/check_and_reboot.sh

# 给脚本设置执行权限
chmod +x ${SCRIPT_PATH}

# 创建systemd服务文件
cat <<EOF >${SERVICE_PATH}
[Unit]
Description=Check network connection and reboot on failure
After=network.target wg-quick@warp.service

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH}
RemainAfterExit=yes
StandardOutput=journal

[Install]
WantedBy=multi-user.target
EOF

# 重新加载systemd，启用并启动服务
systemctl daemon-reload
systemctl enable check_and_reboot.service
systemctl start check_and_reboot.service

echo "服务check_and_reboot已经设置并启动。"
