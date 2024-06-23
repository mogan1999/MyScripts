#!/bin/bash

# 文件路径
SERVICE_FILE="/etc/systemd/system/nezha-agent.service"

# 检查文件是否存在
if [ -f "$SERVICE_FILE" ]; then
    # 使用sed命令修改RestartSec值
    sed -i 's/RestartSec=120/RestartSec=3/' "$SERVICE_FILE"
    echo "Updated RestartSec in $SERVICE_FILE"
else
    echo "$SERVICE_FILE does not exist."
fi

# 重新加载systemd守护进程以应用更改
systemctl daemon-reload

# 可选：重新启动nezha-agent服务
systemctl restart nezha-agent

echo "Done."
