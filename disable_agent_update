#!/bin/bash

# 定义要修改的文件路径
SERVICE_FILE="/etc/systemd/system/nezha-agent.service"

# 定义要查找的行的前缀
EXEC_START_PREFIX="ExecStart="

# 备份原始文件
cp "$SERVICE_FILE" "$SERVICE_FILE.bak"

# 使用 sed 工具在 ExecStart 行的末尾添加参数 --disable-auto-update
sed -i "/^${EXEC_START_PREFIX}/ s|$| --disable-auto-update|" "$SERVICE_FILE"

# 重新加载 systemd 配置
systemctl daemon-reload

# 提示用户操作完成
echo "修改完成，并重新加载 systemd 配置。"
