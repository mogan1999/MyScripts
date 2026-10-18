#!/bin/bash
set -euo pipefail

# 检查是否以root用户运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请以root用户运行此脚本"
    exit 1
fi

# 更新包列表并安装HAProxy
echo "更新包列表并安装HAProxy..."
apt-get update
apt-get install -y haproxy python3 curl

# 下载配置文件
SOURCE_URL="https://raw.githubusercontent.com/mogan1999/MyScripts/master/haproxy"
CONFIG_PATH="/etc/haproxy/haproxy.cfg"
upload_services=(
    haproxy-jpe-upload.service
    haproxy-upload@naive-jpe.service
    haproxy-upload@trojan-sg.service
    haproxy-upload@naive-sg.service
)
download_dir=$(mktemp -d)
trap 'rm -rf "$download_dir"' EXIT

echo "下载配置文件到 ${CONFIG_PATH}..."
curl -fLS --retry 3 -o "$download_dir/all.cfg" "$SOURCE_URL/all.cfg"
curl -fLS --retry 3 -o "$download_dir/jpe_upload_guard.py" "$SOURCE_URL/jpe_upload_guard.py"
curl -fLS --retry 3 -o "$download_dir/haproxy-jpe-upload.service" "$SOURCE_URL/haproxy-jpe-upload.service"
curl -fLS --retry 3 -o "$download_dir/haproxy-upload@.service" "$SOURCE_URL/haproxy-upload@.service"

# 全部下载并校验成功后才替换现有文件。
haproxy -c -f "$download_dir/all.cfg"
python3 -m py_compile "$download_dir/jpe_upload_guard.py"
install -m 644 "$download_dir/all.cfg" "$CONFIG_PATH"
install -m 755 "$download_dir/jpe_upload_guard.py" /usr/local/sbin/haproxy-jpe-upload.py
install -m 644 "$download_dir/haproxy-jpe-upload.service" /etc/systemd/system/haproxy-jpe-upload.service
install -m 644 "$download_dir/haproxy-upload@.service" /etc/systemd/system/haproxy-upload@.service
systemctl daemon-reload

# 重启HAProxy服务
echo "重启HAProxy服务..."
systemctl restart haproxy
for profile in trojan-jpe naive-jpe trojan-sg naive-sg; do
    python3 /usr/local/sbin/haproxy-jpe-upload.py --profile "$profile" --check
done
systemctl enable haproxy "${upload_services[@]}"
systemctl restart "${upload_services[@]}"

# 检查HAProxy服务状态
echo "检查HAProxy服务状态..."
systemctl --no-pager status haproxy "${upload_services[@]}"
# 打印成功消息
echo "HAProxy及日本、新加坡Naive/Trojan上传分流监控已成功安装并配置开启启动。"

exit 0
