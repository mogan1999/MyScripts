#!/bin/bash

# 目标目录
CERT_DIR="/etc/XrayR/cert/certificates"

# 下载新证书和私钥
KEY_URL="https://github.com/mogan1999/MyScripts/raw/master/crt/s-s-w.top.key"
CRT_URL="https://github.com/mogan1999/MyScripts/raw/master/crt/s-s-w.top.crt"
TEMP_KEY="/tmp/s-s-w.top.key"
TEMP_CRT="/tmp/s-s-w.top.crt"

wget -O "$TEMP_KEY" "$KEY_URL"
wget -O "$TEMP_CRT" "$CRT_URL"

# 检查下载是否成功
if [[ ! -f "$TEMP_KEY" || ! -f "$TEMP_CRT" ]]; then
  echo "下载证书或私钥失败。"
  exit 1
fi

# 替换证书和私钥文件内容
for file in "$CERT_DIR"/*.key; do
  if [ -f "$file" ]; then
    cp "$TEMP_KEY" "$file"
    echo "私钥文件已更新: $file"
  fi
done

for file in "$CERT_DIR"/*.crt; do
  if [[ -f "$file" && "$file" != *issuer.crt ]]; then
    cp "$TEMP_CRT" "$file"
    echo "证书文件已更新: $file"
  fi
done

# 清理临时文件
rm -f "$TEMP_KEY" "$TEMP_CRT"

echo "所有文件更新完成。"
