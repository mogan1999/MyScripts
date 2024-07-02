#!/bin/bash

# 目标目录
CERT_DIR="/etc/XrayR/cert/certificates"

# 查找所有*.s-s-w.top.crt证书
for cert in "$CERT_DIR"/*.s-s-w.top.crt; do
  if [ -f "$cert" ]; then
    # 获取过期日期
    expire_date=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
    echo "证书: $cert"
    echo "过期日期: $expire_date"
    echo ""
  fi
done
