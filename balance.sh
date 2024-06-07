#!/bin/bash

# 安装HAProxy
sudo apt-get update
sudo apt-get install -y haproxy

# 备份原始配置文件
sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak

# 创建新的配置文件
sudo tee /etc/haproxy/haproxy.cfg > /dev/null <<EOL
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # Default SSL material locations
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

    # See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.13&config=modern&openssl-version=1.1.1d
    ssl-default-bind-ciphers PROFILE=SYSTEM
    ssl-default-bind-options no-sslv3

defaults
    log     global
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend fe_http
    bind *:40002
    mode tcp
    default_backend be_http

backend be_http
    mode tcp
    balance source  # 基于源IP的负载均衡
    server server1 sg.s-s-w.top:20080 check
    server server2 sg2.s-s-w.top:20080 check
EOL

# 重启HAProxy服务
sudo systemctl restart haproxy

echo "HAProxy安装和配置完成，并已重启服务。"
