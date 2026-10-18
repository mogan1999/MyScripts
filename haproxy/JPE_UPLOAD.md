# 日本、新加坡 Naive / Trojan 上传分流

四个入口分别计量：同一入口、同一公网 IP 的所有连接合计，滚动 30 分钟上传达到 **5GB = 5,000,000,000 字节**时，转到对应的专用后端，保留 24 小时后自动恢复原来的 5 个后端。不同入口的上传量和分流状态相互独立。

| 监控 profile | SNI | 原后端 | 专用目标 |
| --- | --- | --- | --- |
| `trojan-jpe` | `jp-east-stream.ssw-servers.com` | `bk_trojan_jpe` | `jp-east.ssw-servers.com:38082` |
| `naive-jpe` | `jp-east.sswnat.com` | `bk_naive_jp_east` | `jp-east.ssw-servers.com:443` |
| `trojan-sg` | `sg.ssw-servers.com` | `bk_trojan_sg` | `ld-sg1.ssw-servers.com:38081` |
| `naive-sg` | `sg.sswnat.com` | `bk_naive_sg` | `ld-sg1.ssw-servers.com:443` |

`bytes_in_cnt` 统计客户端 → HAProxy → 后端的字节，包含 TLS / VPN 封装开销；服务器 → 客户端的下载字节不计入。下载时客户端发送的少量协议数据仍算上传。共享公网 IP 的用户合并统计，IPv4 和 IPv6 均支持。

HAProxy 的 TCP / TLS 透传连接不能中途迁移。四个监控实例复用 `jpe_upload_guard.py`，每 10 秒采样一次，分别用 SQLite 保存最近 30 分钟的上传增量和分流到期时间。触发后先写入并确认分流标记，再通过 Runtime API 逐个断开该 IP 在 `reality_in` / 对应原后端的旧连接，客户端重连时进入专用后端。该 IP 使用其他 SNI 的连接和已经进入专用后端的连接不会因此断开。

默认兜底使用独立的 `bk_naive_sg_fallback` 后端，仍指向原来的五个新加坡节点；兜底连接的上传不计入 `sg.sswnat.com`，也不会在这个入口触发分流时被断开。

统计按采样区间记账，滚动窗口边界有约一个采样间隔的误差。`option contstats` 使长连接持续更新计数，通常约每 5 秒刷新；叠加 10 秒采样间隔，触发分流可能有约 10–15 秒延迟。`stick-table expire 2h` 是表项的空闲期限，不是滚动统计窗口。分流表不做连接跟踪，读取标记不会续期；脚本同时维护固定的 24 小时到期时间。

分流期间的上传不累加下一轮配额。到期后恢复正常分流并重新计量；已经连到专用节点的连接可以继续使用，新建连接回到原来的后端。客户端是否立即重连取决于 VPN 客户端的行为，正在进行的传输可能中断。

## 部署

专用节点必须能接受**原来的 SNI、TLS 证书校验和 VPN 账号**。HAProxy 只改变连接目标，不会改写 TLS 握手中的 SNI。先用现有客户端确认专用节点可以正常连接。

`all.cfg` 需要搭配 `jpe_upload_guard.py`、`haproxy-jpe-upload.service` 和 `haproxy-upload@.service` 部署。日本 Trojan 继续使用原来的 `haproxy-jpe-upload.service` 和 `state.sqlite3`；三个新入口使用模板服务的三个实例及各自的数据库。更新后的 `all.sh` 会一起下载、校验、安装文件并启动四个监控服务；使用该安装脚本前，这些改动需要已经发布到它引用的 GitHub 分支。也可以在仓库目录中手动安装：

```bash
sudo apt-get install -y haproxy python3
sudo haproxy -c -f haproxy/all.cfg
sudo install -m 644 haproxy/all.cfg /etc/haproxy/haproxy.cfg
sudo install -m 755 haproxy/jpe_upload_guard.py /usr/local/sbin/haproxy-jpe-upload.py
sudo install -m 644 haproxy/haproxy-jpe-upload.service /etc/systemd/system/haproxy-jpe-upload.service
sudo install -m 644 haproxy/haproxy-upload@.service /etc/systemd/system/haproxy-upload@.service
sudo systemctl daemon-reload
sudo systemctl restart haproxy
for profile in trojan-jpe naive-jpe trojan-sg naive-sg; do
    sudo python3 /usr/local/sbin/haproxy-jpe-upload.py --profile "$profile" --check
done
sudo systemctl enable haproxy haproxy-jpe-upload.service \
    haproxy-upload@naive-jpe.service haproxy-upload@trojan-sg.service haproxy-upload@naive-sg.service
sudo systemctl restart haproxy-jpe-upload.service \
    haproxy-upload@naive-jpe.service haproxy-upload@trojan-sg.service haproxy-upload@naive-sg.service
```

本方案使用 HAProxy 的 `track-sc0`、`option contstats`、IPv6 stick-table 和 Runtime API；部署机器上请先执行 `haproxy -v` 和上述配置校验。每条连接只有一个 SNI，四条互斥的跟踪规则可以复用 `track-sc0`。监控通过现有的 `/run/haproxy/admin.sock` 工作，不需要开放新的网络端口。服务以 root 运行，以访问当前配置的管理 socket；四个数据库保存在 `/var/lib/haproxy-jpe-upload/` 中。

```bash
# 查看触发、断线、自动恢复及采样错误
sudo journalctl -u haproxy-jpe-upload.service -f
sudo journalctl -u haproxy-upload@naive-jpe.service -f
sudo journalctl -u haproxy-upload@trojan-sg.service -f
sudo journalctl -u haproxy-upload@naive-sg.service -f

# 查看日本 Trojan 的分流剩余秒数（默认 profile 保持不变）
sudo python3 /usr/local/sbin/haproxy-jpe-upload.py --status

# 指定入口查看或提前解除，下一次采样时应用
sudo python3 /usr/local/sbin/haproxy-jpe-upload.py --profile naive-jpe --status
sudo python3 /usr/local/sbin/haproxy-jpe-upload.py --profile trojan-sg --status
sudo python3 /usr/local/sbin/haproxy-jpe-upload.py --profile naive-sg --release 203.0.113.10
```

阈值、窗口、保留时间和采样间隔由 service 的 `ExecStart` 参数指定，当前为 `--window 1800 --threshold 5000000000 --hold 86400 --interval 10`。修改原服务或模板服务后，执行 `systemctl daemon-reload` 并重启对应实例。如果需要 5GiB，把 `--threshold` 改为 `5368709120`。程序保留 `--counter-table`、`--mark-table`、`--backend` 和 `--state-db` 参数，支持覆盖 profile 的默认值。

监控重启后会继续使用已保存的历史和原有到期时间；HAProxy 重启后会重新建立缺失的分流标记。第一次启动监控时从当前字节计数建立基线，无法追溯之前 30 分钟的上传。停采超过 3 个采样间隔后重新建立基线，避免把停采期间的历史上传全部误算进最近 30 分钟。

HAProxy 重启 / 重载时最后一次采样之后的旧进程上传可能漏计；平滑重载后仍留在旧 worker 的连接不在新 worker 的管理 socket 中，须等旧连接重连后才能继续统计和断开。此配置没有新增 peers / master CLI 的跨进程同步。多台 HAProxy 的上传量也各自独立统计。

## 验证

```bash
python3 -m unittest discover -s haproxy/tests -v
HAPROXY_TEST_BINARY=/path/to/haproxy python3 -m unittest discover -s haproxy/tests -v
```

第一条运行滚动窗口、上传方向、持久化、计数重置和断线范围测试。第二条还运行四个入口的本机 TLS 透传测试：下载不会触发、同一 IP 在各入口独立触发、重连进入对应专用节点、其他入口和默认兜底连接继续工作，以及到期恢复。测试后端只绑定本机回环地址。
