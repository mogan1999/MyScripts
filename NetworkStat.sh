#!/bin/bash

# 获取主网络接口的名称
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

# 使用vnstat获取本月流量数据
# -i 指定网络接口
# --oneline 输出单行格式
# -m 获取月度报告
OUTPUT=$(vnstat -i $INTERFACE -m --oneline | awk -F ";" '{print $10, $11}')

# 提取入站和出站流量数值和单位
RX_VALUE=$(echo $OUTPUT | awk '{print $1}')
RX_UNIT=$(echo $OUTPUT | awk '{print $2}')
TX_VALUE=$(echo $OUTPUT | awk '{print $3}')
TX_UNIT=$(echo $OUTPUT | awk '{print $4}')

# 定义一个函数来转换流量值为GB
convert_to_gb() {
    local VALUE=$1
    local UNIT=$2
    local GB_VALUE

    case $UNIT in
        "MiB")
            GB_VALUE=$(echo "scale=3; $VALUE / 1024" | bc)
            ;;
        "GiB")
            GB_VALUE=$(echo "scale=3; $VALUE" | bc)
            ;;
        "KiB")
            GB_VALUE=$(echo "scale=3; $VALUE / 1048576" | bc) # 1 GB = 1048576 KiB
            ;;
        *)
            GB_VALUE="未知单位"
            ;;
    esac

    echo $GB_VALUE
}

# 转换入站和出站流量为GB
RX_GB=$(convert_to_gb $RX_VALUE $RX_UNIT)
TX_GB=$(convert_to_gb $TX_VALUE $TX_UNIT)

echo "本月入站流量：$RX_GB GB"
echo "本月出站流量：$TX_GB GB"
