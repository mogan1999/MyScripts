import sqlite3
from datetime import datetime, timedelta

# 连接到 SQLite 数据库
conn = sqlite3.connect('/etc/x-ui/x-ui.db')
cursor = conn.cursor()

# 获取今天的日期
today = datetime.now().date()

# 查询所有用户的流量和过期时间
cursor.execute("SELECT email, expiry_time, up, down FROM client_traffics WHERE enable = 1")
users = cursor.fetchall()

for user in users:
    email, expiry_time, up, down = user
    # 将 expiry_time 从毫秒转换为日期
    expiry_date = datetime.fromtimestamp(expiry_time / 1000.0).date()
    
    # 计算每个月的重置日
    reset_day = expiry_date.day
    
    # 检查今天是否是流量重置日
    if today.day == reset_day:
        # 重置 up 和 down 到 0
        cursor.execute("UPDATE client_traffics SET up = 0, down = 0 WHERE email = ?", (email,))
        print(f"已重置 {email} 的流量")

# 提交更改并关闭数据库连接
conn.commit()
conn.close()

print("流量重置脚本执行完成。")
