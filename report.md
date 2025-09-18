### report.md
自动化安全工具 - 报告
生成时间: 2025-09-18T12:00:00Z

元数据
json
复制代码
{
  "owner": "demo_user",
  "environment": "lab_env",
  "purpose": "demo展示"
}
端口检测结果
127.0.0.1:22 — open

127.0.0.1:80 — closed_or_filtered

日志分析结果
匹配统计
json

{
  "failed password": 5,
  "invalid user": 2
}
示例行
Sep 18 10:05:12 server sshd[1201]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2

Sep 18 10:07:33 server sshd[1203]: Failed password for root from 192.168.1.60 port 50210 ssh2

代码审计发现
./config/settings.py 匹配 hardcode(password):

python

DB_PASSWORD = "admin123"
./utils/exec_tool.py 匹配 exec(:

python

exec(user_input)
密码策略评估
password	length	entropy	verdict
weak123	7	41.6	weak
Passw0rd!	9	59.5	medium
Qw!9eT$kLmNp	12	78.8	strong