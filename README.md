# 🔒 自动化安全工具脚本

一个基于 **Python** 开发的轻量级自动化安全检测工具，适合渗透测试与日常安全运维使用。  
本工具通过模块化设计，支持端口扫描、目录爆破和基础漏洞检测，帮助安全人员快速发现潜在风险。

---

## ✨ 功能特性
- ✅ **端口扫描**：基于多线程实现，支持指定端口范围
- ✅ **目录爆破**：支持自定义字典文件
- ✅ **基础漏洞检测**：如 SQL 注入 / XSS / 弱口令等常见问题
- ✅ **日志保存**：扫描结果可导出至本地文件

---

## 📦 安装与运行

### 克隆项目
```bash
git clone https://github.com/CCSCSCS1212/security-tools.git
cd security-tools
安装依赖
bash
复制代码
pip install -r requirements.txt
使用示例
bash
复制代码
# 对指定目标执行端口扫描
python security_tool.py -u http://example.com -m portscan

# 执行目录爆破
python security_tool.py -u http://example.com -m dirscan

# 执行基础漏洞检测
python security_tool.py -u http://example.com -m vulnscan
📂 项目结构
bash
复制代码
├── security_tool.py     # 主程序
├── requirements.txt     # 依赖文件
└── README.md            # 项目说明文档
🛠️ 技术栈
Python 3.x

requests / BeautifulSoup4

socket / threading

📜 许可证
本项目采用 MIT License，可自由使用与修改。

🙋 关于作者
GitHub: @CCSCSCS1212

方向：网络安全 / 自动化运维 / AI安全工具

yaml
复制代码

---

### report.md（复制整块并粘贴到 `report.md` 编辑区）
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
复制代码
{
  "failed password": 5,
  "invalid user": 2
}
示例行（最多10条）
Sep 18 10:05:12 server sshd[1201]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2

Sep 18 10:07:33 server sshd[1203]: Failed password for root from 192.168.1.60 port 50210 ssh2

代码审计发现
./config/settings.py 匹配 hardcode(password):

python
复制代码
DB_PASSWORD = "admin123"
./utils/exec_tool.py 匹配 exec(:

python
复制代码
exec(user_input)
密码策略评估
password	length	entropy	verdict
weak123	7	41.6	weak
Passw0rd!	9	59.5	medium
Qw!9eT$kLmNp	12	78.8	strong

✅ 总结：
本报告基于实验环境生成，展示了自动化安全工具的核心功能：端口检测、日志异常分析、代码静态审计以及密码强度评估。最终结果汇总为 Markdown 文档，适合作为 安全工程师作品集 用于简历和面试展示。

yaml
复制代码

---

## 推荐的 Commit message（可复制）
- `Add README`
- `Add sample report`
- `Initial commit: security_tools.py + README + report`

---

## 还想更省力？我可以直接把这两个文件生成给你下载
如果你愿意我可以把 `README.md` 和 `report.md` 生成成两个可下载的文件（你点下载后再走 “Upload files” → 拖拽到 GitHub）。要我生成下载文件吗？（回复“是”我就生成） 

或者你现在就把准备上传的页面打开，我在这里一步步引导你（告诉我你在哪里卡住）。
