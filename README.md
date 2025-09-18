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





