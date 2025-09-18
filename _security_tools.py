#!/usr/bin/env python3
"""
security_tools.py

自动化安全工具脚本”——侧重于合规与防御性的自动化任务。
包含：
  - port_check: 对用户指定的主机和端口做可达性检测（需明确授权）
  - log_analyze: 解析常见认证/访问日志，统计失败登录等指标
  - code_audit: 在代码目录中查找高风险模式（如硬编码凭据、eval 等）
  - pwd_policy: 对给定密码或密码列表做安全性评估（策略审计）
  - generate_report: 将上述结果汇总成 Markdown 报告

重要：请务必仅在你有授权的范围内运行这些工具（例如：自己的主机、客户明确授权、教学实验环境）。

License: MIT
"""

import argparse
import socket
import sys
import os
import re
import datetime
import json
import math
from collections import Counter

# --------------------------- 配置 ---------------------------
DEFAULT_TIMEOUT = 1.5  # seconds
HIGH_RISK_PATTERNS = [
    r"hardcode(pass(word)?|pwd|token|secret|key)",
    r"=\s*['\"]?[A-Za-z0-9@#$%\-_.]{6,}['\"]?",  # simple heuristic for assignments
    r"eval\s*\(",
    r"exec\s*\(",
    r"subprocess\.Popen",
]

# --------------------------- 工具函数 ---------------------------

def require_authorization_action():
    """在关键操作前强制用户确认已获得授权。"""
    print("注意：请确保你已获得目标系统的明确书面授权。未经授权的测试可能违法。")
    ans = input("我确认我已获得授权并仅在合法范围内运行此脚本 (yes/no): ")
    if ans.strip().lower() != "yes":
        print("未授权，脚本退出。")
        sys.exit(1)


def now_ts():
    return datetime.datetime.utcnow().isoformat() + "Z"


# --------------------------- 子命令：端口可达性检测 ---------------------------

def port_check(hosts, ports, timeout=DEFAULT_TIMEOUT):
    """
    对给定 hosts 列表和 ports 列表进行逐一连接测试。
    仅对明确提供的主机做测试，不做网络段扫扫描。
    """
    results = []
    for h in hosts:
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((h, p))
                s.close()
                status = "open"
            except Exception as e:
                status = "closed_or_filtered"
            results.append({"host": h, "port": p, "status": status})
    return results


# --------------------------- 子命令：日志分析 ---------------------------

def parse_log_for_auth_failures(logfile_path, patterns=None):
    """解析日志文件（如 /var/log/auth.log, nginx access.log 等），统计失败事件。"""
    if patterns is None:
        patterns = [
            r"failed password", r"authentication failure", r"invalid user", r"401",
        ]
    counts = Counter()
    examples = []
    with open(logfile_path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            for p in patterns:
                if re.search(p, line, re.IGNORECASE):
                    counts[p] += 1
                    if len(examples) < 10:
                        examples.append(line.strip())
    return {"counts": dict(counts), "examples": examples}


# --------------------------- 子命令：代码审计（静态模式） ---------------------------

def code_audit(directory, patterns=None):
    """在代码目录中根据正则模式查找可能的高风险代码片段。"""
    if patterns is None:
        patterns = HIGH_RISK_PATTERNS
    findings = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            if fname.endswith((".py", ".js", ".php", ".java", ".rb", ".go", ".sh", ".cfg", ".env")):
                path = os.path.join(root, fname)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                for p in patterns:
                    for m in re.finditer(p, content, re.IGNORECASE):
                        snippet_start = max(m.start() - 40, 0)
                        snippet_end = min(m.end() + 40, len(content))
                        findings.append({
                            "file": path,
                            "pattern": p,
                            "match": content[m.start():m.end()],
                            "context": content[snippet_start:snippet_end].replace("\n", " ")[:400],
                        })
    return findings


# --------------------------- 子命令：密码策略评估 ---------------------------

def entropy_estimate(pw: str) -> float:
    # 近似熵估算：基于字符集大小和长度
    charset = 0
    if re.search(r"[a-z]", pw):
        charset += 26
    if re.search(r"[A-Z]", pw):
        charset += 26
    if re.search(r"[0-9]", pw):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        charset += 32
    if charset == 0:
        charset = 1
    # 熵(bits) = length * log2(charset)
    return len(pw) * math.log2(charset)


def pwd_policy_check(passwords):
    results = []
    for pw in passwords:
        e = entropy_estimate(pw)
        verdict = "weak"
        if e >= 60 and len(pw) >= 12:
            verdict = "strong"
        elif e >= 45 and len(pw) >= 10:
            verdict = "medium"
        results.append({"password": pw, "entropy": round(e, 2), "verdict": verdict, "length": len(pw)})
    return results


# --------------------------- 子命令：生成报告 ---------------------------

def generate_markdown_report(outpath, metadata, port_results=None, log_results=None, audit_results=None, pwd_results=None):
    lines = []
    lines.append(f"# 自动化安全工具 - 报告\n\n")
    lines.append(f"**生成时间**: {now_ts()}\n\n")
    lines.append("## 元数据\n")
    lines.append("```json\n" + json.dumps(metadata, indent=2, ensure_ascii=False) + "\n```\n")

    if port_results is not None:
        lines.append("## 端口检测结果\n")
        for r in port_results:
            lines.append(f"- {r['host']}:{r['port']} — {r['status']}\n")

    if log_results is not None:
        lines.append("## 日志分析结果\n")
        lines.append("### 匹配统计\n")
        lines.append("```json\n" + json.dumps(log_results.get('counts', {}), indent=2, ensure_ascii=False) + "\n```\n")
        lines.append("### 示例行（最多10条）\n")
        for ex in log_results.get('examples', []):
            lines.append(f"- `{ex}`\n")

    if audit_results is not None:
        lines.append("## 代码审计发现\n")
        for f in audit_results[:200]:
            lines.append(f"- `{f['file']}` 匹配 `{f['pattern']}`: {f['context']}\n")

    if pwd_results is not None:
        lines.append("## 密码策略评估\n")
        lines.append("|password|length|entropy|verdict|\n|---|---:|---:|---|\n")
        for p in pwd_results:
            lines.append(f"|`{p['password']}`|{p['length']}|{p['entropy']}|{p['verdict']}|\n")

    with open(outpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return outpath


# --------------------------- CLI ---------------------------

def main():
    parser = argparse.ArgumentParser(description="自动化安全工具脚本（合规/防御方向）")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("port_check", help="对指定主机和端口做可达性检测（需授权）")
    p_scan.add_argument("--hosts", nargs="+", required=True, help="要检测的主机，例如 192.168.1.10")
    p_scan.add_argument("--ports", nargs="+", required=True, type=int, help="要检测的端口，例如 22 80 443")
    p_scan.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)

    p_log = sub.add_parser("log_analyze", help="解析并统计日志文件中的认证/失败事件")
    p_log.add_argument("--logfile", required=True)

    p_audit = sub.add_parser("code_audit", help="在代码目录里查找高风险模式")
    p_audit.add_argument("--dir", required=True)

    p_pwd = sub.add_parser("pwd_policy", help="对密码或密码列表做强度评估")
    p_pwd.add_argument("--passwords", nargs="+", required=True, help="要评估的密码（只用于审计示例）")

    p_report = sub.add_parser("generate_report", help="根据此前步骤结果生成 Markdown 报告示例（从 stdin 读取 JSON payload）")
    p_report.add_argument("--out", required=True, help="输出 Markdown 路径，例如 report.md")

    args = parser.parse_args()

    if args.cmd == "port_check":
        require_authorization_action()
        res = port_check(args.hosts, args.ports, timeout=args.timeout)
        print(json.dumps(res, indent=2, ensure_ascii=False))

    elif args.cmd == "log_analyze":
        res = parse_log_for_auth_failures(args.logfile)
        print(json.dumps(res, indent=2, ensure_ascii=False))

    elif args.cmd == "code_audit":
        res = code_audit(args.dir)
        print(json.dumps(res, indent=2, ensure_ascii=False))

    elif args.cmd == "pwd_policy":
        res = pwd_policy_check(args.passwords)
        print(json.dumps(res, indent=2, ensure_ascii=False))

    elif args.cmd == "generate_report":
        # 预期从 stdin 读取一个 JSON payload：{"metadata":..., "port_results":..., ...}
        payload = json.load(sys.stdin)
        out = generate_markdown_report(args.out, payload.get("metadata", {}),
                                       payload.get("port_results"), payload.get("log_results"),
                                       payload.get("audit_results"), payload.get("pwd_results"))
        print(f"报告已生成: {out}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
