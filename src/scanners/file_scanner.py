"""
目录遍历与敏感文件泄露扫描器
============================

向目标端点的文件下载接口发送路径穿越 Payload，分析响应内容识别
敏感文件特征（源码泄露、Linux /etc/passwd、Windows win.ini 等）。

独立运行：
    python -m src.scanners.file_scanner

库调用：
    from src.scanners.file_scanner import scan
    result = scan("http://127.0.0.1:5000/file/download")

注意：本工具仅用于授权的安全测试和教育目的。
"""

import logging
import requests
from typing import Dict, List

from config import SCANNER_TIMEOUT, FILE_TRAVERSAL_PAYLOADS

logger = logging.getLogger(__name__)

# ── 默认配置 ──────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "timeout": SCANNER_TIMEOUT,
    "payloads": FILE_TRAVERSAL_PAYLOADS,
    "sensitive_patterns": {
        "source_code": ["import flask", "app = Flask", "def ", "class "],
        "linux_system": ["root:", "daemon:", "bin/bash"],
        "windows_system": ["[extensions]", "[fonts]", "[mci extensions]"],
    },
}

# ── 风险闭环：修复建议知识库 ─────────────────────────────────────────
REMEDIATION_DB = {
    "title": "路径校验与文件名过滤（Path Validation）",
    "description": (
        "直接使用用户输入的文件名拼接路径，攻击者可通过 ../ 跳出根目录，"
        "读取服务器上任意文件。"
    ),
    "suggestion": (
        "1. 使用 os.path.basename() 仅提取文件名，剥离目录部分。\n"
        "2. 确保解析后的绝对路径仍在预设的 BASE_DIR 范围内。\n"
        "3. 建立允许访问的文件白名单机制。"
    ),
    "code_example": (
        "import os\n"
        "from werkzeug.utils import secure_filename\n\n"
        "filename = secure_filename(user_input)\n"
        "file_path = os.path.join(BASE_DIR, filename)\n\n"
        "# 二次校验：确保路径未逃逸\n"
        "if not os.path.abspath(file_path).startswith(os.path.abspath(BASE_DIR)):\n"
        "    raise ValueError('非法路径访问')"
    ),
}


# ── 公开接口 ──────────────────────────────────────────────────────────

def scan(target_url: str, **kwargs) -> Dict:
    """对目标 URL 执行目录遍历漏洞扫描

    Args:
        target_url: 目标 URL（如 http://127.0.0.1:5000/file/download）
        **kwargs: 覆盖默认配置项

    Returns:
        Dict: 包含 vulnerable、severity、details、vulnerabilities、remediation
    """
    config = DEFAULT_CONFIG.copy()
    config.update(kwargs)

    result: Dict = {
        "vulnerable": False,
        "severity": "NONE",
        "details": [],
        "vulnerabilities": [],
        "remediation": None,
    }

    try:
        result["details"].append(f"[*] 开始对 {target_url} 进行目录遍历扫描")

        found_vulns = []
        for payload in config["payloads"]:
            try:
                resp = requests.get(
                    target_url,
                    params={"file": payload},
                    timeout=config["timeout"],
                )
                if resp.status_code != 200:
                    continue

                content = resp.text
                patterns = config["sensitive_patterns"]

                if _contains_pattern(content, patterns["source_code"]):
                    found_vulns.append({
                        "type": "源码泄露",
                        "payload": payload,
                        "file_type": "Python 源代码",
                        "preview": content[:200],
                    })
                elif _contains_pattern(content, patterns["linux_system"]):
                    found_vulns.append({
                        "type": "敏感文件泄露",
                        "payload": payload,
                        "file_type": "Linux 系统文件",
                        "preview": content[:200],
                    })
                elif _contains_pattern(content, patterns["windows_system"]):
                    found_vulns.append({
                        "type": "敏感文件泄露",
                        "payload": payload,
                        "file_type": "Windows 系统文件",
                        "preview": content[:200],
                    })
            except requests.RequestException:
                continue

        result["vulnerabilities"] = found_vulns

        if found_vulns:
            result["vulnerable"] = True
            result["severity"] = "CRITICAL"
            result["details"].append(f"[+] 发现 {len(found_vulns)} 个目录遍历漏洞")
            result["remediation"] = REMEDIATION_DB
            for v in found_vulns:
                result["details"].append(f"    - {v['type']}: {v['payload']}")
        else:
            result["details"].append("[-] 未检测到目录遍历漏洞")

    except Exception as exc:
        logger.exception("目录遍历扫描出错")
        result["details"].append(f"[-] 扫描错误: {exc}")

    return result


# ── 内部实现 ──────────────────────────────────────────────────────────

def _contains_pattern(content: str, patterns: List[str]) -> bool:
    """检查响应内容是否包含任意敏感特征模式（大小写不敏感）"""
    content_lower = content.lower()
    return any(p.lower() in content_lower for p in patterns)


# ── 独立测试入口 ──────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    test_url = "http://127.0.0.1:5000/file/download"
    print(f"[*] 开始扫描 {test_url} ...")
    r = scan(test_url)
    print(f"  存在漏洞: {r['vulnerable']}")
    print(f"  严重等级: {r['severity']}")
    for d in r["details"]:
        print(f"  {d}")
