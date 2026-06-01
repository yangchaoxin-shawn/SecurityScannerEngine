"""
XSS 跨站脚本攻击扫描器
======================

自动检测反射型 XSS 漏洞：向目标 URL 的查询参数注入常见 Payload
（含确定性大小写变体），若 Payload 原样出现在响应中则判定存在漏洞。

独立运行：
    python -m src.scanners.xss_scanner

库调用：
    from src.scanners.xss_scanner import scan
    result = scan("http://127.0.0.1:5000/xss/search", params="name")

注意：本工具仅用于授权的安全测试和教育目的。
"""

import logging
import requests
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Union

from config import SCANNER_TIMEOUT, XSS_BASE_PAYLOADS

logger = logging.getLogger(__name__)

# ── 默认配置 ──────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "timeout": SCANNER_TIMEOUT,
    "base_payloads": XSS_BASE_PAYLOADS,
}

# ── 风险闭环：修复建议知识库 ─────────────────────────────────────────
REMEDIATION_DB = {
    "title": "输出编码与内容安全策略（Output Encoding & CSP）",
    "description": (
        "用户输入在渲染到 HTML 页面之前必须进行严格的 HTML 实体转义，"
        "否则攻击者可注入恶意脚本。"
    ),
    "suggestion": (
        "1. 在 Flask/Jinja2 中避免使用 |safe 过滤器。\n"
        "2. 使用 html.escape() 对原生字符串进行转义。\n"
        "3. 配置 Content-Security-Policy 响应头限制脚本来源。"
    ),
    "code_example": (
        "# ❌ 危险写法（Jinja2）\n"
        "{{ user_input|safe }}\n\n"
        "# ✅ 安全写法（Jinja2 默认行为，自动转义）\n"
        "{{ user_input }}"
    ),
}


# ── 确定性大小写变体生成器 ────────────────────────────────────────────

def _case_variations(payload: str) -> List[str]:
    """为 Payload 生成确定性的小规模大小写混淆变体

    与旧版使用 random.choice 不同，此版本保证每次运行产生相同结果，
    使扫描结果可复现。
    """
    variations = {payload}
    lower = payload.lower()

    if "<script>" in lower:
        variations.update([
            "<ScRiPt>alert('xss')</ScRiPt>",
            "<SCRIPT>alert('xss')</SCRIPT>",
        ])
    elif "<img" in lower:
        variations.update([
            "<IMG src=x onerror=alert(1)>",
            "<iMg src=x onerror=alert(1)>",
        ])
    elif "<svg" in lower:
        variations.update([
            "<SVG/onload=alert(1)>",
            "<sVg/onload=alert(1)>",
        ])
    elif "javascript:" in lower:
        variations.update([
            "JAVASCRIPT:alert(1)",
            "JavaScript:alert(1)",
        ])

    return list(variations)


# ── 公开接口 ──────────────────────────────────────────────────────────

def scan(target_url: str,
         params: Optional[Union[str, List[str]]] = None,
         **kwargs) -> Dict:
    """对目标 URL 执行 XSS 漏洞扫描

    Args:
        target_url: 目标 URL
        params: 要测试的参数（字符串或列表），为 None 时自动从 URL 提取
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
        params_to_test = _resolve_params(target_url, params)
        if not params_to_test:
            result["details"].append("[!] URL 中未找到参数且未指定参数")
            return result

        result["details"].append(f"[*] 待测试参数: {params_to_test}")

        all_vulns = []
        for p in params_to_test:
            all_vulns.extend(_scan_single_param(target_url, p, config))

        result["vulnerabilities"] = all_vulns

        if all_vulns:
            result["vulnerable"] = True
            result["severity"] = "HIGH"
            result["details"].append(f"[!] 发现 {len(all_vulns)} 处 XSS 漏洞")
            result["remediation"] = REMEDIATION_DB
            for v in all_vulns:
                result["details"].append(
                    f"    - 参数: {v['param']}, Payload: {v['payload']}"
                )
        else:
            result["details"].append("[-] 未发现 XSS 漏洞")

    except Exception as exc:
        logger.exception("XSS 扫描出错")
        result["details"].append(f"[-] 扫描错误: {exc}")

    return result


# ── 内部实现 ──────────────────────────────────────────────────────────

def _resolve_params(target_url: str,
                    params: Optional[Union[str, List[str]]]) -> List[str]:
    """解析要测试的参数列表"""
    if params is None:
        parsed = urlparse(target_url)
        return list(parse_qs(parsed.query).keys())
    if isinstance(params, str):
        return [params]
    if isinstance(params, list):
        return params
    return []


def _scan_single_param(target_url: str, param_name: str,
                       config: Dict) -> List[Dict]:
    """针对单个参数执行 XSS 扫描"""
    # 构建 Payload 列表（含确定性大小写变体）
    all_payloads = []
    for p in config["base_payloads"]:
        all_payloads.extend(_case_variations(p))
    all_payloads = list(dict.fromkeys(all_payloads))  # 去重，保持顺序

    found = []
    for payload in all_payloads:
        try:
            resp = requests.get(
                target_url,
                params={param_name: payload},
                timeout=config["timeout"],
            )
            # 判断 Payload 是否原样出现在响应中
            if payload in resp.text:
                found.append({
                    "param": param_name,
                    "payload": payload,
                    "url": target_url,
                })
        except Exception:
            continue
    return found


# ── 独立测试入口 ──────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    test_url = "http://127.0.0.1:5000/xss/search"
    print(f"[*] 开始扫描 {test_url} ...")
    r = scan(test_url, params="name")
    print(f"  存在漏洞: {r['vulnerable']}")
    print(f"  严重等级: {r['severity']}")
    for d in r["details"]:
        print(f"  {d}")
