"""
统一配置中心 — 全自动安全扫描引擎

所有配置项均可通过 .env 文件或环境变量覆盖，默认值保证本地开箱即用。

安全提醒：
    - 复制 .env.example → .env，填入真实密码后即可使用
    - .env 已被 .gitignore 排除，不会被提交到 Git
    - 系统环境变量的优先级高于 .env 文件
"""

import os
from dotenv import load_dotenv

# 优先加载项目根目录的 .env 文件（若不存在则静默跳过）
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


# ── 靶场应用 ──────────────────────────────────────────────────────────
TARGET_HOST = os.getenv("SCANNER_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.getenv("SCANNER_TARGET_PORT", "5000"))
TARGET_BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

# ── 数据库（供靶场应用 SQL 注入模块使用）────────────────────────────
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "changeme")
DB_NAME = os.getenv("DB_NAME", "vuln_db")
DB_CHARSET = os.getenv("DB_CHARSET", "utf8mb4")

# ── 报警服务器 ────────────────────────────────────────────────────────
ALERT_SERVER_HOST = os.getenv("ALERT_SERVER_HOST", "127.0.0.1")
ALERT_SERVER_PORT = int(os.getenv("ALERT_SERVER_PORT", "9999"))

# ── 扫描器默认参数 ────────────────────────────────────────────────────
SCANNER_TIMEOUT = int(os.getenv("SCANNER_TIMEOUT", "5"))

# SQL 注入
SQLI_MAX_DB_LENGTH = 50       # 数据库名最大长度
SQLI_MAX_TABLE_COUNT = 50     # 最大猜解表数量
SQLI_MAX_THREADS = 10         # 爆破表名时的并行线程数

# XSS 跨站脚本
XSS_BASE_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]

# 目录遍历 / 文件泄露
FILE_TRAVERSAL_PAYLOADS = [
    # 命中项目根目录的实际文件（源码泄露检测）
    "../run.py",
    "../config.py",
    "../requirements.txt",
    "../src/target_app.py",
    # Linux 系统文件
    "../../../../etc/passwd",
    # Windows 系统文件（从 user_files/ 穿越到 C:\Windows）
    "../../../../Windows/win.ini",
    "..\\..\\..\\..\\Windows\\win.ini",
]

# ── 报告与日志 ────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
SCAN_REPORT_FILE = os.path.join(REPORTS_DIR, "scan_report.json")
ALERTS_REPORT_FILE = os.path.join(REPORTS_DIR, "alerts_report.json")

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ── 用户文件目录（靶场文件下载端点使用）──────────────────────────────
USER_FILES_DIR = os.path.join(PROJECT_ROOT, "user_files")


def ensure_directories():
    """创建必要的输出目录（若不存在）"""
    for d in (REPORTS_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)
