#!/usr/bin/env python3
"""
全自动安全扫描引擎 — 统一入口

用法：
    python run.py target       启动漏洞靶场应用
    python run.py server       启动 TCP 报警服务器
    python run.py scan         执行完整的安全扫描
    python run.py dashboard    启动 Streamlit 可视化大屏

快速开始（打开三个终端）：
    1.  python run.py target          （Flask 应用，端口 :5000）
    2.  python run.py server          （报警服务器，端口 :9999）
    3.  python run.py scan            （执行全部扫描，导出报告）

随后：
    python run.py dashboard           （Streamlit 大屏，端口 :8501）
"""

import logging
import os
import sys


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def setup_logging():
    """配置根日志记录器，使所有模块共享统一的日志格式"""
    from config import LOG_DIR, LOG_LEVEL

    os.makedirs(LOG_DIR, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


def _run_target():
    """启动漏洞靶场 Flask 应用"""
    from config import TARGET_HOST, TARGET_PORT, USER_FILES_DIR

    # 首次运行时创建测试文件
    os.makedirs(USER_FILES_DIR, exist_ok=True)
    test_file = os.path.join(USER_FILES_DIR, "test.txt")
    if not os.path.exists(test_file):
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("这是一个用于目录遍历扫描的测试文件。\n")
        print(f"[+] 已创建 {test_file}")

    secret_file = os.path.join(USER_FILES_DIR, "secret.txt")
    if not os.path.exists(secret_file):
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("SECRET_KEY=super_secret_password_12345\n")
            f.write("DATABASE_PASSWORD=admin@123\n")
        print(f"[+] 已创建 {secret_file}")

    from src.target_app import app
    app.run(host=TARGET_HOST, port=TARGET_PORT, debug=True)


def _run_server():
    """启动 TCP 报警服务器"""
    from src.server import AlertServer
    server = AlertServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] 用户中断。")
    finally:
        server.stop()


def _run_scan():
    """执行完整的安全扫描"""
    from config import TARGET_BASE_URL
    from src.engine import ScannerEngine

    engine = ScannerEngine(TARGET_BASE_URL)
    try:
        engine.run_scan()
        engine.export_results()
    except KeyboardInterrupt:
        print("\n[!] 扫描中断。")
    except Exception:
        logging.getLogger(__name__).exception("扫描失败")


def _run_dashboard():
    """通过 Streamlit CLI 启动可视化大屏"""
    import streamlit.web.cli as stcli

    dashboard_path = os.path.join(PROJECT_ROOT, "src", "dashboard.py")
    sys.argv = ["streamlit", "run", dashboard_path, "--server.port=8501"]
    stcli.main()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()
    commands = {
        "target": _run_target,
        "server": _run_server,
        "scan": _run_scan,
        "dashboard": _run_dashboard,
    }

    if cmd not in commands:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)

    setup_logging()
    commands[cmd]()


if __name__ == "__main__":
    main()
