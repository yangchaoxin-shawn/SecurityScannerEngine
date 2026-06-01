"""
总控调度引擎 — 协调三大专家扫描器并行执行，收集结果、发送报警、生成综合报告。

使用示例：
    from src.engine import ScannerEngine
    engine = ScannerEngine("http://127.0.0.1:5000")
    engine.run_scan()
    engine.export_results()
"""

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime
from typing import Dict

from config import (
    ALERT_SERVER_HOST,
    ALERT_SERVER_PORT,
    SCAN_REPORT_FILE,
)
from src.scanners import sqli_scanner, xss_scanner, file_scanner

logger = logging.getLogger(__name__)


# ── 扫描引擎 ──────────────────────────────────────────────────────────

class ScannerEngine:
    """调度三大专家扫描器在多线程中并行工作"""

    def __init__(self, target_base_url: str, enable_alert_server: bool = True):
        self.target_base_url = target_base_url.rstrip("/")
        self.enable_alert_server = enable_alert_server
        self.results: Dict = {}
        self._results_lock = threading.Lock()   # 线程安全锁
        self.start_time: float = 0.0
        self.end_time: float = 0.0

        # 三个扫描任务定义
        self.scan_tasks = {
            "SQL Injection": {
                "module": sqli_scanner,
                "endpoint": "/sqli/index.php",
                "params": {},
                "description": "SQL 注入布尔盲注检测与数据爆破",
            },
            "XSS": {
                "module": xss_scanner,
                "endpoint": "/xss/search",
                "params": {"params": "name"},
                "description": "反射型跨站脚本攻击检测",
            },
            "Directory Traversal": {
                "module": file_scanner,
                "endpoint": "/file/download",
                "params": {},
                "description": "目录遍历与敏感文件泄露检测",
            },
        }

    # ── 工作线程 ──────────────────────────────────────────────────────

    def _scan_worker(self, task_name: str, task_config: Dict):
        """单个扫描任务的工作线程函数

        Args:
            task_name: 任务名称（如 "SQL Injection"）
            task_config: 任务配置字典，包含 module/endpoint/params
        """
        module = task_config["module"]
        endpoint = task_config["endpoint"]
        params = task_config.get("params", {})
        target_url = f"{self.target_base_url}{endpoint}"

        logger.info("%s 扫描开始 → %s", task_name, target_url)
        task_start = time.time()

        try:
            result = module.scan(target_url, **params)
            duration = time.time() - task_start

            with self._results_lock:
                self.results[task_name] = {
                    "result": result,
                    "duration": duration,
                    "status": "completed",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }

            logger.info(
                "%s 完成 %.2fs | 漏洞: %s | 等级: %s",
                task_name, duration, result["vulnerable"], result["severity"],
            )
        except Exception as exc:
            duration = time.time() - task_start
            with self._results_lock:
                self.results[task_name] = {
                    "result": None,
                    "duration": duration,
                    "status": "failed",
                    "error": str(exc),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            logger.exception("%s 任务失败", task_name)

    # ── 调度编排 ──────────────────────────────────────────────────────

    def run_scan(self) -> Dict:
        """并行执行所有扫描任务并返回聚合结果"""
        logger.info("=" * 60)
        logger.info("  全自动安全扫描引擎 v1.0")
        logger.info("  目标: %s", self.target_base_url)
        logger.info("  模块: %s", "、".join(self.scan_tasks))
        logger.info("=" * 60)

        self.start_time = time.time()
        self.results = {}

        threads = []
        for task_name, task_config in self.scan_tasks.items():
            t = threading.Thread(
                target=self._scan_worker,
                args=(task_name, task_config),
                name=f"Thread-{task_name}",
                daemon=True,
            )
            threads.append(t)
            t.start()
            time.sleep(0.3)  # 错开启动，避免瞬时大量请求

        for t in threads:
            t.join()

        self.end_time = time.time()

        # 推送报警到服务器
        if self.enable_alert_server:
            self._push_alerts()

        self._print_report()
        return self.results

    def _push_alerts(self):
        """将扫描结果上报至报警服务器"""
        logger.info("正在上报结果至报警服务器 …")
        client = AlertClient(
            target_url=self.target_base_url,
            server_host=ALERT_SERVER_HOST,
            server_port=ALERT_SERVER_PORT,
        )
        if client.connect():
            for task_name, result_data in self.results.items():
                if result_data["status"] == "completed":
                    client.send_report(task_name, result_data["result"])
            client.close()

    def _print_report(self):
        """打印综合扫描报告"""
        duration = self.end_time - self.start_time

        completed = sum(1 for r in self.results.values() if r["status"] == "completed")
        failed = sum(1 for r in self.results.values() if r["status"] == "failed")
        vuln_count = sum(
            1 for r in self.results.values()
            if r["status"] == "completed" and r["result"]["vulnerable"]
        )

        lines = [
            "",
            "=" * 60,
            "           扫描综合报告",
            "=" * 60,
            f"  总计: {len(self.results)} | 成功: {completed} | "
            f"失败: {failed} | 发现漏洞: {vuln_count}",
            f"  耗时: {duration:.2f}s",
            "",
        ]

        for task_name, rd in self.results.items():
            icon = "✓" if rd["status"] == "completed" else "✗"
            lines.append(f"  [{icon}] {task_name}  ({rd['duration']:.2f}s)")

            if rd["status"] == "failed":
                lines.append(f"        错误: {rd.get('error', '未知')}")
                continue

            r = rd["result"]
            lines.append(f"        漏洞: {r['vulnerable']}  等级: {r['severity']}")
            for d in r.get("details", []):
                lines.append(f"          {d}")

        # 整体安全评估
        if vuln_count == 0:
            lines.append("\n  ✓  未发现明显漏洞 — 系统相对安全。")
        elif vuln_count <= 1:
            lines.append("\n  ⚠  发现少量漏洞，建议尽快修复。")
        elif vuln_count <= 2:
            lines.append("\n  !!  发现多处漏洞，存在较高安全风险！")
        else:
            lines.append("\n  🔴 发现大量漏洞，系统处于极度危险状态！")

        lines.append("\n" + "=" * 60 + "\n")
        for line in lines:
            logger.info(line)

    # ── 导出 ──────────────────────────────────────────────────────────

    def export_results(self, filename: str = None):
        """导出扫描结果为 JSON 文件

        Args:
            filename: 输出文件路径，默认使用 config.SCAN_REPORT_FILE
        """
        if filename is None:
            filename = SCAN_REPORT_FILE
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        export_data = {
            "target": self.target_base_url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_duration": (
                self.end_time - self.start_time if self.end_time else 0
            ),
            "results": {},
        }
        for task_name, result_data in self.results.items():
            export_data["results"][task_name] = {
                "status": result_data["status"],
                "duration": result_data["duration"],
                "timestamp": result_data["timestamp"],
                "result": (
                    result_data["result"]
                    if result_data["status"] == "completed"
                    else None
                ),
                "error": result_data.get("error"),
            }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        logger.info("报告已导出 → %s", filename)


# ── 报警客户端 ────────────────────────────────────────────────────────

class AlertClient:
    """TCP 客户端，将扫描结果发送至报警服务器"""

    def __init__(self, target_url: str, server_host: str = "127.0.0.1",
                 server_port: int = 9999):
        self.target_url = target_url
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None

    def connect(self) -> bool:
        """连接报警服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(3)
            self.socket.connect((self.server_host, self.server_port))
            logger.info("已连接报警服务器 %s:%s", self.server_host, self.server_port)
            return True
        except Exception as exc:
            logger.warning("无法连接报警服务器: %s", exc)
            return False

    def send_report(self, module_name: str, result_data: Dict):
        """发送单个模块的扫描报告

        Args:
            module_name: 模块名称
            result_data: 扫描结果字典
        """
        if not self.socket:
            return
        try:
            message = {
                "type": module_name,
                "severity": result_data.get("severity", "NONE"),
                "target": self.target_url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": result_data.get("details", []),
                "vulnerable": result_data.get("vulnerable", False),
            }
            # 附加漏洞特有数据
            if "extracted_data" in result_data:
                message["extracted_data"] = result_data["extracted_data"]
            if "vulnerabilities" in result_data:
                message["vulnerabilities"] = result_data["vulnerabilities"]
            if "remediation" in result_data:
                message["remediation"] = result_data["remediation"]

            payload = json.dumps(message, ensure_ascii=False) + "\n"
            self.socket.sendall(payload.encode("utf-8"))

            if result_data.get("vulnerable"):
                logger.info("报警已发送: %s", module_name)
        except Exception as exc:
            logger.error("报警发送失败 (%s): %s", module_name, exc)

    def close(self):
        """关闭连接"""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass


# ── 独立运行入口 ──────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    engine = ScannerEngine("http://127.0.0.1:5000", enable_alert_server=False)
    try:
        engine.run_scan()
        engine.export_results()
    except KeyboardInterrupt:
        logger.warning("用户中断扫描。")
    except Exception:
        logger.exception("扫描过程中发生未处理异常。")
