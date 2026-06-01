"""
TCP 报警服务器 — 接收扫描引擎发送的结构化漏洞报告，按类型和严重等级分类，
并在关闭时将数据持久化到 JSON 文件。
"""

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime
from typing import Dict, List

from config import ALERT_SERVER_HOST, ALERT_SERVER_PORT, ALERTS_REPORT_FILE

logger = logging.getLogger(__name__)


class AlertServer:
    """多客户端 TCP 服务器，负责接收和处理扫描报警"""

    def __init__(self, host: str = None, port: int = None):
        self.host = host or ALERT_SERVER_HOST
        self.port = port or ALERT_SERVER_PORT
        self.server_socket = None
        self.is_running = False

        # 存储所有接收到的报警
        self.alerts: List[Dict] = []

        # 按漏洞类型分类存储
        self.alerts_by_type: Dict[str, List[Dict]] = {
            "SQL Injection": [],
            "XSS": [],
            "Directory Traversal": [],
            "Other": [],
        }

        # 统计信息
        self.stats = {
            "total_alerts": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        }

        self.clients: List[Dict] = []
        self._clients_lock = threading.Lock()

    # ── 生命周期 ─────────────────────────────────────────────────────

    def start(self):
        """启动报警服务器，开始监听"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)  # 避免 Windows 下 accept() 阻塞无法响应 Ctrl+C
        self.is_running = True

        logger.info("=" * 60)
        logger.info("  报警服务器监听 %s:%s", self.host, self.port)
        logger.info("  启动时间: %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("  Ctrl+C 可安全退出", )
        logger.info("=" * 60)

        # 启动统计刷新后台线程
        threading.Thread(target=self._stats_refresh_loop, daemon=True).start()

        # 主循环：接受客户端连接
        while self.is_running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                logger.info("新连接: %s", client_addr)
                # 为每个客户端创建独立处理线程
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                ).start()
                with self._clients_lock:
                    self.clients.append({
                        "socket": client_sock,
                        "address": client_addr,
                        "connected_at": datetime.now(),
                    })
            except socket.timeout:
                # accept() 超时，回到循环检查 is_running，允许 Ctrl+C 退出
                continue
            except OSError:
                break
            except Exception:
                logger.exception("接受连接时出错")

    def stop(self):
        """安全关闭报警服务器"""
        logger.info("正在关闭报警服务器 …")
        self.is_running = False

        # 关闭所有客户端连接
        with self._clients_lock:
            for c in self.clients:
                try:
                    c["socket"].close()
                except Exception:
                    pass

        # 关闭服务器 Socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        # 持久化报警数据
        if self.alerts:
            self._save_reports()
        logger.info("报警服务器已停止。")

    # ── 客户端处理 ──────────────────────────────────────────────────

    def _handle_client(self, client_socket: socket.socket,
                       client_address: tuple):
        """处理单个客户端连接的数据接收"""
        client_socket.settimeout(1.0)  # 允许在停止时及时退出 recv() 阻塞
        buffer = ""
        try:
            while self.is_running:
                try:
                    data = client_socket.recv(4096)
                except socket.timeout:
                    continue  # 超时回到循环检查 is_running
                if not data:
                    break
                buffer += data.decode("utf-8")
                # 以换行符分隔多个 JSON 对象
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            self._process_alert(json.loads(line), client_address)
                        except json.JSONDecodeError:
                            logger.warning("来自 %s 的无效 JSON 数据", client_address)
        except ConnectionResetError:
            pass
        except Exception:
            logger.exception("客户端处理异常")
        finally:
            client_socket.close()
            with self._clients_lock:
                self.clients = [
                    c for c in self.clients
                    if c["socket"] is not client_socket
                ]

    # ── 报警处理 ────────────────────────────────────────────────────

    def _process_alert(self, alert_data: Dict, client_address: tuple):
        """处理接收到的报警数据，分类存储并更新统计"""
        alert_data["received_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_data["source"] = str(client_address)
        self.alerts.append(alert_data)

        # 按类型分类
        alert_type = alert_data.get("type", "Other")
        category = alert_type if alert_type in self.alerts_by_type else "Other"
        self.alerts_by_type[category].append(alert_data)

        # 更新统计
        self.stats["total_alerts"] += 1
        sev = alert_data.get("severity", "").upper()
        if sev == "CRITICAL":
            self.stats["critical_count"] += 1
        elif sev == "HIGH":
            self.stats["high_count"] += 1
        elif sev == "MEDIUM":
            self.stats["medium_count"] += 1
        elif sev == "LOW":
            self.stats["low_count"] += 1

        self._display_alert(alert_data)

    def _display_alert(self, alert_data: Dict):
        """实时显示报警信息"""
        sev = alert_data.get("severity", "UNKNOWN")
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = icons.get(sev, "⚪")

        logger.info(
            "%s [%s] %s → %s",
            icon, sev,
            alert_data.get("type", "?"),
            alert_data.get("target", "?"),
        )

        if sev in ("CRITICAL", "HIGH"):
            logger.warning("  ⚠ 高危/严重漏洞 — 请立即关注！")

    def _stats_refresh_loop(self):
        """每 10 秒输出一次实时统计"""
        while self.is_running:
            time.sleep(10)
            if self.stats["total_alerts"] > 0:
                logger.info(
                    "统计 | 总计=%d | 严重=%d 高危=%d 中危=%d 低危=%d",
                    self.stats["total_alerts"],
                    self.stats["critical_count"],
                    self.stats["high_count"],
                    self.stats["medium_count"],
                    self.stats["low_count"],
                )

    def _save_reports(self):
        """将报警数据持久化到 JSON 文件"""
        os.makedirs(os.path.dirname(ALERTS_REPORT_FILE), exist_ok=True)
        report = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "statistics": self.stats,
            "alerts_by_type": {
                k: v for k, v in self.alerts_by_type.items() if v
            },
            "all_alerts": self.alerts,
        }
        with open(ALERTS_REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logger.info("报警数据已保存 → %s", ALERTS_REPORT_FILE)


# ── 入口 ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    srv = AlertServer()
    try:
        srv.start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
