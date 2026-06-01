# 🛡️ 全自动安全扫描引擎

> 基于 Python 的模块化 Web 安全扫描平台，用于**授权的渗透测试与安全教学**。

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 目录

- [项目概述](#项目概述)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
- [使用方式](#使用方式)
- [项目结构](#项目结构)
- [扫描器模块](#扫描器模块)
- [配置说明](#配置说明)
- [可视化大屏](#可视化大屏)
- [风险闭环修复](#风险闭环修复)
- [路线图](#路线图)
- [免责声明](#免责声明)
- [开源许可](#开源许可)

---

## 项目概述

**全自动安全扫描引擎**是一个 Python 平台，调度三大专家扫描器 — **SQL 注入**、**跨站脚本 (XSS)**、**目录遍历** — 对一个故意设计存在漏洞的靶场应用进行自动化并行检测。

**核心特性：**

- **并行扫描** — 三大专家在多线程中同时工作
- **风险闭环** — 每项发现附带具体的修复建议和代码示例
- **实时报警** — 基于 TCP 的报警服务器接收漏洞实时通知
- **可视化大屏** — Streamlit 驱动的监控面板，含图表和可钻取数据表
- **统一 API** — 每个扫描器对外暴露单一的 `scan()` 函数，返回结构化字典
- **零硬编码密钥** — 所有配置由 `config.py` 和环境变量驱动

---

## 系统架构

```
┌─────────────┐     ┌──────────────────────────────────┐
│  run.py     │────▶│  ScannerEngine (src/engine.py)   │
│  (CLI 入口) │     │  ┌──────────┐ ┌──────────┐      │
└─────────────┘     │  │ SQLi     │ │ XSS      │      │
                    │  │ 扫描器   │ │ 扫描器   │ ...  │
                    │  └────┬─────┘ └────┬─────┘      │
                    └───────┼────────────┼────────────┘
                            │  HTTP GET  │
                            ▼            ▼
                    ┌─────────────────────────────┐
                    │  靶场应用 (:5000)            │
                    │  /sqli   /xss   /file       │
                    │  （故意包含漏洞）            │
                    └─────────────────────────────┘
                            │
                    ┌───────▼────────┐
                    │  报警服务器     │──▶ alerts_report.json
                    │  (:9999)       │
                    └────────────────┘
                            │
                    ┌───────▼────────┐
                    │  可视化大屏     │──▶ scan_report.json
                    │  (Streamlit)   │
                    └────────────────┘
```

---

## 快速开始

> **前提条件：** Python 3.9+、MySQL 5.7+（SQL 注入靶场需要）。

### 1. 克隆并安装

```bash
git clone <仓库地址>
cd security-scanner-engine
pip install -r requirements.txt
```

### 2. 初始化 MySQL 数据库

SQL 注入靶场依赖 `vuln_db` 数据库。

**2.1 配置数据库密码：**

```powershell
# 复制模板文件创建 .env（CMD 用 copy 代替 cp）
copy .env.example .env
# 用编辑器打开 .env，将 DB_PASSWORD=你的MySQL密码 改为真实密码
```

> `.env` 已被 `.gitignore` 排除，不会被提交到 Git，保护你的密码安全。

**2.2 执行初始化：**

```shell
# CMD
mysql -u root -p --default-character-set=utf8mb4 < init_database.sql

# PowerShell
Get-Content init_database.sql | mysql -u root -p --default-character-set=utf8mb4
```

> 详细初始化步骤及故障排查见下方[数据库初始化](#数据库初始化)章节。

### 3. 启动漏洞靶场

```bash
python run.py target
```
启动 Flask 应用，监听 `http://127.0.0.1:5000`，包含三个故意设计的漏洞端点。

### 4. 启动报警服务器（可选）

```bash
python run.py server
```
监听 `127.0.0.1:9999`，接收扫描器发送的漏洞报告。

### 5. 执行扫描

```bash
python run.py scan
```
三大扫描器并行执行，结果打印到控制台并导出至 `reports/scan_report.json`。

### 6. 查看大屏

```bash
python run.py dashboard
```
打开 Streamlit 可视化大屏，访问 `http://127.0.0.1:8501`。

---

## 使用方式

| 命令                       | 说明                           |
|---------------------------|--------------------------------|
| `python run.py target`    | 启动漏洞靶场 Flask 应用         |
| `python run.py server`    | 启动 TCP 报警服务器            |
| `python run.py scan`      | 执行全部扫描并导出报告          |
| `python run.py dashboard` | 启动 Streamlit 可视化大屏      |

也可以单独运行某个扫描器：

```bash
python -m src.scanners.sqli_scanner
python -m src.scanners.xss_scanner
python -m src.scanners.file_scanner
```

---

## 项目结构

```
security-scanner-engine/
├── run.py                      # 统一 CLI 入口
├── config.py                   # 集中配置（支持 .env）
├── .env.example                # 环境变量模板
├── init_database.sql           # MySQL 数据库初始化脚本
├── requirements.txt            # Python 依赖
├── LICENSE                     # MIT 许可证
├── .gitignore
├── README.md
├── src/
│   ├── __init__.py
│   ├── engine.py               # 总控调度引擎 + 报警客户端
│   ├── server.py               # TCP 报警服务器
│   ├── dashboard.py            # Streamlit 实时大屏
│   ├── target_app.py           # 故意包含漏洞的靶场应用
│   └── scanners/
│       ├── __init__.py
│       ├── sqli_scanner.py     # SQL 注入布尔盲注扫描器
│       ├── xss_scanner.py      # 反射型 XSS 扫描器
│       └── file_scanner.py     # 目录遍历扫描器
├── user_files/                 # 目录遍历测试文件（运行时生成）
├── reports/                    # 扫描与报警报告输出（运行时生成）
└── logs/                       # 运行日志（运行时生成）
```

---

## 扫描器模块

### 1. SQL 注入扫描器 (`src/scanners/sqli_scanner.py`)

- **阶段一 — 探测**：发送 `' and 1=1 --` / `' and 1=2 --` 比对响应长度
- **阶段二 — 爆破**：二分查找法逐位猜解数据库名和表名，表名爆破使用多线程并行

**返回值：** `{vulnerable, severity, details, extracted_data, remediation}`

### 2. XSS 扫描器 (`src/scanners/xss_scanner.py`)

- 向每个查询参数注入常见 Payload（`<script>`、`<img onerror>`、`<svg/onload>`、`javascript:`）及确定性大小写变体
- Payload 原样出现在响应正文中即判定存在漏洞

**返回值：** `{vulnerable, severity, details, vulnerabilities, remediation}`

### 3. 目录遍历扫描器 (`src/scanners/file_scanner.py`)

- 向文件下载端点发送路径穿越 Payload（`../../../etc/passwd` 等）
- 匹配响应内容中的已知文件特征（源码、Linux passwd、Windows win.ini）

**返回值：** `{vulnerable, severity, details, vulnerabilities, remediation}`

---

## 配置说明

所有配置项定义在 **`config.py`**，可通过本项目根目录的 `.env` 文件覆盖（将 `.env.example` 复制为 `.env` 后取消注释需要修改的变量即可）：

| 环境变量                 | 默认值            | 说明                |
|-------------------------|-------------------|---------------------|
| `SCANNER_TARGET_HOST`   | `127.0.0.1`       | 靶场主机地址         |
| `SCANNER_TARGET_PORT`   | `5000`            | 靶场端口            |
| `DB_HOST`               | `127.0.0.1`       | MySQL 主机          |
| `DB_PORT`               | `3306`            | MySQL 端口          |
| `DB_USER`               | `root`            | MySQL 用户名        |
| `DB_PASSWORD`           | `changeme`        | MySQL 密码          |
| `DB_NAME`               | `vuln_db`         | 数据库名            |
| `DB_CHARSET`            | `utf8mb4`         | 数据库字符集         |
| `ALERT_SERVER_HOST`     | `127.0.0.1`       | 报警服务器主机       |
| `ALERT_SERVER_PORT`     | `9999`            | 报警服务器端口       |
| `SCANNER_TIMEOUT`       | `5`               | HTTP 请求超时（秒）  |
| `LOG_LEVEL`             | `INFO`            | 日志级别            |

> **提示：** 未在 `.env` 中配置的变量将使用上表中的默认值。系统环境变量的优先级高于 `.env` 文件。

### 数据库初始化

SQL 注入靶场依赖 MySQL 数据库。项目根目录下提供了 `init_database.sql` 初始化脚本。

#### 前置检查

```sql
-- 进入 MySQL 确认服务正常
mysql -u root -p
mysql> SELECT VERSION();   -- 确认版本（需 5.7+）
mysql> EXIT;
```

#### 执行初始化

**CMD（命令提示符）：**
```shell
:: 确保已进入项目根目录
cd security-scanner-engine
:: 执行初始化脚本（必须指定 utf8mb4，否则中文数据会报 1366 错误）
mysql -u root -p --default-character-set=utf8mb4 < init_database.sql
```

**PowerShell：**
```powershell
# 确保已进入项目根目录
cd security-scanner-engine
# 执行初始化脚本（必须指定 utf8mb4，否则中文数据会报 1366 错误）
Get-Content init_database.sql | mysql -u root -p --default-character-set=utf8mb4
```

**登录后导入（两种终端通用）：**
```sql
mysql -u root -p --default-character-set=utf8mb4
mysql> source init_database.sql;
```

#### 验证结果

```sql
mysql -u root -p --default-character-set=utf8mb4 -e "USE vuln_db; SHOW TABLES; SELECT COUNT(*) AS user_count FROM users;"
```

期望输出：
```
+------------+
| user_count |
+------------+
|          7 |
+------------+
```

#### 配置数据库密码

> **推荐使用 `.env` 文件**，安全且不会被提交到 Git。

```powershell
# 1. 从模板创建 .env（只在首次执行，.gitignore 已排除此文件）
copy .env.example .env

# 2. 用任意编辑器打开 .env，找到 MySQL 密码这一行：
#    取消注释并改为你的真实密码（不要加引号）
#    DB_PASSWORD=你的MySQL密码

# 3. 验证密码已生效
python -c "from config import DB_PASSWORD; print('✅ 密码已加载' if DB_PASSWORD != 'changeme' else '⚠ 请在 .env 中修改 DB_PASSWORD')"
```

之后如需修改其他配置项（如主机地址、端口等），同样在 `.env` 中取消对应行的注释并修改即可。未注释的项沿用 `config.py` 中的默认值。

其他方式（适合临时或 CI/CD 环境）：

```powershell
# 临时环境变量（PowerShell，关终端即失效）
$env:DB_PASSWORD="你的密码"

# 临时环境变量（CMD）
set DB_PASSWORD=你的密码
```

脚本会创建 `vuln_db` 数据库及三张表：

| 表名            | 用途                       | 示例数据 |
|----------------|----------------------------|---------|
| `users`        | SQL 注入演示（核心目标）     | 7 条    |
| `products`     | 扩展数据爆破演示            | 8 条    |
| `system_config`| 模拟敏感配置信息泄露        | 7 条    |

> **注意：** 数据库连接信息（主机、端口、用户名、密码）可通过环境变量覆盖，详见上方配置表。若未初始化数据库，SQLi 扫描器将返回「未检测到 SQL 注入漏洞」。

#### 强制关闭卡死的报警服务器

如果 `python run.py server` 按 `Ctrl+C` 无法退出（Windows 下偶发），通过端口号定位并终止进程：

```powershell
# 找到占用 9999 端口的进程 PID
netstat -ano | findstr :9999

# 记下最后一列的 PID，例如 31116，强制终止
taskkill /F /PID 31116
```

---

## 可视化大屏

Streamlit 大屏提供以下功能：

- **KPI 指标卡** — 漏洞总数、严重/高危数量、扫描时间
- **饼图** — 漏洞严重等级分布（严重/高危/中危/低危）
- **柱状图** — 各扫描器模块发现数量对比
- **明细表** — 每条漏洞的 Payload、目标 URL、修复建议，按严重程度排序

大屏每 3 秒自动刷新以获取最新扫描结果。

---

## 风险闭环修复

每条漏洞报告都包含 `remediation` 字段，提供：

- **标题** — 修复方案一句话概括
- **描述** — 漏洞产生原因
- **建议** — 具体修复步骤
- **代码示例** — 危险写法 vs 安全写法对比

这种"风险闭环"设计不仅指出问题，更告诉开发者**如何修复**。

---

## 路线图

- [ ] CSRF / SSRF / XXE 扫描器模块
- [ ] Web 管理界面（Flask 后台面板）
- [ ] CI/CD 集成（GitHub Actions 扫描工作流）
- [ ] 分布式扫描节点（Celery / Redis）
- [ ] 认证与授权测试
- [ ] PDF / HTML 格式报告导出

---

## 免责声明

**本软件仅用于授权的安全测试、教学培训和研究目的。**

请勿使用本工具扫描未经授权或未获得明确书面许可的系统。作者不对任何误用或因此造成的损失承担任何责任。

---

## 开源许可

MIT — 详见 [LICENSE](LICENSE) 文件。
