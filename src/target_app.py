"""
漏洞靶场应用 — 综合安全漏洞演示平台（Flask）

这是一个故意包含安全漏洞的 Web 应用，将 SQL 注入、反射型 XSS、
目录遍历三大经典漏洞整合到单一 Flask 服务中。

启动方式：
    python run.py target
    或：python -m src.target_app

漏洞模块：
    /sqli/*   — SQL 注入（字符串拼接构造 SQL）
    /xss/*    — 反射型 XSS（|safe 过滤器禁用自动转义）
    /file/*   — 目录遍历（未校验路径，直接拼接用户输入）

⚠️  警告：此应用包含故意设计的安全漏洞，仅用于教学测试！
"""

import logging
import os

import pymysql
from flask import Flask, request, render_template_string, send_file

from config import (
    DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_CHARSET,
    USER_FILES_DIR,
)

logger = logging.getLogger(__name__)

# ── Flask 应用实例 ────────────────────────────────────────────────────
app = Flask(__name__)
os.makedirs(USER_FILES_DIR, exist_ok=True)


# ── 数据库连接工具 ────────────────────────────────────────────────────

def _get_conn():
    """获取 MySQL 数据库连接"""
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        db=DB_NAME,
        charset=DB_CHARSET,
        cursorclass=pymysql.cursors.DictCursor,
    )


# ═══════════════════════════════════════════════════════════════════════
#  模块一：SQL 注入漏洞 (/sqli/*)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/sqli/index.php")
def sqli_index():
    """
    【漏洞类型】SQL 注入 — Union 注入 / 错误回显注入 / 布尔盲注

    漏洞核心：使用 f-string 直接拼接用户输入到 SQL 语句中。
    攻击者可构造恶意 Payload 进行联合查询或错误爆破。
    """
    user_id = request.args.get("id")
    if not user_id:
        return "请输入用户 ID，例如: /sqli/index.php?id=1", 200

    # 🔴 漏洞：危险的字符串拼接
    query = f"SELECT username, email FROM users WHERE id = '{user_id}'"
    logger.debug("[SQLi] 执行查询: %s", query)

    conn = None
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
        if row:
            return (
                f"<h3>用户信息</h3>"
                f"<p>用户名: {row['username']}</p>"
                f"<p>邮箱: {row['email']}</p>"
            )
        return "<h3>错误</h3><p>未找到该用户。</p>", 200
    except Exception as exc:
        # 🔴 信息泄露：返回详细数据库错误（便于错误回显注入）
        return f"<p>数据库错误: {exc}</p>", 500
    finally:
        if conn:
            conn.close()


@app.route("/sqli/health")
def sqli_health():
    """健康检查端点"""
    return {"status": "ok", "module": "SQL Injection"}


# ═══════════════════════════════════════════════════════════════════════
#  模块二：反射型 XSS (/xss/*)
# ═══════════════════════════════════════════════════════════════════════

XSS_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>搜索结果</title></head>
<body>
    <h2>搜索中心</h2>
    <form action="/xss/search" method="get">
        <input type="text" name="name" placeholder="输入搜索关键词">
        <input type="submit" value="查询">
    </form>
    <hr>
    {% if name %}
        <!--
            【漏洞说明】
            Jinja2 默认会对 {{ name }} 进行 HTML 转义，但此处故意使用
            |safe 过滤器移除了自动转义保护，模拟开发者误用的场景。

            安全做法: {{ name }}
            危险做法: {{ name|safe }} ← 当前使用此方式演示漏洞
        -->
        <h3>您搜索的内容是：{{ name|safe }}</h3>
    {% endif %}
</body>
</html>"""


@app.route("/xss/search")
def xss_search():
    """
    【漏洞类型】反射型 XSS 跨站脚本攻击

    漏洞核心：模板渲染时使用了 |safe 过滤器，导致 Jinja2 不会对
    用户输入进行 HTML 实体转义。
    """
    name = request.args.get("name", "")
    # 注意：此处故意不做任何过滤，完全依赖模板层的 |safe 触发漏洞
    return render_template_string(XSS_TEMPLATE, name=name)


@app.route("/xss/health")
def xss_health():
    """健康检查端点"""
    return {"status": "ok", "module": "XSS"}


# ═══════════════════════════════════════════════════════════════════════
#  模块三：目录遍历漏洞 (/file/*)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/file/download")
def file_download():
    """
    【漏洞类型】目录遍历 / 路径穿越 (Directory Traversal)

    漏洞核心：直接将用户输入的文件名与基目录拼接，未进行路径校验。
    攻击者可使用 ../ 跳出限制目录访问任意文件。
    """
    filename = request.args.get("file")
    if not filename:
        return "请提供文件名参数，例如: /file/download?file=test.txt", 400

    # 🔴 漏洞：直接拼接用户输入，未做路径校验
    file_path = os.path.join(USER_FILES_DIR, filename)
    logger.debug("[File] 请求路径: %s", file_path)

    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            return send_file(file_path)
        except Exception as exc:
            return f"文件读取错误: {exc}", 500
    return f"文件不存在: {file_path}", 404


@app.route("/file/health")
def file_health():
    """健康检查端点"""
    return {"status": "ok", "module": "File Traversal"}


# ═══════════════════════════════════════════════════════════════════════
#  首页 — 靶场导航
# ═══════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """靶场首页，提供各漏洞模块的导航链接"""
    return """<html>
<head><title>综合安全漏洞靶场</title></head>
<body>
    <h1>🎯 综合安全漏洞靶场</h1>
    <p>欢迎使用集成化 Web 安全漏洞演示平台。</p>
    <hr>
    <h2>可用模块：</h2>
    <ul>
        <li><b>SQL 注入:</b> <a href="/sqli/index.php?id=1">/sqli/index.php?id=1</a></li>
        <li><b>XSS 跨站脚本:</b> <a href="/xss/search?name=test">/xss/search?name=test</a></li>
        <li><b>目录遍历:</b> <a href="/file/download?file=test.txt">/file/download?file=test.txt</a></li>
    </ul>
    <hr>
    <h2>健康检查：</h2>
    <ul>
        <li><a href="/sqli/health">SQLi Health</a></li>
        <li><a href="/xss/health">XSS Health</a></li>
        <li><a href="/file/health">File Health</a></li>
    </ul>
    <hr>
    <p style="color:red;">⚠️ 此应用包含故意设计的安全漏洞，仅用于教学测试！</p>
</body>
</html>"""


# ── 入口 ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # 首次启动时自动创建测试文件
    test_file = os.path.join(USER_FILES_DIR, "test.txt")
    if not os.path.exists(test_file):
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("这是一个用于目录遍历扫描的测试文件。\n")
            f.write("如果你能看到这段文字，说明目录遍历漏洞利用成功！\n")
        logger.info("已创建 %s", test_file)

    secret_file = os.path.join(USER_FILES_DIR, "secret.txt")
    if not os.path.exists(secret_file):
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("SECRET_KEY=super_secret_password_12345\n")
            f.write("DATABASE_PASSWORD=admin@123\n")
        logger.info("已创建 %s", secret_file)

    logger.info("靶场启动，监听 http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
