"""
Streamlit 可视化大屏 — 实时展示扫描结果。

启动方式：
    streamlit run src/dashboard.py
    或：python run.py dashboard
"""

import json
import os

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# ── 页面配置 ───────────────────────────────────────────────────────────
st.set_page_config(
    page_title="安全扫描引擎 — 实时监控大屏",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 自定义黑客风格 CSS
st.markdown("""
<style>
.big-font { font-size:30px !important; font-weight: bold; color: #FF4B4B; }
.metric-card { background-color: #262730; padding: 20px;
              border-radius: 10px; border: 1px solid #444; }
div[data-testid="stMetricValue"] { font-size: 2.5rem; }
</style>
""", unsafe_allow_html=True)


# ── 数据加载 ───────────────────────────────────────────────────────────

@st.cache_data(ttl=2)
def load_scan_data():
    """读取并解析 scan_report.json"""
    report_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports", "scan_report.json",
    )
    if not os.path.exists(report_path):
        return None
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, PermissionError):
        return None


def parse_vulnerabilities(data):
    """将嵌套的 JSON 扫描结果转换为扁平化的 DataFrame"""
    if not data or "results" not in data:
        return pd.DataFrame()

    rows = []
    for mod_name, mod_data in data["results"].items():
        if mod_data.get("status") != "completed":
            continue
        result = mod_data.get("result")
        if not result:
            continue

        severity = result.get("severity", "NONE")
        vulns = result.get("vulnerabilities", [])
        rem = result.get("remediation")
        rem_title = rem.get("title", "—") if isinstance(rem, dict) else "—"

        # 处理没有 vulnerabilities 列表但有 extracted_data 的模块（如 SQLi）
        if not vulns and result.get("vulnerable"):
            vulns = [{
                "type": mod_name,
                "payload": "布尔盲注",
                "url": data.get("target", "N/A"),
            }]

        if vulns:
            for v in vulns:
                # XSS 漏洞中 type 字段缺失，用模块名 + payload 摘要替代
                vuln_type = v.get("type") or mod_name
                vuln_target = v.get("url") or data.get("target", "N/A")
                rows.append({
                    "模块": mod_name,
                    "严重等级": severity,
                    "类型": vuln_type,
                    "Payload": v.get("payload", "N/A"),
                    "目标URL": vuln_target,
                    "修复建议": rem_title,
                })
        else:
            # 已完成但未发现漏洞的模块也展示一行，便于了解扫描覆盖
            rows.append({
                "模块": mod_name,
                "严重等级": "✅ 无漏洞",
                "类型": "—",
                "Payload": "—",
                "目标URL": data.get("target", "N/A"),
                "修复建议": "—",
            })

    return pd.DataFrame(rows)


# ── 界面布局 ───────────────────────────────────────────────────────────
st.title("🛡️ 全自动安全扫描引擎 — 漏洞监控中心")
st.markdown("---")

# 每 3 秒自动刷新
st_autorefresh(interval=3000, key="data_refresh")

data = load_scan_data()

if data is None:
    st.warning("⚠️ 尚未检测到扫描报告。请先运行扫描（`python run.py scan`）。")
    st.stop()

df = parse_vulnerabilities(data)
df_vulns = df[df["严重等级"] != "✅ 无漏洞"]  # 仅含真实漏洞的行
total = len(df_vulns)
critical = len(df_vulns[df_vulns["严重等级"] == "CRITICAL"])
high = len(df_vulns[df_vulns["严重等级"] == "HIGH"])
total_modules = len(data.get("results", {}))

# 顶部 KPI 指标卡
c1, c2, c3, c4 = st.columns(4)
c1.metric("🔍 发现漏洞总数", total)
c2.metric("🔴 严重 (Critical)", critical, delta_color="inverse")
c3.metric("🟠 高危 (High)", high, delta_color="inverse")
c4.metric("📦 扫描模块数", total_modules)

st.markdown("---")

# 图表区域
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("📊 漏洞严重等级分布")
    if not df_vulns.empty:
        counts = df_vulns["严重等级"].value_counts().reset_index()
        counts.columns = ["等级", "数量"]
        fig = px.pie(
            counts,
            values="数量",
            names="等级",
            color_discrete_map={
                "CRITICAL": "#FF4B4B",
                "HIGH": "#FFA500",
                "MEDIUM": "#FFD700",
                "LOW": "#00FF00",
            },
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("暂无漏洞数据用于绘图")

with col_right:
    st.subheader("📈 各模块风险统计")
    if not df_vulns.empty:
        mod_counts = df_vulns["模块"].value_counts().reset_index()
        mod_counts.columns = ["模块", "漏洞数"]
        fig = px.bar(mod_counts, x="模块", y="漏洞数", color="模块")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("各模块均未发现漏洞")

st.markdown("---")

# 详细数据表格
st.subheader("📋 漏洞明细与修复建议")
if not df.empty:
    # 按严重程度排序（无漏洞模块排在最后）
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "✅ 无漏洞": 5}
    df["_sort"] = df["严重等级"].map(order)
    df = df.sort_values("_sort").drop(columns=["_sort"])
    st.dataframe(df, use_container_width=True, height=400)
else:
    st.success("✅ 恭喜！本次扫描未发现明显漏洞。")

st.markdown("---")
st.caption("全自动安全扫描引擎 可视化大屏 | Powered by Streamlit")
