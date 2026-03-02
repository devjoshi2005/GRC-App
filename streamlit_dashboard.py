"""
GRC Compliance Engine — Streamlit Risk Analytics Dashboard
Launch: streamlit run streamlit_dashboard.py
Reads risk data from GRC_RISK_FILE env var or default path.
"""

import json
import os

import pandas as pd
import streamlit as st

# ─── Page Config ─────────────────────────────────────────────
st.set_page_config(
    page_title="GRC Risk Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark card styling
st.markdown("""
<style>
    .metric-card {
        background-color: #161b22;
        padding: 16px;
        border-radius: 10px;
        border: 1px solid #30363D;
        text-align: center;
    }
    .metric-value { font-size: 28px; font-weight: 700; }
    .metric-label { font-size: 12px; color: #8b949e; text-transform: uppercase; }
    .critical { color: #f85149; }
    .high { color: #db6d28; }
    .medium { color: #d29922; }
    .low { color: #3fb950; }
</style>
""", unsafe_allow_html=True)


# ─── Load Data ───────────────────────────────────────────────
@st.cache_data
def load_data():
    risk_file = os.environ.get("GRC_RISK_FILE", "risk_quantification_report.json")

    # Search common paths
    search_paths = [
        risk_file,
        os.path.join("api", "outputs", risk_file),
    ]

    # Also search in output subdirectories
    outputs_dir = os.path.join("api", "outputs")
    if os.path.isdir(outputs_dir):
        for d in os.listdir(outputs_dir):
            candidate = os.path.join(outputs_dir, d, "risk_quantification_report.json")
            search_paths.append(candidate)

    for path in search_paths:
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                records = data.get("records", [])
                summary = data.get("summary", {})
            else:
                records = data
                summary = {}
            return pd.DataFrame(records), summary

    return pd.DataFrame(), {}


df, summary = load_data()

if df.empty:
    st.warning("No risk data found. Run the GRC pipeline first to generate risk_quantification_report.json")
    st.stop()


# ─── Compliance Score ────────────────────────────────────────
def calc_compliance_score(df):
    if df.empty:
        return 100.0
    risky = (
        (df.get("is_public", False) == True) |
        (df.get("severity", "").isin(["Critical"])) |
        (df.get("control_effectiveness", 1) < 0.3)
    )
    return round(max(0, 100 - (risky.sum() / len(df) * 100)), 1)


# ─── Header ──────────────────────────────────────────────────
st.title("🛡️ Enterprise GRC Risk Analytics")
st.markdown("**FAIR Risk Quantification** | IBM Data Breach Report 2025 Metrics")
st.divider()


# ─── KPI Cards ───────────────────────────────────────────────
comp_score = calc_compliance_score(df)
total_ale = df["ale"].sum() if "ale" in df.columns else 0
critical_count = len(df[df["severity"] == "Critical"]) if "severity" in df.columns else 0
high_count = len(df[df["severity"] == "High"]) if "severity" in df.columns else 0

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Compliance Score", f"{comp_score}%")
with col2:
    st.metric("Total ALE", f"${total_ale:,.0f}")
with col3:
    st.metric("Critical", critical_count)
with col4:
    st.metric("High", high_count)
with col5:
    st.metric("Total Findings", len(df))

st.divider()


# ─── Charts ──────────────────────────────────────────────────
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Severity Distribution")
    if "severity" in df.columns:
        sev_counts = df["severity"].value_counts()
        st.bar_chart(sev_counts, color="#58a6ff")

with chart_col2:
    st.subheader("ALE by Service")
    if "service" in df.columns and "ale" in df.columns:
        svc_ale = df.groupby("service")["ale"].sum().sort_values(ascending=False).head(10)
        st.bar_chart(svc_ale, color="#f85149")

st.divider()

chart_col3, chart_col4 = st.columns(2)

with chart_col3:
    st.subheader("Data Classification")
    if "classification" in df.columns:
        cls_counts = df["classification"].value_counts()
        st.bar_chart(cls_counts, color="#3fb950")

with chart_col4:
    st.subheader("Cloud Provider Split")
    if "cloud_provider" in df.columns:
        provider_counts = df["cloud_provider"].value_counts()
        st.bar_chart(provider_counts, color="#d29922")

st.divider()


# ─── Top Risk Findings Table ─────────────────────────────────
st.subheader("Top Risk Findings (by ALE)")

display_cols = ["asset", "severity", "service", "classification", "ale",
                "control_effectiveness", "finding_title", "cloud_provider"]
available_cols = [c for c in display_cols if c in df.columns]

if available_cols:
    top_risks = df.nlargest(20, "ale")[available_cols] if "ale" in df.columns else df.head(20)[available_cols]
    st.dataframe(
        top_risks.style.format({"ale": "${:,.2f}", "control_effectiveness": "{:.0%}"}),
        use_container_width=True,
        hide_index=True,
    )

st.divider()


# ─── IBM Context ─────────────────────────────────────────────
st.subheader("IBM Data Breach Report 2025 Context")

ibm_context = summary.get("ibm_context", {})
ibm_col1, ibm_col2, ibm_col3 = st.columns(3)

with ibm_col1:
    st.metric("Avg Breach Cost", f"${ibm_context.get('avg_breach_cost', 4880000):,}")
with ibm_col2:
    st.metric("Your ALE as % of Avg Breach", f"{ibm_context.get('total_ale_as_pct_of_avg_breach', 0):.1f}%")
with ibm_col3:
    st.metric("Avg Detection Time", f"{ibm_context.get('avg_detection_days', 194)} days")


# ─── Sidebar Filters ─────────────────────────────────────────
st.sidebar.header("Filters")

if "severity" in df.columns:
    selected_severity = st.sidebar.multiselect(
        "Severity",
        options=df["severity"].unique().tolist(),
        default=df["severity"].unique().tolist(),
    )
    filtered_df = df[df["severity"].isin(selected_severity)]
else:
    filtered_df = df

if "cloud_provider" in df.columns:
    selected_provider = st.sidebar.multiselect(
        "Cloud Provider",
        options=df["cloud_provider"].unique().tolist(),
        default=df["cloud_provider"].unique().tolist(),
    )
    filtered_df = filtered_df[filtered_df["cloud_provider"].isin(selected_provider)]

st.sidebar.divider()
st.sidebar.subheader("Filtered Summary")
st.sidebar.metric("Findings", len(filtered_df))
if "ale" in filtered_df.columns:
    st.sidebar.metric("Filtered ALE", f"${filtered_df['ale'].sum():,.0f}")


# ─── Raw Data ────────────────────────────────────────────────
with st.expander("View Raw Data"):
    st.dataframe(filtered_df, use_container_width=True, hide_index=True)

# ─── Download ────────────────────────────────────────────────
st.sidebar.divider()
st.sidebar.download_button(
    "Download Filtered CSV",
    data=filtered_df.to_csv(index=False),
    file_name="grc_risk_filtered.csv",
    mime="text/csv",
)
