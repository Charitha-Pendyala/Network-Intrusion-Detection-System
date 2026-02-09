import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import matplotlib.pyplot as plt

# ------------------ Page Config ------------------
st.set_page_config(
    page_title="SentinelNet – AI-Powered NIDS",
    page_icon="🛡️",
    layout="wide"
)

# ------------------ Custom CSS ------------------
st.markdown("""
<style>
/* Main title */
.main-title {
    font-size: 42px;
    font-weight: 700;
    margin-bottom: 0.2em;
}

/* Subtitle */
.subtitle {
    font-size: 18px;
    color: #555;
    margin-bottom: 1.5em;
}

/* Section headers */
.section {
    font-size: 26px;
    font-weight: 600;
    margin-top: 1.5em;
    margin-bottom: 0.5em;
}

/* Smaller helper text */
.helper {
    font-size: 14px;
    color: #666;
}

/* Metric labels */
div[data-testid="metric-container"] {
    background-color: #f8f9fa;
    padding: 16px;
    border-radius: 10px;
}

/* Table font */
.dataframe {
    font-size: 13px;
}
</style>
""", unsafe_allow_html=True)

# ------------------ Header ------------------
st.markdown('<div class="main-title">🛡️ SentinelNet</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtitle">AI-Powered Network Intrusion Detection System using supervised and unsupervised learning</div>',
    unsafe_allow_html=True
)

# ------------------ Sidebar ------------------
st.sidebar.header("⚙️ Control Panel")
st.sidebar.markdown(
    "Upload **NSL-KDD formatted CSV** to analyze network traffic and generate alerts."
)

uploaded_file = st.sidebar.file_uploader(
    "📤 Upload CSV File",
    type=["csv"],
    help="Use NSL-KDD format (e.g., nsl_kdd_upload.csv)"
)

# ------------------ File Checks ------------------
REQUIRED_FILES = [
    "rf_model.pkl",
    "iso_model.pkl",
    "scaler.pkl",
    "feature_columns.pkl"
]

missing = [f for f in REQUIRED_FILES if not os.path.exists(f)]
if missing:
    st.error(f"Missing required files: {missing}")
    st.stop()

# ------------------ Load Models ------------------
@st.cache_resource
def load_artifacts():
    rf = joblib.load("rf_model.pkl")
    iso = joblib.load("iso_model.pkl")
    scaler = joblib.load("scaler.pkl")
    feature_columns = joblib.load("feature_columns.pkl")
    return rf, iso, scaler, feature_columns

rf, iso, scaler, feature_columns = load_artifacts()

# ------------------ Main Logic ------------------
if uploaded_file:
    df = pd.read_csv(uploaded_file)

    with st.expander("📄 Uploaded Data Preview"):
        st.dataframe(df.head(10), use_container_width=True)

    # ------------------ Preprocessing ------------------
    raw_df = df.drop(
        columns=[c for c in ["label", "difficulty"] if c in df.columns],
        errors="ignore"
    )

    raw_df = pd.get_dummies(
        raw_df,
        columns=["protocol_type", "service", "flag"]
    )

    raw_df = raw_df.reindex(columns=feature_columns, fill_value=0)
    X_scaled = scaler.transform(raw_df)

    # ------------------ Predictions ------------------
    rf_pred = rf.predict(X_scaled)
    iso_pred = np.where(iso.predict(X_scaled) == -1, 1, 0)

    alerts = []
    for r, i in zip(rf_pred, iso_pred):
        if r == 1 and i == 1:
            alerts.append("CRITICAL")
        elif r == 1:
            alerts.append("HIGH")
        elif i == 1:
            alerts.append("MEDIUM")
        else:
            alerts.append("SAFE")

    df["Alert_Level"] = alerts
    severity_counts = df["Alert_Level"].value_counts()

    # ------------------ Metrics ------------------
    st.markdown('<div class="section">📊 Threat Overview</div>', unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🟢 SAFE", severity_counts.get("SAFE", 0))
    c2.metric("🟡 MEDIUM", severity_counts.get("MEDIUM", 0))
    c3.metric("🟠 HIGH", severity_counts.get("HIGH", 0))
    c4.metric("🔴 CRITICAL", severity_counts.get("CRITICAL", 0))

    # ------------------ Charts ------------------
    st.markdown('<div class="section">📈 Alert Distribution</div>', unsafe_allow_html=True)

    chart_df = severity_counts.reset_index()
    chart_df.columns = ["Alert Level", "Count"]

    st.bar_chart(chart_df.set_index("Alert Level"))

    # ------------------ Donut Chart (Clean & Compact) ------------------
    st.markdown('<div class="section">🧠 Severity Breakdown</div>', unsafe_allow_html=True)
    
    col_left, col_center, col_right = st.columns([1, 2, 1])
    
    with col_center:
        fig, ax = plt.subplots(figsize=(3, 3))
    
        wedges, texts, autotexts = ax.pie(
            chart_df["Count"],
            autopct="%1.0f%%",
            startangle=90,
            pctdistance=0.75,
            textprops={"fontsize": 9}
        )
    
        # Donut hole
        centre_circle = plt.Circle((0, 0), 0.55, fc="white")
        ax.add_artist(centre_circle)
    
        ax.axis("equal")
    
        # Legend outside (clean)
        ax.legend(
            wedges,
            chart_df["Alert Level"],
            title="Alert Level",
            loc="center left",
            bbox_to_anchor=(1.05, 0.5),
            fontsize=9
        )
    
        plt.tight_layout()
        st.pyplot(fig, use_container_width=False)
    


    # ------------------ Filter ------------------
    st.markdown('<div class="section">🚨 Filter Alerts</div>', unsafe_allow_html=True)

    selected_level = st.selectbox(
        "Select alert severity",
        ["ALL", "SAFE", "MEDIUM", "HIGH", "CRITICAL"]
    )

    filtered_df = df if selected_level == "ALL" else df[df["Alert_Level"] == selected_level]
    st.dataframe(filtered_df, use_container_width=True)

    # ------------------ Explanation ------------------
    with st.expander("ℹ️ How SentinelNet Works"):
        st.markdown("""
- **Random Forest** identifies known intrusion patterns  
- **Isolation Forest** detects abnormal behavior  
- Alerts are severity-based:
  - SAFE → Normal traffic  
  - MEDIUM → Anomalous behavior  
  - HIGH → Known attack  
  - CRITICAL → Confirmed intrusion  
        """)

    # ------------------ Download ------------------
    st.markdown('<div class="section">⬇ Download Report</div>', unsafe_allow_html=True)
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Alert CSV",
        csv,
        "sentinelnet_alerts.csv",
        "text/csv"
    )

else:
    st.info("⬅ Upload an NSL-KDD CSV file from the sidebar to begin analysis.")
