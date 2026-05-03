import base64
from pathlib import Path
import streamlit as st


def get_base64_video(path: Path) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()


st.set_page_config(page_title="NetSafe", page_icon="🛡️", layout="centered")

video_b64 = get_base64_video(Path(__file__).parent / "assets" / "video_2026-05-03_12-38-38.mp4")

st.markdown(f"""
    <style>
        .stAppDeployButton {{ display: none; }}
        #MainMenu {{ display: none; }}

        /* Background video */
        .bg-video {{
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            object-fit: cover;
            z-index: -1;
            opacity: 0.25;
        }}

        .stApp {{
            background: transparent;
        }}

        [data-testid="stAppViewContainer"] {{
            background: transparent;
        }}

        [data-testid="stHeader"] {{
            background: transparent;
        }}

        @keyframes fadeUp {{
            from {{ opacity: 0; transform: translateY(30px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}

        .fade-up {{
            animation: fadeUp 0.6s ease forwards;
            opacity: 0;
        }}
        .delay-1 {{ animation-delay: 0.1s; }}
        .delay-2 {{ animation-delay: 0.25s; }}
        .delay-3 {{ animation-delay: 0.4s; }}
        .delay-4 {{ animation-delay: 0.55s; }}
        .delay-5 {{ animation-delay: 0.7s; }}
        .delay-6 {{ animation-delay: 0.85s; }}
    </style>

    <video class="bg-video" autoplay muted loop playsinline>
        <source src="data:video/mp4;base64,{video_b64}" type="video/mp4">
    </video>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown('<div class="fade-up delay-1">', unsafe_allow_html=True)
st.title("🛡️ NetSafe")
st.caption("Network Anomaly Detector — powered by Machine Learning")
st.markdown('</div>', unsafe_allow_html=True)
st.divider()

# ── Model Selection ───────────────────────────────────────────────────────────
st.markdown('<div class="fade-up delay-2">', unsafe_allow_html=True)
st.subheader("Select Detection Model")

MODEL_INFO = {
    "Isolation Forest": "Tree-based outlier detection. Fast and effective for high-dimensional data.",
    "One-Class SVM": "Learns a boundary around normal traffic. Flags deviations as anomalies.",
    "Autoencoder": "Neural network that flags traffic with high reconstruction error as anomalous.",
    "Random Forest": "Ensemble classifier trained to distinguish normal vs anomalous traffic.",
}

selected_model = st.selectbox(
    label="Choose a model",
    options=list(MODEL_INFO.keys()),
    index=0,
)
st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="fade-up delay-3">', unsafe_allow_html=True)
st.info(f"**{selected_model}:** {MODEL_INFO[selected_model]}")
st.markdown('</div>', unsafe_allow_html=True)

st.divider()

# ── Scan Mode ─────────────────────────────────────────────────────────────────
st.markdown('<div class="fade-up delay-4">', unsafe_allow_html=True)
scan_mode = st.radio("Scan Mode", ["Dataset", "Live Traffic", "Upload CSV"], horizontal=True)

live_duration, live_iface, uploaded_df = 10, None, None
if scan_mode == "Live Traffic":
    st.warning("⚠️ Live capture requires root/admin privileges.")
    if selected_model == "Isolation Forest":
        st.error("🚫 Isolation Forest is not reliable for live traffic — it will flag ~50% of flows regardless of actual threat. Use Random Forest or One-Class SVM instead.")
    live_duration = st.slider("Capture duration (seconds)", 5, 60, 10)
    live_iface = st.text_input("Network interface (leave blank for default)", value="") or None
elif scan_mode == "Upload CSV":
    from core.preprocessor import REQUIRED_COLUMNS
    uploaded_file = st.file_uploader("Upload a CSV file", type="csv")
    if uploaded_file:
        import pandas as pd
        uploaded_df = pd.read_csv(uploaded_file)
        missing = [c for c in REQUIRED_COLUMNS if c not in uploaded_df.columns]
        extra = [c for c in uploaded_df.columns if c not in REQUIRED_COLUMNS]
        if missing or extra:
            if missing:
                st.error(f"❌ Missing columns ({len(missing)}): `{'`, `'.join(missing)}`")
            if extra:
                st.warning(f"⚠️ Unexpected columns will be ignored: `{'`, `'.join(extra)}`")
            uploaded_df = None
        else:
            st.success(f"✅ CSV valid — {len(uploaded_df)} rows, 38 features. Ready to scan.")

scan_clicked = st.button("🔍 Scan Network", use_container_width=True, type="primary")
st.markdown('</div>', unsafe_allow_html=True)


def _show_results(result: dict, scan_mode: str, selected_model: str):
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd
    from sklearn.metrics import confusion_matrix, roc_curve, auc

    predictions = result["predictions"]
    y_true = result.get("y_true")
    total = result["total_samples"]
    anomalies = result["anomalies_detected"]
    normal = result["normal_count"]

    # ── Summary metrics ───────────────────────────────────────────────────────
    st.divider()
    st.subheader("Scan Results")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Samples", total)
    col2.metric("Anomalies Detected", anomalies, delta_color="inverse")
    col3.metric("Normal Traffic", normal)

    threat_pct = anomalies / total * 100
    if threat_pct > 20:
        st.error(f"⚠️ High anomaly rate detected: {threat_pct:.1f}% of traffic flagged as suspicious.")
    elif threat_pct > 5:
        st.warning(f"🟡 Moderate anomaly rate: {threat_pct:.1f}% of traffic flagged.")
    else:
        st.success(f"✅ Network looks healthy. Only {threat_pct:.1f}% anomalies detected.")

    # ── Performance metrics (dataset mode only) ───────────────────────────────
    if result["metrics"]:
        st.divider()
        st.subheader("Model Performance Metrics")
        m = result["metrics"]
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Accuracy", f"{m['accuracy'] * 100:.2f}%")
        mc2.metric("Precision", f"{m['precision'] * 100:.2f}%")
        mc3.metric("Recall", f"{m['recall'] * 100:.2f}%")
        mc4.metric("F1 Score", f"{m['f1_score'] * 100:.2f}%")

    st.divider()
    st.subheader("Visualizations")

    # ── Chart 1: Prediction distribution (all modes) ──────────────────────────
    col_a, col_b = st.columns(2)
    with col_a:
        fig_donut = go.Figure(go.Pie(
            labels=["Normal", "Anomaly"],
            values=[normal, anomalies],
            hole=0.5,
            marker_colors=["#2ecc71", "#e74c3c"],
        ))
        fig_donut.update_layout(title="Prediction Distribution", showlegend=True, margin=dict(t=40, b=0))
        st.plotly_chart(fig_donut, use_container_width=True)

    # ── Chart 2: Actual vs Predicted bar (dataset mode) / live stats ──────────
    with col_b:
        if y_true is not None:
            actual_normal = int((y_true == 1).sum())
            actual_anomaly = int((y_true == -1).sum())
            fig_bar = go.Figure(data=[
                go.Bar(name="Actual",    x=["Normal", "Anomaly"], y=[actual_normal, actual_anomaly],    marker_color=["#27ae60", "#c0392b"]),
                go.Bar(name="Predicted", x=["Normal", "Anomaly"], y=[normal,        anomalies], marker_color=["#2ecc71", "#e74c3c"]),
            ])
            fig_bar.update_layout(title="Actual vs Predicted", barmode="group", margin=dict(t=40, b=0))
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            anomaly_rate = anomalies / total
            threat_score = min(anomaly_rate * 2, 1.0)
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=round(threat_score * 100, 1),
                number={"suffix": "%"},
                title={"text": "Threat Score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#e74c3c"},
                    "steps": [
                        {"range": [0, 20],  "color": "#2ecc71"},
                        {"range": [20, 50], "color": "#f39c12"},
                        {"range": [50, 100],"color": "#e74c3c"},
                    ],
                },
            ))
            fig_gauge.update_layout(margin=dict(t=40, b=0))
            st.plotly_chart(fig_gauge, use_container_width=True)

    # ── Chart 3: Confusion matrix (dataset mode only) ─────────────────────────
    if y_true is not None:
        col_c, col_d = st.columns(2)
        with col_c:
            cm = confusion_matrix(y_true, predictions, labels=[1, -1])
            fig_cm = go.Figure(go.Heatmap(
                z=cm,
                x=["Pred Normal", "Pred Anomaly"],
                y=["Actual Normal", "Actual Anomaly"],
                colorscale="Reds",
                text=cm, texttemplate="%{text}",
                showscale=False,
            ))
            fig_cm.update_layout(title="Confusion Matrix", margin=dict(t=40, b=0))
            st.plotly_chart(fig_cm, use_container_width=True)

        # ── Chart 4: ROC Curve ────────────────────────────────────────────────
        with col_d:
            fpr, tpr, _ = roc_curve(y_true, predictions, pos_label=-1)
            roc_auc = auc(fpr, tpr)
            fig_roc = go.Figure()
            fig_roc.add_trace(go.Scatter(x=fpr, y=tpr, mode="lines", name=f"AUC = {roc_auc:.3f}", line=dict(color="#e74c3c", width=2)))
            fig_roc.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="Random", line=dict(color="gray", dash="dash")))
            fig_roc.update_layout(title="ROC Curve", xaxis_title="False Positive Rate", yaxis_title="True Positive Rate", margin=dict(t=40, b=0))
            st.plotly_chart(fig_roc, use_container_width=True)

    # ── Chart 5: Feature distribution (CSV mode only) ────────────────────────
    if scan_mode == "Upload CSV" and result.get("df") is not None:
        df = result["df"].copy()
        df["label"] = ["Anomaly" if p == -1 else "Normal" for p in predictions]
        top_features = ["serror_rate", "src_bytes", "num_failed_logins", "dst_bytes", "rerror_rate", "count"]
        st.markdown("**Feature Distribution by Predicted Label**")
        cols = st.columns(3)
        for i, feat in enumerate(top_features):
            if feat in df.columns:
                fig_hist = px.histogram(
                    df, x=feat, color="label",
                    color_discrete_map={"Normal": "#2ecc71", "Anomaly": "#e74c3c"},
                    barmode="overlay", opacity=0.7,
                    title=feat,
                )
                fig_hist.update_layout(showlegend=(i == 0), margin=dict(t=40, b=0))
                cols[i % 3].plotly_chart(fig_hist, use_container_width=True)


if scan_clicked:
    try:
        if scan_mode == "Dataset":
            from core.predictor import run_detection
            with st.spinner(f"Running {selected_model} on KDD Cup 99 & IoT-23 datasets..."):
                result = run_detection(selected_model)
        elif scan_mode == "Live Traffic":
            from core.predictor import run_live_detection
            with st.spinner(f"Capturing live traffic for {live_duration}s..."):
                result = run_live_detection(selected_model, duration=live_duration, iface=live_iface)
        else:
            if uploaded_df is None:
                st.error("Please upload a valid CSV file before scanning.")
                st.stop()
            from core.predictor import run_csv_detection
            with st.spinner(f"Running {selected_model} on uploaded CSV..."):
                result = run_csv_detection(selected_model, uploaded_df)
        _show_results(result, scan_mode, selected_model)
    except FileNotFoundError as e:
        st.error(str(e))
    except Exception as e:
        st.error(f"An error occurred during detection: {e}")
