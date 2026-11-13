import base64
import numpy as np
from pathlib import Path
import streamlit as st

# Attack types that are DDoS-related
DDOS_ATTACKS = {
    "DDoS", "C&C-HeartBeat-Attack", "Attack", "Okiru-Attack",
    "PartOfAHorizontalPortScan-Attack", "C&C", "C&C-HeartBeat",
    "C&C-Mirai", "C&C-Torii", "Okiru", "PartOfAHorizontalPortScan",
    "C&C-PartOfAHorizontalPortScan", "C&C-FileDownload",
    "C&C-HeartBeat-FileDownload", "FileDownload", "anomaly",
}


def _format_attack(attack: str) -> str:
    """Return display label: DDoS Attack — <subtype> if DDoS-related, else the raw name."""
    if attack in DDOS_ATTACKS:
        return f"DDoS Attack — {attack}"
    return attack


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
    "Random Forest": "Ensemble classifier trained to distinguish normal vs anomalous traffic.",
}

# Show info about Autoencoder being unavailable
with st.expander("ℹ️ Why is Autoencoder unavailable?", expanded=False):
    st.warning("""
    **Autoencoder (TensorFlow) is not available on Python 3.15**
    
    TensorFlow does not yet have wheels compiled for Python 3.15. 
    To use the Autoencoder model, you would need to:
    1. Downgrade Python to 3.11 or 3.12
    2. Reinstall the virtual environment
    
    For now, use one of the available models above which work perfectly on Python 3.15.
    """)

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

# ── Agent Mode Toggle ─────────────────────────────────────────────────────────
st.markdown('<div class="fade-up delay-4">', unsafe_allow_html=True)
st.subheader("Threat Mitigation")

col_agent_toggle, col_agent_info = st.columns([1, 2])
with col_agent_toggle:
    agent_mode_enabled = st.toggle("🤖 Agent Mode", value=False, key="agent_mode_toggle")

with col_agent_info:
    if agent_mode_enabled:
        st.success("🟢 Agent mode enabled — will mitigate detected threats")
    else:
        st.info("🔵 Agent mode disabled — anomalies will only be detected")

st.markdown('</div>', unsafe_allow_html=True)

# ── Agent Configuration ────────────────────────────────────────────────────────
if agent_mode_enabled:
    st.markdown('<div class="fade-up delay-5">', unsafe_allow_html=True)
    with st.expander("⚙️ Agent Configuration", expanded=False):
        agent_auto_execute = st.checkbox(
            "Auto-execute mitigations (requires approval for destructive actions)",
            value=False,
            help="If unchecked, all mitigations will be executed in dry-run mode (simulation only)"
        )
        agent_dry_run = st.checkbox(
            "Dry-run mode (simulate without executing)",
            value=True,
            help="Enable to test mitigation plans without actually running commands"
        )
        st.info("""
        **Agent Configuration:**
        - Auto-execute: Automatically execute mitigation plans
        - Dry-run: Simulate actions without actually executing them
        - Requires elevation: Most actions need admin/root privileges
        """)
    st.markdown('</div>', unsafe_allow_html=True)
else:
    agent_auto_execute = False
    agent_dry_run = True

# ── Scan Mode ─────────────────────────────────────────────────────────────────
st.markdown('<div class="fade-up delay-6">', unsafe_allow_html=True)
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
    import pandas as pd
    from sklearn.metrics import confusion_matrix, roc_curve, auc

    predictions    = result["predictions"]
    y_true         = result.get("y_true")
    total          = result["total_samples"]
    anomalies      = result["anomalies_detected"]
    normal         = result["normal_count"]
    scores         = result.get("anomaly_scores")
    inference_time = result.get("inference_time", 0)

    # ── Summary ─────────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("Scan Results")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Samples", total)
    col2.metric("Anomalies Detected", anomalies, delta_color="inverse")
    col3.metric("Normal Traffic", normal)
    col4.metric("Inference Time", f"{inference_time * 1000:.1f} ms")

    threat_pct = anomalies / total * 100
    if threat_pct > 20:
        st.error(f"⚠️ High anomaly rate detected: {threat_pct:.1f}% of traffic flagged as suspicious.")
    elif threat_pct > 5:
        st.warning(f"🟡 Moderate anomaly rate: {threat_pct:.1f}% of traffic flagged.")
    else:
        st.success(f"✅ Network looks healthy. Only {threat_pct:.1f}% anomalies detected.")

    # ── Performance metrics ───────────────────────────────────────────────────────
    if result["metrics"]:
        st.divider()
        st.subheader("Model Performance Metrics")
        m = result["metrics"]
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Accuracy",  f"{m['accuracy']  * 100:.2f}%")
        mc2.metric("Precision", f"{m['precision'] * 100:.2f}%")
        mc3.metric("Recall",    f"{m['recall']    * 100:.2f}%")
        mc4.metric("F1 Score",  f"{m['f1_score']  * 100:.2f}%")

    st.divider()
    st.subheader("Visualizations")

    # ── Row 1: Prediction distribution + Actual vs Predicted / Threat Score ────
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Anomaly Count**")
        st.bar_chart(pd.DataFrame({"Count": [normal, anomalies]}, index=["Normal", "Anomaly"]))

    with col_b:
        if y_true is not None:
            st.markdown("**Actual vs Predicted**")
            st.bar_chart(pd.DataFrame({
                "Actual":    [int((y_true == 1).sum()),  int((y_true == -1).sum())],
                "Predicted": [normal, anomalies],
            }, index=["Normal", "Anomaly"]))
        else:
            threat_score = min((anomalies / total) * 2, 1.0) * 100
            st.markdown("**Threat Score**")
            st.metric(label="", value=f"{threat_score:.1f}%",
                delta="High Risk" if threat_score > 50 else ("Moderate" if threat_score > 20 else "Low Risk"),
                delta_color="inverse")

    # ── Row 2: Confusion matrix + ROC curve (dataset mode only) ───────────────
    if y_true is not None:
        col_c, col_d = st.columns(2)
        with col_c:
            cm = confusion_matrix(y_true, predictions, labels=[1, -1])
            st.markdown("**Confusion Matrix**")
            st.dataframe(pd.DataFrame(
                cm,
                index=["Actual Normal", "Actual Anomaly"],
                columns=["Pred Normal", "Pred Anomaly"],
            ))

        with col_d:
            fpr, tpr, _ = roc_curve(y_true, predictions, pos_label=-1)
            roc_auc = auc(fpr, tpr)
            st.markdown(f"**ROC Curve** — AUC = {roc_auc:.3f}")
            st.line_chart(pd.DataFrame({"TPR (True Positive Rate)": tpr}, index=fpr))

        # ── Row 3: Precision / Recall / F1 bar chart ──────────────────────────
        m = result["metrics"]
        st.markdown("**Precision / Recall / F1**")
        st.bar_chart(pd.DataFrame({
            "Score": [m["precision"], m["recall"], m["f1_score"]]
        }, index=["Precision", "Recall", "F1 Score"]))

    # ── Row 4: Anomaly score distribution ─────────────────────────────────
    if scores is not None:
        st.markdown("**Anomaly Score Distribution**")
        sample = min(2000, len(scores))
        idx    = np.random.choice(len(scores), sample, replace=False)
        score_df = pd.DataFrame({
            "Anomaly Score": scores[idx],
            "Label": ["Anomaly" if predictions[i] == -1 else "Normal" for i in idx],
        }).sort_values("Anomaly Score")
        normal_scores  = score_df[score_df["Label"] == "Normal"]["Anomaly Score"]
        anomaly_scores = score_df[score_df["Label"] == "Anomaly"]["Anomaly Score"]
        col_e, col_f = st.columns(2)
        with col_e:
            st.markdown("*Normal flows*")
            st.line_chart(normal_scores.reset_index(drop=True))
        with col_f:
            st.markdown("*Anomalous flows*")
            st.line_chart(anomaly_scores.reset_index(drop=True))

    # ── Feature averages (CSV mode only) ──────────────────────────────────
    if scan_mode == "Upload CSV" and result.get("df") is not None:
        df = result["df"].copy()
        df["label"] = ["Anomaly" if p == -1 else "Normal" for p in predictions]
        top_features = ["serror_rate", "src_bytes", "num_failed_logins", "dst_bytes", "rerror_rate", "count"]
        st.markdown("**Feature Averages by Predicted Label**")
        st.bar_chart(df.groupby("label")[top_features].mean().T)


if scan_clicked:
    try:
        if scan_mode == "Dataset":
            from core.predictor import run_detection, run_multiclass_detection
            with st.spinner(f"Running {selected_model} on KDD Cup 99 & IoT-23 datasets..."):
                result = run_detection(selected_model)
            _show_results(result, scan_mode, selected_model)

            # ── Agent Mitigation (Dataset Mode) ─────────────────────────────────────
            if agent_mode_enabled and result["anomalies_detected"] > 0:
                from agent_integration import (
                    detection_result_to_threat,
                    trigger_agent_mitigation,
                    format_mitigation_result
                )
                
                st.divider()
                st.subheader("🤖 Threat Mitigation Agent")
                
                with st.spinner("Analyzing threat and generating mitigation plan..."):
                    threat = detection_result_to_threat(
                        predictions=result["predictions"],
                        total_samples=result["total_samples"],
                        anomalies_detected=result["anomalies_detected"],
                        anomaly_scores=result.get("anomaly_scores"),
                        raw_data={"model": selected_model}
                    )
                    
                    plan, mitigation_results = trigger_agent_mitigation(
                        threat=threat,
                        auto_execute=agent_auto_execute,
                        dry_run=agent_dry_run
                    )
                
                if plan:
                    st.success(f"✅ Mitigation plan generated: {plan.plan_id}")
                    
                    # Show plan details
                    with st.expander("📋 Mitigation Plan Details", expanded=True):
                        st.write(f"**Threat Type:** {plan.threat_type.value}")
                        st.write(f"**Threat ID:** {threat.threat_id}")
                        st.write(f"**Confidence:** {threat.confidence*100:.1f}%")
                        st.write(f"**Number of Actions:** {len(plan.actions)}")
                        
                        if plan.actions:
                            st.write("**Planned Actions:**")
                            for i, action in enumerate(plan.actions, 1):
                                st.write(f"\n{i}. **{action.action_type}** on `{action.target}`")
                                st.write(f"   - Reason: {action.reason}")
                                st.write(f"   - Reversible: {'Yes' if action.reversible else 'No'}")
                                if action.timeout_seconds:
                                    st.write(f"   - Auto-expires in: {action.timeout_seconds}s")
                    
                    # Show results
                    if mitigation_results:
                        st.markdown(format_mitigation_result(plan, mitigation_results))
                        
                        with st.expander("📊 Action Execution Details", expanded=False):
                            for result in mitigation_results:
                                status = "✅" if result.success else "❌"
                                st.write(f"{status} {result.action_id}")
                                st.write(f"Execution time: {result.execution_time_ms:.2f}ms")
                                if result.error:
                                    st.error(f"Error: {result.error}")
                else:
                    st.warning("⚠️ No mitigation plan generated for this threat")

            # Show attack type breakdown for Random Forest
            if selected_model == "Random Forest":
                import pandas as pd
                with st.spinner("Running attack type classification..."):
                    mc_result = run_multiclass_detection()
                st.divider()
                st.subheader("🔍 Attack Type Classification")
                st.caption("Random Forest multiclass model — identifies specific attack categories")

                attack_counts = mc_result["attack_counts"]
                normal_count  = attack_counts.pop("normal", 0)
                sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)

                # Metrics row
                a1, a2, a3 = st.columns(3)
                a1.metric("Total Flows",     mc_result["total_samples"])
                a2.metric("Normal",          normal_count)
                a3.metric("Anomalous Flows", mc_result["anomalies_detected"])

                # Attack type bar chart
                if sorted_attacks:
                    st.markdown("**Detected Attack Types**")
                    display_attacks = [(_format_attack(k), v) for k, v in sorted_attacks]
                    attack_df = pd.DataFrame(display_attacks, columns=["Attack Type", "Count"]).set_index("Attack Type")
                    st.bar_chart(attack_df)

                    # Attack type table
                    st.markdown("**Breakdown**")
                    attack_df["% of Anomalies"] = (attack_df["Count"] / mc_result["anomalies_detected"] * 100).round(2).astype(str) + "%"
                    st.dataframe(attack_df, use_container_width=True)
                else:
                    st.success("✅ No attack types detected — all traffic classified as normal.")
        elif scan_mode == "Live Traffic":
            from core.predictor import run_live_window, _load_model
            from models.random_forest import RandomForestMulticlassModel
            import pandas as pd

            WINDOW    = 5
            n_windows = max(1, live_duration // WINDOW)

            model    = _load_model(selected_model)
            mc_model = RandomForestMulticlassModel()
            mc_model.load()

            st.divider()
            st.subheader("🖥️ Live Network Monitor")
            st.caption(f"Capturing {WINDOW}s windows over {live_duration}s total — {n_windows} windows")

            chart_placeholder   = st.empty()
            status_placeholder  = st.empty()
            metrics_placeholder = st.empty()
            attack_placeholder  = st.empty()

            timestamps      = []
            anomaly_rates   = []
            total_flows     = []
            total_anomalies = []
            all_attack_counts = {}

            for i in range(n_windows):
                status_placeholder.info(f"📡 Capturing window {i + 1}/{n_windows}...")
                window_result = run_live_window(model, iface=live_iface, window=WINDOW)

                t_label = f"+{(i + 1) * WINDOW}s"
                rate    = window_result["anomalies_detected"] / max(window_result["total_samples"], 1) * 100
                timestamps.append(t_label)
                anomaly_rates.append(round(rate, 2))
                total_flows.append(window_result["total_samples"])
                total_anomalies.append(window_result["anomalies_detected"])

                # Attack type classification for this window
                attack_label    = "🟢 No Threat"
                attack_html_color = "#2ecc71"
                if window_result["anomalies_detected"] > 0:
                    mc_preds = mc_model.predict(window_result["X_raw"])
                    classes, counts = np.unique(mc_preds, return_counts=True)
                    attack_map = {c: int(n) for c, n in zip(classes, counts) if c != "normal"}
                    if attack_map:
                        top_attack        = max(attack_map, key=attack_map.get)
                        attack_label      = f"🚨 {_format_attack(top_attack)}"
                        attack_html_color = "#e74c3c"
                        for k, v in attack_map.items():
                            display_k = _format_attack(k)
                            all_attack_counts[display_k] = all_attack_counts.get(display_k, 0) + v

                chart_placeholder.line_chart(
                    pd.DataFrame({"Anomaly Rate (%)": anomaly_rates}, index=timestamps)
                )

                mc1, mc2, mc3, mc4 = metrics_placeholder.columns(4)
                mc1.metric("Window",       f"{i + 1}/{n_windows}")
                mc2.metric("Flows",        window_result["total_samples"])
                mc3.metric("Anomalies",    window_result["anomalies_detected"])
                mc4.metric("Anomaly Rate", f"{rate:.1f}%")

                attack_placeholder.markdown(
                    f"""
                    <div style="
                        background-color: {attack_html_color}22;
                        border: 2px solid {attack_html_color};
                        border-radius: 12px;
                        padding: 16px 24px;
                        text-align: center;
                        margin-top: 8px;
                    ">
                        <p style="margin:0; font-size:13px; color:{attack_html_color}; font-weight:600; letter-spacing:1px; text-transform:uppercase;">Detected Attack</p>
                        <p style="margin:4px 0 0 0; font-size:22px; font-weight:700; color:{attack_html_color};">{attack_label}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            status_placeholder.success(f"✅ Monitoring complete — {n_windows} windows captured.")

            # ── Session Summary ───────────────────────────────────────────────────────
            avg_rate = sum(anomaly_rates) / len(anomaly_rates)
            st.divider()
            st.subheader("Session Summary")
            s1, s2, s3, s4 = st.columns(4)
            s1.metric("Total Flows",      sum(total_flows))
            s2.metric("Total Anomalies",  sum(total_anomalies))
            s3.metric("Avg Anomaly Rate", f"{avg_rate:.1f}%")
            s4.metric("Duration",         f"{live_duration}s")

            st.divider()
            st.subheader("🛡️ Network Status Assessment")

            if sum(total_anomalies) == 0:
                st.markdown("""
                    <div style="background:#2ecc7122;border:2px solid #2ecc71;border-radius:12px;padding:20px;text-align:center;">
                        <p style="margin:0;font-size:15px;color:#2ecc71;font-weight:600;text-transform:uppercase;letter-spacing:1px;">✅ All Clear</p>
                        <p style="margin:6px 0 0 0;font-size:20px;font-weight:700;color:#2ecc71;">Network is Safe — No Threats Detected</p>
                    </div>""", unsafe_allow_html=True)
            elif avg_rate > 20:
                st.markdown(f"""
                    <div style="background:#e74c3c22;border:2px solid #e74c3c;border-radius:12px;padding:20px;text-align:center;">
                        <p style="margin:0;font-size:15px;color:#e74c3c;font-weight:600;text-transform:uppercase;letter-spacing:1px;">🚨 High Threat</p>
                        <p style="margin:6px 0 0 0;font-size:20px;font-weight:700;color:#e74c3c;">{avg_rate:.1f}% Anomaly Rate — Immediate Action Recommended</p>
                    </div>""", unsafe_allow_html=True)
            elif avg_rate > 5:
                st.markdown(f"""
                    <div style="background:#f39c1222;border:2px solid #f39c12;border-radius:12px;padding:20px;text-align:center;">
                        <p style="margin:0;font-size:15px;color:#f39c12;font-weight:600;text-transform:uppercase;letter-spacing:1px;">🟡 Moderate Threat</p>
                        <p style="margin:6px 0 0 0;font-size:20px;font-weight:700;color:#f39c12;">{avg_rate:.1f}% Anomaly Rate — Monitor Closely</p>
                    </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                    <div style="background:#2ecc7122;border:2px solid #2ecc71;border-radius:12px;padding:20px;text-align:center;">
                        <p style="margin:0;font-size:15px;color:#2ecc71;font-weight:600;text-transform:uppercase;letter-spacing:1px;">✅ Healthy</p>
                        <p style="margin:6px 0 0 0;font-size:20px;font-weight:700;color:#2ecc71;">Low Threat — {avg_rate:.1f}% Anomaly Rate</p>
                    </div>""", unsafe_allow_html=True)

            # ── Attack type summary ─────────────────────────────────────────────────────
            if all_attack_counts:
                st.divider()
                st.subheader("🔍 Attack Types Detected")
                sorted_attacks = sorted(all_attack_counts.items(), key=lambda x: -x[1])
                attack_df = pd.DataFrame(sorted_attacks, columns=["Attack Type", "Count"]).set_index("Attack Type")
                st.bar_chart(attack_df)
                st.dataframe(attack_df, use_container_width=True)
            else:
                st.info("🟢 No specific attack types identified across the session.")
        else:
            if uploaded_df is None:
                st.error("Please upload a valid CSV file before scanning.")
                st.stop()
            from core.predictor import run_csv_detection
            with st.spinner(f"Running {selected_model} on uploaded CSV..."):
                result = run_csv_detection(selected_model, uploaded_df)
            _show_results(result, scan_mode, selected_model)

            # ── Agent Mitigation (CSV Mode) ────────────────────────────────────────
            if agent_mode_enabled and result["anomalies_detected"] > 0:
                from agent_integration import (
                    detection_result_to_threat,
                    trigger_agent_mitigation,
                    format_mitigation_result
                )
                
                st.divider()
                st.subheader("🤖 Threat Mitigation Agent")
                
                with st.spinner("Analyzing threat and generating mitigation plan..."):
                    threat = detection_result_to_threat(
                        predictions=result["predictions"],
                        total_samples=result["total_samples"],
                        anomalies_detected=result["anomalies_detected"],
                        anomaly_scores=result.get("anomaly_scores"),
                        raw_data={"model": selected_model, "source": "uploaded_csv"}
                    )
                    
                    plan, mitigation_results = trigger_agent_mitigation(
                        threat=threat,
                        auto_execute=agent_auto_execute,
                        dry_run=agent_dry_run
                    )
                
                if plan:
                    st.success(f"✅ Mitigation plan generated: {plan.plan_id}")
                    
                    with st.expander("📋 Mitigation Plan Details", expanded=True):
                        st.write(f"**Threat Type:** {plan.threat_type.value}")
                        st.write(f"**Threat ID:** {threat.threat_id}")
                        st.write(f"**Confidence:** {threat.confidence*100:.1f}%")
                        st.write(f"**Number of Actions:** {len(plan.actions)}")
                        
                        if plan.actions:
                            st.write("**Planned Actions:**")
                            for i, action in enumerate(plan.actions, 1):
                                st.write(f"\n{i}. **{action.action_type}** on `{action.target}`")
                                st.write(f"   - Reason: {action.reason}")
                                st.write(f"   - Reversible: {'Yes' if action.reversible else 'No'}")
                                if action.timeout_seconds:
                                    st.write(f"   - Auto-expires in: {action.timeout_seconds}s")
                    
                    if mitigation_results:
                        st.markdown(format_mitigation_result(plan, mitigation_results))
                else:
                    st.warning("⚠️ No mitigation plan generated for this threat")
    except FileNotFoundError as e:
        st.error(str(e))
    except Exception as e:
        st.error(f"An error occurred during detection: {e}")
