import time
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, accuracy_score, precision_score,
    recall_score, f1_score, confusion_matrix, roc_curve, auc
)

DATASETS_DIR = "<dataset path here>"


# ── Load KDD-99 dataset ───────────────────────────────────────────────────────
train_df = pd.read_csv(f"{DATASETS_DIR}/kdd-99-cup/Train_data.csv")
test_df  = pd.read_csv(f"{DATASETS_DIR}/kdd-99-cup/Test_data.csv")
kdd_df   = pd.concat([train_df, test_df], ignore_index=True)

KDD_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

X_kdd = kdd_df[KDD_FEATURES].fillna(0).values
y_kdd = np.where(kdd_df["class"] == "normal", 1, -1)


# ── Load IoT-23 dataset ───────────────────────────────────────────────────────
iot_files = glob.glob(f"{DATASETS_DIR}/iot-23/*.csv")
iot_dfs   = [pd.read_csv(f, sep="|", low_memory=False) for f in iot_files]
iot_df    = pd.concat(iot_dfs, ignore_index=True)

IOT_FEATURES = [
    "duration", "orig_bytes", "resp_bytes", "missed_bytes",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "proto_icmp", "proto_tcp", "proto_udp",
    "service_-", "service_dhcp", "service_dns", "service_http",
    "service_irc", "service_ssh", "service_ssl",
    "conn_state_OTH", "conn_state_REJ", "conn_state_RSTO", "conn_state_RSTOS0",
    "conn_state_RSTR", "conn_state_RSTRH", "conn_state_S0", "conn_state_S1",
    "conn_state_S2", "conn_state_S3", "conn_state_SF", "conn_state_SH",
    "conn_state_SHR",
]

X_iot = iot_df[IOT_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0).values
y_iot = np.where(iot_df["label"].astype(str) == "0", 1, -1)


# ── Build union feature space (68 features) ───────────────────────────────────
KDD_FEATURES_SET  = set(KDD_FEATURES)
IOT_ONLY          = [f for f in IOT_FEATURES if f not in KDD_FEATURES_SET]
COMBINED_FEATURES = KDD_FEATURES + IOT_ONLY

kdd_out = pd.DataFrame(0.0, index=range(len(kdd_df)), columns=COMBINED_FEATURES)
kdd_out[KDD_FEATURES] = kdd_df[KDD_FEATURES].fillna(0).values
X_kdd = kdd_out.values

iot_out = pd.DataFrame(0.0, index=range(len(iot_df)), columns=COMBINED_FEATURES)
for feat in IOT_FEATURES:
    if feat in iot_df.columns:
        iot_out[feat] = pd.to_numeric(iot_df[feat], errors="coerce").fillna(0).values
X_iot = iot_out.values

X = np.vstack([X_kdd, X_iot])
y = np.concatenate([y_kdd, y_iot])

rng         = np.random.default_rng(42)
normal_idx  = np.where(y == 1)[0]
anomaly_idx = np.where(y == -1)[0]
n           = min(len(normal_idx), len(anomaly_idx))
idx         = np.concatenate([rng.choice(normal_idx, n, replace=False), rng.choice(anomaly_idx, n, replace=False)])
X, y        = X[idx], y[idx]

print("Total samples:", len(X), "| Normal:", np.sum(y == 1), "| Anomaly:", np.sum(y == -1))


# ── Train/test split and scaling ──────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler  = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)


# ── Train Isolation Forest (on normal samples only) ───────────────────────────
model = IsolationForest(n_estimators=100, max_samples=0.5, contamination=0.5, random_state=42, n_jobs=-1)

model.fit(X_train[y_train == 1])


# ── Predict + inference time ──────────────────────────────────────────────────
t0          = time.perf_counter()
predictions = model.predict(X_test)
inf_time    = (time.perf_counter() - t0) * 1000

print(f"\nInference Time: {inf_time:.1f} ms")
print("Anomalies Detected:", np.sum(predictions == -1))
print("Normal Traffic:    ", np.sum(predictions == 1))
print("\nAccuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")
print("\nClassification Report:")
print(classification_report(y_test, predictions, target_names=["Anomaly (-1)", "Normal (1)"]))


# ── Anomaly scores ────────────────────────────────────────────────────────────
scores = -model.decision_function(X_test)


# ── Visualizations ────────────────────────────────────────────────────────────
fig, axes = plt.subplots(2, 3, figsize=(18, 10))
fig.suptitle("Isolation Forest — Results", fontsize=16)

# 1. Anomaly count bar chart
axes[0, 0].bar(["Normal", "Anomaly"], [np.sum(predictions == 1), np.sum(predictions == -1)],
               color=["#2ecc71", "#e74c3c"])
axes[0, 0].set_title("Anomaly Count")
axes[0, 0].set_ylabel("Count")

# 2. Precision / Recall / F1
metrics = [
    precision_score(y_test, predictions, pos_label=-1, zero_division=0),
    recall_score(y_test, predictions, pos_label=-1, zero_division=0),
    f1_score(y_test, predictions, pos_label=-1, zero_division=0),
]
axes[0, 1].bar(["Precision", "Recall", "F1 Score"], metrics, color=["#3498db", "#9b59b6", "#e67e22"])
axes[0, 1].set_ylim(0, 1)
axes[0, 1].set_title("Precision / Recall / F1")
for i, v in enumerate(metrics):
    axes[0, 1].text(i, v + 0.01, f"{v:.2f}", ha="center")

# 3. Confusion matrix heatmap
cm = confusion_matrix(y_test, predictions, labels=[1, -1])
im = axes[0, 2].imshow(cm, cmap="Reds")
axes[0, 2].set_xticks([0, 1]); axes[0, 2].set_yticks([0, 1])
axes[0, 2].set_xticklabels(["Pred Normal", "Pred Anomaly"])
axes[0, 2].set_yticklabels(["Actual Normal", "Actual Anomaly"])
axes[0, 2].set_title("Confusion Matrix")
for i in range(2):
    for j in range(2):
        axes[0, 2].text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=12)
plt.colorbar(im, ax=axes[0, 2])

# 4. ROC Curve
fpr, tpr, _ = roc_curve(y_test, predictions, pos_label=-1)
roc_auc     = auc(fpr, tpr)
axes[1, 0].plot(fpr, tpr, color="#e74c3c", lw=2, label=f"AUC = {roc_auc:.3f}")
axes[1, 0].plot([0, 1], [0, 1], color="gray", linestyle="--")
axes[1, 0].set_xlabel("False Positive Rate")
axes[1, 0].set_ylabel("True Positive Rate")
axes[1, 0].set_title("ROC Curve")
axes[1, 0].legend()

# 5. Anomaly score distribution — Normal flows
normal_scores  = scores[predictions == 1]
anomaly_scores = scores[predictions == -1]
axes[1, 1].hist(normal_scores,  bins=50, color="#2ecc71", alpha=0.7, label="Normal")
axes[1, 1].hist(anomaly_scores, bins=50, color="#e74c3c", alpha=0.7, label="Anomaly")
axes[1, 1].set_title("Anomaly Score Distribution")
axes[1, 1].set_xlabel("Anomaly Score")
axes[1, 1].set_ylabel("Count")
axes[1, 1].legend()

# 6. Inference time display
axes[1, 2].axis("off")
axes[1, 2].text(0.5, 0.6, f"Inference Time", ha="center", va="center", fontsize=14)
axes[1, 2].text(0.5, 0.4, f"{inf_time:.1f} ms", ha="center", va="center", fontsize=28, color="#e74c3c", fontweight="bold")
axes[1, 2].text(0.5, 0.25, f"on {len(X_test):,} samples", ha="center", va="center", fontsize=11, color="gray")

plt.tight_layout()
plt.show()
