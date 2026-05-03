import glob
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.callbacks import EarlyStopping


# ── Load KDD-99 dataset ───────────────────────────────────────────────────────
train_df = pd.read_csv("../datasets/kdd-99-cup/Train_data.csv")
test_df  = pd.read_csv("../datasets/kdd-99-cup/Test_data.csv")
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
iot_files = glob.glob("../datasets/iot-23/*.csv")
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


# ── Combine and balance datasets ──────────────────────────────────────────────
X_iot = np.pad(X_iot, ((0, 0), (0, X_kdd.shape[1] - X_iot.shape[1])))

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


# ── Build Autoencoder ─────────────────────────────────────────────────────────
input_dim    = X_train.shape[1]
encoding_dim = max(8, input_dim // 4)

inputs  = Input(shape=(input_dim,))
encoded = Dense(encoding_dim * 2, activation="relu")(inputs)
encoded = Dense(encoding_dim,     activation="relu")(encoded)
decoded = Dense(encoding_dim * 2, activation="relu")(encoded)
outputs = Dense(input_dim,        activation="linear")(decoded)

autoencoder = Model(inputs, outputs)
autoencoder.compile(optimizer="adam", loss="mse")

autoencoder.summary()


# ── Train on normal samples only ──────────────────────────────────────────────
X_normal = X_train[y_train == 1]

autoencoder.fit(
    X_normal, X_normal,
    epochs=30,
    batch_size=256,
    validation_split=0.1,
    callbacks=[EarlyStopping(patience=3, restore_best_weights=True)],
    verbose=1,
)


# ── Compute reconstruction error threshold (95th percentile) ─────────────────
reconstructions = autoencoder.predict(X_normal, verbose=0)
train_mse       = np.mean(np.power(X_normal - reconstructions, 2), axis=1)
threshold       = np.percentile(train_mse, 95)

print("\nReconstruction error threshold (95th percentile):", round(threshold, 6))


# ── Predict ───────────────────────────────────────────────────────────────────
reconstructions = autoencoder.predict(X_test, verbose=0)
test_mse        = np.mean(np.power(X_test - reconstructions, 2), axis=1)
predictions     = np.where(test_mse > threshold, -1, 1)

print("\nPredictions (1 = Normal, -1 = Anomaly):")
print(predictions)

print("\nAccuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")
print("\nClassification Report:")
print(classification_report(y_test, predictions, target_names=["Anomaly (-1)", "Normal (1)"]))
