import glob
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict
from sklearn.preprocessing import StandardScaler

DATASETS_DIR = Path(__file__).parent.parent / "datasets"

# KDD-99 features (38) — connection-level statistical features
KDD_NUMERIC_FEATURES = [
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

# IoT-23 features excluding "duration" which is shared with KDD (30 unique)
IOT_NUMERIC_FEATURES = [
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

# IoT features that are NOT in KDD (excludes shared "duration")
IOT_ONLY_FEATURES = [f for f in IOT_NUMERIC_FEATURES if f not in KDD_NUMERIC_FEATURES]

# Union feature space: 38 KDD + 30 IoT-only = 68 total
COMBINED_FEATURES = KDD_NUMERIC_FEATURES + IOT_ONLY_FEATURES
N_FEATURES = len(COMBINED_FEATURES)  # 68


def load_kdd() -> tuple[np.ndarray, np.ndarray]:
    train = pd.read_csv(DATASETS_DIR / "kdd-99-cup" / "Train_data.csv")
    test  = pd.read_csv(DATASETS_DIR / "kdd-99-cup" / "Test_data.csv")
    df    = pd.concat([train, test], ignore_index=True)
    y     = np.where(df["class"] == "normal", 1, -1)
    # Fill KDD slots, IoT-only slots stay 0
    out        = pd.DataFrame(0.0, index=df.index, columns=COMBINED_FEATURES)
    out[KDD_NUMERIC_FEATURES] = df[KDD_NUMERIC_FEATURES].fillna(0).values
    return out.values, y


def load_iot() -> tuple[np.ndarray, np.ndarray]:
    files = glob.glob(str(DATASETS_DIR / "iot-23" / "*.csv"))
    dfs   = [pd.read_csv(f, sep="|", low_memory=False) for f in files]
    df    = pd.concat(dfs, ignore_index=True)
    y     = np.where(df["label"].astype(str) == "0", 1, -1)
    # Fill IoT slots, KDD-only slots stay 0
    out = pd.DataFrame(0.0, index=df.index, columns=COMBINED_FEATURES)
    for feat in IOT_NUMERIC_FEATURES:
        if feat in df.columns:
            out[feat] = pd.to_numeric(df[feat], errors="coerce").fillna(0).values
    return out.values, y


def load_combined() -> tuple[np.ndarray, np.ndarray]:
    X_kdd, y_kdd = load_kdd()
    X_iot, y_iot = load_iot()

    X = np.vstack([X_kdd, X_iot])
    y = np.concatenate([y_kdd, y_iot])

    # Balance classes
    rng         = np.random.default_rng(42)
    normal_idx  = np.where(y == 1)[0]
    anomaly_idx = np.where(y == -1)[0]
    n           = min(len(normal_idx), len(anomaly_idx))
    idx         = np.concatenate([rng.choice(normal_idx, n, replace=False), rng.choice(anomaly_idx, n, replace=False)])
    return X[idx], y[idx]


def scale(X_train: np.ndarray, X_test: np.ndarray) -> tuple[np.ndarray, np.ndarray, StandardScaler]:
    scaler = StandardScaler()
    return scaler.fit_transform(X_train), scaler.transform(X_test), scaler


def load_kdd_multiclass() -> tuple[np.ndarray, np.ndarray]:
    train = pd.read_csv(DATASETS_DIR / "kdd-99-cup" / "Train_data.csv")
    test  = pd.read_csv(DATASETS_DIR / "kdd-99-cup" / "Test_data.csv")
    df    = pd.concat([train, test], ignore_index=True)
    df    = df.dropna(subset=["class"])
    y     = df["class"].str.strip().values
    out   = pd.DataFrame(0.0, index=df.index, columns=COMBINED_FEATURES)
    out[KDD_NUMERIC_FEATURES] = df[KDD_NUMERIC_FEATURES].fillna(0).values
    return out.values, y


def load_iot_multiclass() -> tuple[np.ndarray, np.ndarray]:
    files = glob.glob(str(DATASETS_DIR / "iot-23" / "*.csv"))
    dfs   = [pd.read_csv(f, sep="|", low_memory=False) for f in files]
    df    = pd.concat(dfs, ignore_index=True)
    # Use multi-label for attack type names, map benign to "normal"
    y = df["multi-label"].fillna("Unknown").astype(str).str.strip()
    y = y.replace("nan", "Unknown")
    y = y.where(df["label"].astype(str) != "0", "normal").values
    out   = pd.DataFrame(0.0, index=df.index, columns=COMBINED_FEATURES)
    for feat in IOT_NUMERIC_FEATURES:
        if feat in df.columns:
            out[feat] = pd.to_numeric(df[feat], errors="coerce").fillna(0).values
    return out.values, y


def load_combined_multiclass() -> tuple[np.ndarray, np.ndarray]:
    X_kdd, y_kdd = load_kdd_multiclass()
    X_iot, y_iot = load_iot_multiclass()

    X = np.vstack([X_kdd, X_iot])
    y = np.concatenate([y_kdd, y_iot]).astype(str)

    # Balance: undersample each class to max 50k samples
    rng     = np.random.default_rng(42)
    indices = []
    for cls in np.unique(y):
        cls_idx = np.where(y == cls)[0]
        n       = min(len(cls_idx), 50_000)
        indices.append(rng.choice(cls_idx, n, replace=False))
    idx = np.concatenate(indices)
    return X[idx], y[idx]


# CSV upload accepts the full 68-feature union
REQUIRED_COLUMNS = COMBINED_FEATURES


def load_uploaded_csv(df: pd.DataFrame) -> np.ndarray:
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    extra   = [c for c in df.columns if c not in REQUIRED_COLUMNS]
    if missing or extra:
        raise ValueError(
            (f"Missing columns: {missing}. " if missing else "") +
            (f"Unexpected columns: {extra}."  if extra   else "")
        )
    X      = df[REQUIRED_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0).values
    scaler = pickle.load(open(Path(__file__).parent.parent / "saved_models" / "scaler.pkl", "rb"))
    return scaler.transform(X)


def capture_live_traffic(duration: int = 10, iface: str = None) -> np.ndarray:
    """
    Capture live traffic using cross-platform packet capture.
    Delegates to platform-specific implementation.
    """
    from core.packet_capture import capture_live_traffic_cross_platform
    return capture_live_traffic_cross_platform(duration, iface)
