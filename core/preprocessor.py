import glob
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict
from sklearn.preprocessing import StandardScaler

DATASETS_DIR = Path(__file__).parent.parent / "datasets"

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


def load_kdd() -> tuple[np.ndarray, np.ndarray]:
    train = pd.read_csv(DATASETS_DIR / "kdd-99-cup" / "Train_data.csv")
    test = pd.read_csv(DATASETS_DIR / "kdd-99-cup" / "Test_data.csv")
    df = pd.concat([train, test], ignore_index=True)
    y = np.where(df["class"] == "normal", 1, -1)
    X = df[KDD_NUMERIC_FEATURES].fillna(0).values
    return X, y


def load_iot() -> tuple[np.ndarray, np.ndarray]:
    files = glob.glob(str(DATASETS_DIR / "iot-23" / "*.csv"))
    dfs = []
    for f in files:
        df = pd.read_csv(f, sep="|", low_memory=False)
        dfs.append(df)
    df = pd.concat(dfs, ignore_index=True)
    # label: 0 = benign → 1 (normal), 1 = malicious → -1 (anomaly)
    y = np.where(df["label"].astype(str) == "0", 1, -1)
    X = df[IOT_NUMERIC_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0).values
    return X, y


def load_combined() -> tuple[np.ndarray, np.ndarray]:
    X_kdd, y_kdd = load_kdd()
    X_iot, y_iot = load_iot()

    # Pad the smaller feature set to match the larger one
    max_features = max(X_kdd.shape[1], X_iot.shape[1])
    if X_kdd.shape[1] < max_features:
        X_kdd = np.pad(X_kdd, ((0, 0), (0, max_features - X_kdd.shape[1])))
    if X_iot.shape[1] < max_features:
        X_iot = np.pad(X_iot, ((0, 0), (0, max_features - X_iot.shape[1])))

    X = np.vstack([X_kdd, X_iot])
    y = np.concatenate([y_kdd, y_iot])

    # Balance classes: undersample majority to match minority count
    rng = np.random.default_rng(42)
    normal_idx = np.where(y == 1)[0]
    anomaly_idx = np.where(y == -1)[0]
    n = min(len(normal_idx), len(anomaly_idx))
    idx = np.concatenate([rng.choice(normal_idx, n, replace=False), rng.choice(anomaly_idx, n, replace=False)])
    return X[idx], y[idx]


def scale(X_train: np.ndarray, X_test: np.ndarray) -> tuple[np.ndarray, np.ndarray, StandardScaler]:
    scaler = StandardScaler()
    return scaler.fit_transform(X_train), scaler.transform(X_test), scaler


REQUIRED_COLUMNS = KDD_NUMERIC_FEATURES  # exact 38 padded feature names


def load_uploaded_csv(df: pd.DataFrame) -> np.ndarray:
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    extra = [c for c in df.columns if c not in REQUIRED_COLUMNS]
    if missing or extra:
        raise ValueError(
            (f"Missing columns: {missing}. " if missing else "") +
            (f"Unexpected columns: {extra}." if extra else "")
        )
    X = df[REQUIRED_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0).values
    scaler = pickle.load(open(Path(__file__).parent.parent / "saved_models" / "scaler.pkl", "rb"))
    return scaler.transform(X)


def capture_live_traffic(duration: int = 10, iface: str = None) -> np.ndarray:
    from scapy.all import sniff, IP, TCP, UDP, ICMP

    packets = sniff(iface=iface, timeout=duration, store=True)

    flows = defaultdict(lambda: {
        "duration": 0.0, "orig_bytes": 0, "resp_bytes": 0, "missed_bytes": 0,
        "orig_pkts": 0, "orig_ip_bytes": 0, "resp_pkts": 0, "resp_ip_bytes": 0,
        "proto": "other", "start": None, "end": None,
    })

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "icmp" if pkt.haslayer(ICMP) else "other"
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        key = (ip.src, ip.dst, sport, dport, proto)
        f = flows[key]
        t = float(pkt.time)
        if f["start"] is None:
            f["start"] = t
        f["end"] = t
        f["proto"] = proto
        f["orig_pkts"] += 1
        pkt_len = len(pkt)
        f["orig_bytes"] += pkt_len
        f["orig_ip_bytes"] += pkt_len

    if not flows:
        return np.zeros((1, 38))

    rows = []
    for f in flows.values():
        dur = (f["end"] - f["start"]) if (f["start"] is not None and f["end"] != f["start"]) else 0.0
        row = [
            dur, f["orig_bytes"], f["resp_bytes"], f["missed_bytes"],
            f["orig_pkts"], f["orig_ip_bytes"], f["resp_pkts"], f["resp_ip_bytes"],
            int(f["proto"] == "icmp"), int(f["proto"] == "tcp"), int(f["proto"] == "udp"),
            0, 0, 0, 0, 0, 0, 0,  # service_*
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # conn_state_*
            0, 0, 0, 0, 0, 0, 0,  # padding to 38
        ]
        rows.append(row[:38])

    X = np.array(rows, dtype=np.float64)
    scaler = pickle.load(open(Path(__file__).parent.parent / "saved_models" / "scaler.pkl", "rb"))
    return scaler.transform(X)
