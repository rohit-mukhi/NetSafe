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
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
    except ImportError:
        raise RuntimeError("Live capture is not available in this environment. Run the app locally with scapy installed.")

    packets = sniff(iface=iface, timeout=duration, store=True)

    flows = defaultdict(lambda: {
        "start": None, "end": None, "proto": "other",
        "orig_bytes": 0, "resp_bytes": 0, "missed_bytes": 0,
        "orig_pkts": 0,  "orig_ip_bytes": 0,
        "resp_pkts": 0,  "resp_ip_bytes": 0,
        "syn_errors": 0, "rst_errors": 0, "total_pkts": 0,
        "dst": None, "dport": 0,
    })

    # Track per-destination connection counts for KDD-style count/serror_rate
    dst_counts    = defaultdict(int)
    dst_syn_errs  = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip    = pkt[IP]
        proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "icmp" if pkt.haslayer(ICMP) else "other"
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        key   = (ip.src, ip.dst, sport, dport, proto)
        f     = flows[key]
        t     = float(pkt.time)

        if f["start"] is None:
            f["start"] = t
        f["end"]   = t
        f["proto"] = proto
        f["dst"]   = ip.dst
        f["dport"] = dport

        pkt_len         = len(pkt)
        f["orig_pkts"]  += 1
        f["orig_bytes"] += pkt_len
        f["orig_ip_bytes"] += pkt_len
        f["total_pkts"] += 1

        # Detect SYN-only packets (SYN flood signature)
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags == 0x02:  # SYN only
                f["syn_errors"] += 1
                dst_syn_errs[ip.dst] += 1
        dst_counts[ip.dst] += 1

    if not flows:
        return np.zeros((1, N_FEATURES))

    rows = []
    for f in flows.values():
        dur          = (f["end"] - f["start"]) if (f["start"] is not None and f["end"] != f["start"]) else 0.0
        total        = f["total_pkts"] or 1
        serror_rate  = f["syn_errors"] / total
        rerror_rate  = f["rst_errors"] / total
        dst_count    = dst_counts.get(f["dst"], 0)
        dst_serr     = dst_syn_errs.get(f["dst"], 0)
        dst_serr_rate = dst_serr / dst_count if dst_count > 0 else 0.0

        # Build 68-feature row: KDD slots first, then IoT-only slots
        kdd_vals = [
            dur,                        # duration
            f["orig_bytes"],            # src_bytes
            f["resp_bytes"],            # dst_bytes
            0,                          # land
            0,                          # wrong_fragment
            0,                          # urgent
            0,                          # hot
            0,                          # num_failed_logins
            0,                          # logged_in
            0,                          # num_compromised
            0,                          # root_shell
            0,                          # su_attempted
            0,                          # num_root
            0,                          # num_file_creations
            0,                          # num_shells
            0,                          # num_access_files
            0,                          # num_outbound_cmds
            0,                          # is_host_login
            0,                          # is_guest_login
            dst_count,                  # count
            dst_count,                  # srv_count
            serror_rate,                # serror_rate
            serror_rate,                # srv_serror_rate
            rerror_rate,                # rerror_rate
            rerror_rate,                # srv_rerror_rate
            0,                          # same_srv_rate
            0,                          # diff_srv_rate
            0,                          # srv_diff_host_rate
            dst_count,                  # dst_host_count
            dst_count,                  # dst_host_srv_count
            0,                          # dst_host_same_srv_rate
            0,                          # dst_host_diff_srv_rate
            0,                          # dst_host_same_src_port_rate
            0,                          # dst_host_srv_diff_host_rate
            dst_serr_rate,              # dst_host_serror_rate
            dst_serr_rate,              # dst_host_srv_serror_rate
            rerror_rate,                # dst_host_rerror_rate
            rerror_rate,                # dst_host_srv_rerror_rate
        ]

        iot_vals = [
            f["orig_bytes"],            # orig_bytes
            f["resp_bytes"],            # resp_bytes
            f["missed_bytes"],          # missed_bytes
            f["orig_pkts"],             # orig_pkts
            f["orig_ip_bytes"],         # orig_ip_bytes
            f["resp_pkts"],             # resp_pkts
            f["resp_ip_bytes"],         # resp_ip_bytes
            int(f["proto"] == "icmp"),  # proto_icmp
            int(f["proto"] == "tcp"),   # proto_tcp
            int(f["proto"] == "udp"),   # proto_udp
            0,                          # service_-
            0,                          # service_dhcp
            int(f["dport"] == 53),      # service_dns
            int(f["dport"] == 80),      # service_http
            0,                          # service_irc
            int(f["dport"] == 22),      # service_ssh
            int(f["dport"] == 443),     # service_ssl
            0, 0, 0, 0, 0, 0,           # conn_state_OTH to RSTRH
            int(serror_rate > 0.5),     # conn_state_S0 (SYN no response)
            0, 0, 0,                    # S1, S2, S3
            int(serror_rate < 0.1),     # conn_state_SF (normal finish)
            0, 0,                       # SH, SHR
        ]

        rows.append(kdd_vals + iot_vals)

    X      = np.array(rows, dtype=np.float64)
    scaler = pickle.load(open(Path(__file__).parent.parent / "saved_models" / "scaler.pkl", "rb"))
    return scaler.transform(X)
