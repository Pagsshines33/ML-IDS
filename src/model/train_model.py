import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
import requests

warnings.filterwarnings("ignore")

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

ATTACK_MAP = {
    "normal": "Normal",
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "mailbomb": "DoS", "apache2": "DoS",
    "processtable": "DoS", "udpstorm": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe",
    "mscan": "Probe", "saint": "Probe",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L",
    "phf": "R2L", "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L",
    "sendmail": "R2L", "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "worm": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R",
    "httptunnel": "U2R", "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
}

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def download_nslkdd():
    urls = {
        "train": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
        "test": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt",
    }
    dataframes = {}
    for key, url in urls.items():
        try:
            print(f"Downloading {key} set from {url}...")
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            from io import StringIO
            df = pd.read_csv(StringIO(resp.text), header=None, names=COLUMNS)
            dataframes[key] = df
            print(f"  Done! {key} set: {len(df)} rows")
        except Exception as e:
            print(f"  Failed to download {key}: {e}")
            return None, None
    return dataframes.get("train"), dataframes.get("test")


def generate_synthetic_data(n_samples=20000):
    print("Generating synthetic NSL-KDD-like data as fallback...")
    np.random.seed(42)

    protocols = ["tcp", "udp", "icmp"]
    services = ["http", "smtp", "ftp", "ssh", "dns", "telnet", "finger", "pop_3",
                 "nntp", "imap4", "discard", "systat", "daytime", "netstat", "echo",
                 "other", "private"]
    flags = ["SF", "S0", "REJ", "RSTR", "RSTO", "SH", "S1", "S2", "RSTOS0", "S3", "OTH"]
    labels = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    label_weights = [0.47, 0.30, 0.12, 0.08, 0.03]

    data = {
        "duration": np.random.exponential(50, n_samples).astype(int),
        "protocol_type": np.random.choice(protocols, n_samples, p=[0.7, 0.2, 0.1]),
        "service": np.random.choice(services, n_samples),
        "flag": np.random.choice(flags, n_samples, p=[0.5, 0.15, 0.1, 0.05, 0.05, 0.03, 0.03, 0.03, 0.02, 0.02, 0.02]),
        "src_bytes": np.random.exponential(3000, n_samples).astype(int),
        "dst_bytes": np.random.exponential(2000, n_samples).astype(int),
        "land": np.random.choice([0, 1], n_samples, p=[0.99, 0.01]),
        "wrong_fragment": np.random.choice([0, 1, 2, 3], n_samples, p=[0.95, 0.03, 0.01, 0.01]),
        "urgent": np.random.choice([0, 1], n_samples, p=[0.99, 0.01]),
        "hot": np.random.poisson(0.2, n_samples),
        "num_failed_logins": np.random.choice([0, 1, 2, 3, 4, 5], n_samples, p=[0.9, 0.05, 0.02, 0.01, 0.01, 0.01]),
        "logged_in": np.random.choice([0, 1], n_samples, p=[0.4, 0.6]),
        "num_compromised": np.random.poisson(0.1, n_samples),
        "root_shell": np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
        "su_attempted": np.random.choice([0, 1, 2], n_samples, p=[0.96, 0.02, 0.02]),
        "num_root": np.random.poisson(0.1, n_samples),
        "num_file_creations": np.random.poisson(0.05, n_samples),
        "num_shells": np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
        "num_access_files": np.random.choice([0, 1, 2], n_samples, p=[0.95, 0.03, 0.02]),
        "num_outbound_cmds": np.zeros(n_samples, dtype=int),
        "is_host_login": np.random.choice([0, 1], n_samples, p=[0.99, 0.01]),
        "is_guest_login": np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
        "count": np.random.poisson(50, n_samples),
        "srv_count": np.random.poisson(25, n_samples),
        "serror_rate": np.random.beta(0.5, 5, n_samples),
        "srv_serror_rate": np.random.beta(0.5, 5, n_samples),
        "rerror_rate": np.random.beta(0.3, 5, n_samples),
        "srv_rerror_rate": np.random.beta(0.3, 5, n_samples),
        "same_srv_rate": np.random.beta(5, 1, n_samples),
        "diff_srv_rate": np.random.beta(0.5, 5, n_samples),
        "srv_diff_host_rate": np.random.beta(0.5, 5, n_samples),
        "dst_host_count": np.random.poisson(150, n_samples),
        "dst_host_srv_count": np.random.poisson(100, n_samples),
        "dst_host_same_srv_rate": np.random.beta(5, 1, n_samples),
        "dst_host_diff_srv_rate": np.random.beta(0.5, 5, n_samples),
        "dst_host_same_src_port_rate": np.random.beta(2, 3, n_samples),
        "dst_host_srv_diff_host_rate": np.random.beta(0.5, 5, n_samples),
        "dst_host_serror_rate": np.random.beta(0.5, 5, n_samples),
        "dst_host_srv_serror_rate": np.random.beta(0.5, 5, n_samples),
        "dst_host_rerror_rate": np.random.beta(0.3, 5, n_samples),
        "dst_host_srv_rerror_rate": np.random.beta(0.3, 5, n_samples),
        "attack_category": np.random.choice(labels, n_samples, p=label_weights),
    }

    df = pd.DataFrame(data)

    dos_mask = df["attack_category"] == "DoS"
    df.loc[dos_mask, "src_bytes"] = np.random.exponential(50000, dos_mask.sum()).astype(int)
    df.loc[dos_mask, "count"] = np.random.poisson(300, dos_mask.sum())
    df.loc[dos_mask, "serror_rate"] = np.random.beta(5, 1, dos_mask.sum())

    probe_mask = df["attack_category"] == "Probe"
    df.loc[probe_mask, "dst_host_count"] = np.random.poisson(250, probe_mask.sum())
    df.loc[probe_mask, "srv_count"] = np.random.poisson(5, probe_mask.sum())
    df.loc[probe_mask, "diff_srv_rate"] = np.random.beta(5, 1, probe_mask.sum())

    r2l_mask = df["attack_category"] == "R2L"
    df.loc[r2l_mask, "num_failed_logins"] = np.random.poisson(3, r2l_mask.sum())
    df.loc[r2l_mask, "logged_in"] = np.random.choice([0, 1], r2l_mask.sum(), p=[0.7, 0.3])

    u2r_mask = df["attack_category"] == "U2R"
    df.loc[u2r_mask, "root_shell"] = np.random.choice([0, 1], u2r_mask.sum(), p=[0.3, 0.7])
    df.loc[u2r_mask, "num_root"] = np.random.poisson(5, u2r_mask.sum())
    df.loc[u2r_mask, "su_attempted"] = np.random.choice([0, 1, 2], u2r_mask.sum(), p=[0.2, 0.4, 0.4])

    print(f"  Generated {n_samples} synthetic samples")
    return df


def train():
    model_dir = os.path.dirname(os.path.abspath(__file__))

    print("=" * 60)
    print("  ML-IDS Model Training - NSL-KDD Dataset")
    print("=" * 60)

    train_df, test_df = download_nslkdd()
    use_synthetic = train_df is None

    if use_synthetic:
        df = generate_synthetic_data(25000)
    else:
        df = pd.concat([train_df, test_df], ignore_index=True)
        df.drop("difficulty", axis=1, inplace=True, errors="ignore")
        df["label"] = df["label"].str.strip().str.lower()
        df["attack_category"] = df["label"].map(ATTACK_MAP).fillna("Unknown")
        df = df[df["attack_category"] != "Unknown"]
        print(f"\nTotal samples after mapping: {len(df)}")

    print(f"\nClass distribution:")
    print(df["attack_category"].value_counts())

    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        if col in df.columns:
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le

    if use_synthetic:
        feature_cols = [c for c in df.columns if c != "attack_category"]
        X = df[feature_cols].values
        y = df["attack_category"].values
    else:
        feature_cols = [c for c in df.columns if c not in ["label", "attack_category"]]
        X = df[feature_cols].values
        y = df["attack_category"].values

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_encoded, test_size=0.25, random_state=42, stratify=y_encoded
    )

    print(f"\nTraining set: {X_train.shape[0]} samples")
    print(f"Test set:     {X_test.shape[0]} samples")
    print(f"Features:     {X_train.shape[1]}")

    print("\nTraining Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n{'=' * 60}")
    print(f"  Model Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"{'=' * 60}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    importances = model.feature_importances_
    top_n = min(15, len(feature_cols))
    indices = np.argsort(importances)[::-1][:top_n]
    print(f"\nTop {top_n} Important Features:")
    for i, idx in enumerate(indices):
        print(f"  {i+1}. {feature_cols[idx]}: {importances[idx]:.4f}")

    artifacts = {
        "model": model,
        "scaler": scaler,
        "encoders": encoders,
        "label_encoder": label_encoder,
        "feature_cols": feature_cols,
        "categorical_cols": CATEGORICAL_COLS,
        "accuracy": accuracy,
        "classification_report": classification_report(y_test, y_pred, target_names=label_encoder.classes_, output_dict=True),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "feature_importances": dict(zip(feature_cols, importances.tolist())),
        "classes": label_encoder.classes_.tolist(),
    }

    model_path = os.path.join(model_dir, "ids_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(artifacts, f)

    print(f"\nModel saved to: {model_path}")
    print("Training complete!")
    return artifacts


if __name__ == "__main__":
    train()