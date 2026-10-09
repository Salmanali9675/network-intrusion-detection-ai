"""
data_generator.py
Synthesizes benchmark-grade realistic network connection telemetry modeled
after NSL-KDD and CICIDS intrusion detection benchmarks.
"""

import os
import numpy as np
import pandas as pd


def generate_network_dataset(num_samples: int = 8000, random_state: int = 42) -> pd.DataFrame:
    """
    Generates a realistic multi-class network traffic dataset with distinct
    telemetry signatures for Normal traffic, DoS, Probe, R2L, and U2R attacks.
    """
    np.random.seed(random_state)

    # Class distribution (realistic SOC imbalance):
    # Normal: ~52%, DoS: ~30%, Probe: ~12%, R2L: ~4%, U2R: ~2%
    weights = [0.52, 0.30, 0.12, 0.04, 0.02]
    attack_classes = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    assigned_classes = np.random.choice(attack_classes, size=num_samples, p=weights)

    records = []

    for label in assigned_classes:
        if label == "Normal":
            # Normal web/email/dns traffic:
            # - Protocol: mainly TCP and UDP
            # - Service: http, dns, smtp
            # - Flag: predominantly SF (Normal establish & close)
            # - src_bytes and dst_bytes: balanced normal payload
            # - failed logins: 0 (or very rarely 1)
            # - serror_rate: 0
            # - count: low to moderate
            protocol = np.random.choice(["tcp", "udp", "icmp"], p=[0.75, 0.22, 0.03])
            service = np.random.choice(["http", "dns", "smtp", "ftp", "ssh"], p=[0.55, 0.22, 0.12, 0.06, 0.05])
            flag = np.random.choice(["SF", "S0", "REJ"], p=[0.94, 0.04, 0.02])
            duration = max(0.0, np.random.exponential(scale=2.5))
            src_bytes = int(np.random.lognormal(mean=6.5, sigma=1.0))
            dst_bytes = int(np.random.lognormal(mean=8.0, sigma=1.2))
            wrong_fragment = 0
            urgent = 0
            hot = int(np.random.choice([0, 1], p=[0.97, 0.03]))
            num_failed_logins = int(np.random.choice([0, 1], p=[0.99, 0.01]))
            logged_in = 1 if service in ["http", "smtp", "ftp", "ssh"] and np.random.rand() > 0.1 else 0
            count = int(np.random.randint(1, 25))
            srv_count = int(np.random.randint(1, 20))
            serror_rate = round(float(np.random.uniform(0.0, 0.05)), 2)
            same_srv_rate = round(float(np.random.uniform(0.85, 1.0)), 2)
            diff_srv_rate = round(float(np.random.uniform(0.0, 0.12)), 2)
            dst_host_count = int(np.random.randint(10, 255))
            dst_host_srv_count = int(np.random.randint(15, 255))
            dst_host_same_srv_rate = round(float(np.random.uniform(0.70, 1.0)), 2)
            dst_host_diff_srv_rate = round(float(np.random.uniform(0.0, 0.15)), 2)

        elif label == "DoS":
            # Denial of Service (SYN Flood / Smurf / Neptune):
            # - Protocol: mainly TCP or ICMP
            # - Flag: S0 (no reply) or REJ
            # - Service: private, http, ecr_i
            # - Extremely high connection count in 2-second window
            # - High serror_rate (~0.8 to 1.0)
            # - Very small payload (SYN packets)
            # - logged_in: 0
            protocol = np.random.choice(["tcp", "icmp", "udp"], p=[0.82, 0.15, 0.03])
            service = np.random.choice(["private", "http", "eco_i", "other"], p=[0.50, 0.30, 0.15, 0.05])
            flag = np.random.choice(["S0", "REJ", "SF"], p=[0.85, 0.10, 0.05])
            duration = 0.0
            src_bytes = int(np.random.choice([0, 44, 60, 120]))
            dst_bytes = 0
            wrong_fragment = int(np.random.choice([0, 1, 3], p=[0.85, 0.10, 0.05]))
            urgent = 0
            hot = 0
            num_failed_logins = 0
            logged_in = 0
            count = int(np.random.randint(150, 511))
            srv_count = int(np.random.randint(100, 511))
            serror_rate = round(float(np.random.uniform(0.75, 1.0)), 2)
            same_srv_rate = round(float(np.random.uniform(0.70, 1.0)), 2)
            diff_srv_rate = round(float(np.random.uniform(0.0, 0.08)), 2)
            dst_host_count = int(np.random.randint(200, 255))
            dst_host_srv_count = int(np.random.randint(1, 35))
            dst_host_same_srv_rate = round(float(np.random.uniform(0.0, 0.20)), 2)
            dst_host_diff_srv_rate = round(float(np.random.uniform(0.05, 0.30)), 2)

        elif label == "Probe":
            # Network PortScan / IP Sweep (Nmap, Satan, Ipsweep):
            # - Probing multiple different ports/services across hosts
            # - High diff_srv_rate (targeting many distinct ports)
            # - Flag: REJ, RSTR, S0
            # - Short duration, 0 or small payload
            protocol = np.random.choice(["tcp", "icmp", "udp"], p=[0.70, 0.20, 0.10])
            service = np.random.choice(["private", "other", "http", "finger", "telnet"], p=[0.40, 0.30, 0.15, 0.08, 0.07])
            flag = np.random.choice(["REJ", "RSTR", "S0", "SF"], p=[0.55, 0.25, 0.15, 0.05])
            duration = round(float(np.random.uniform(0.0, 3.0)), 2)
            src_bytes = int(np.random.randint(0, 50))
            dst_bytes = int(np.random.randint(0, 30))
            wrong_fragment = 0
            urgent = 0
            hot = 0
            num_failed_logins = 0
            logged_in = 0
            count = int(np.random.randint(10, 180))
            srv_count = int(np.random.randint(1, 15))
            serror_rate = round(float(np.random.uniform(0.10, 0.50)), 2)
            same_srv_rate = round(float(np.random.uniform(0.0, 0.30)), 2)
            diff_srv_rate = round(float(np.random.uniform(0.60, 1.0)), 2)
            dst_host_count = int(np.random.randint(150, 255))
            dst_host_srv_count = int(np.random.randint(1, 20))
            dst_host_same_srv_rate = round(float(np.random.uniform(0.01, 0.15)), 2)
            dst_host_diff_srv_rate = round(float(np.random.uniform(0.65, 1.0)), 2)

        elif label == "R2L":
            # Remote to Local (SSH/FTP Password Guessing / Brute Force):
            # - Target service: ssh, ftp, telnet
            # - High num_failed_logins (2, 3, 4, 5)
            # - Protocol: TCP
            # - Flag: SF
            # - Moderate payload, duration longer
            protocol = "tcp"
            service = np.random.choice(["ssh", "ftp", "telnet"], p=[0.60, 0.25, 0.15])
            flag = "SF"
            duration = round(float(np.random.uniform(5.0, 60.0)), 2)
            src_bytes = int(np.random.randint(300, 2500))
            dst_bytes = int(np.random.randint(200, 1800))
            wrong_fragment = 0
            urgent = 0
            hot = int(np.random.randint(1, 4))
            num_failed_logins = int(np.random.randint(2, 6))
            logged_in = int(np.random.choice([0, 1], p=[0.70, 0.30]))
            count = int(np.random.randint(1, 10))
            srv_count = int(np.random.randint(1, 10))
            serror_rate = 0.0
            same_srv_rate = 1.0
            diff_srv_rate = 0.0
            dst_host_count = int(np.random.randint(1, 50))
            dst_host_srv_count = int(np.random.randint(1, 50))
            dst_host_same_srv_rate = round(float(np.random.uniform(0.60, 1.0)), 2)
            dst_host_diff_srv_rate = round(float(np.random.uniform(0.0, 0.10)), 2)

        else:  # U2R
            # User to Root (Privilege Escalation, Buffer Overflow, Rootkit):
            # - Normal login first (logged_in: 1)
            # - High 'hot' actions (entering root dirs, compiling binaries)
            # - High 'urgent' packets or root shell spawning
            # - Service: telnet, ftp, ssh
            protocol = "tcp"
            service = np.random.choice(["telnet", "ssh", "ftp"], p=[0.50, 0.35, 0.15])
            flag = "SF"
            duration = round(float(np.random.uniform(10.0, 120.0)), 2)
            src_bytes = int(np.random.randint(1200, 8000))
            dst_bytes = int(np.random.randint(3000, 15000))
            wrong_fragment = 0
            urgent = int(np.random.choice([0, 1, 2], p=[0.70, 0.20, 0.10]))
            hot = int(np.random.randint(3, 9))
            num_failed_logins = 0
            logged_in = 1
            count = int(np.random.randint(1, 5))
            srv_count = int(np.random.randint(1, 5))
            serror_rate = 0.0
            same_srv_rate = 1.0
            diff_srv_rate = 0.0
            dst_host_count = int(np.random.randint(1, 25))
            dst_host_srv_count = int(np.random.randint(1, 25))
            dst_host_same_srv_rate = 1.0
            dst_host_diff_srv_rate = 0.0

        records.append({
            "duration": duration,
            "protocol_type": protocol,
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "wrong_fragment": wrong_fragment,
            "urgent": urgent,
            "hot": hot,
            "num_failed_logins": num_failed_logins,
            "logged_in": logged_in,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "attack_type": label,
            "is_attack": 0 if label == "Normal" else 1
        })

    df = pd.DataFrame(records)
    return df


def save_dataset(output_path: str, num_samples: int = 8000):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    df = generate_network_dataset(num_samples=num_samples)
    df.to_csv(output_path, index=False)
    print(f"Dataset saved to: {output_path} ({len(df)} records)")
    print("Class distribution:")
    print(df["attack_type"].value_counts(normalize=True).apply(lambda x: f"{x*100:.1f}%"))


if __name__ == "__main__":
    output_csv = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "network_traffic.csv")
    save_dataset(output_csv)
