"""Write small MADE-UP CSVs in the real UNSW-NB15, CICIDS2017 and BETH column formats.

These rows are random test data, not samples of the real datasets. They exist only
so the alert generator and its checks can be tested without the real files. The
folder gets a FIXTURE_NOT_REAL_DATA marker, and the generator refuses to write
fixture-based output into data/poc_alerts.

    python tests/fixtures/make_raw_fixture.py /tmp/raw_fixture
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

SCALE = 8  # enough rows for the ~1,000-alert build
UNSW_COUNTS = {k: v * SCALE for k, v in {
    "Normal": 600, "Reconnaissance": 60, "Analysis": 20, "Exploits": 60, "Shellcode": 10,
    "Fuzzers": 20, "Generic": 20, "DoS": 60, "Backdoor": 10, "Worms": 5}.items()}
CIC_COUNTS = {k: v * SCALE for k, v in {
    "BENIGN": 600, "PortScan": 40, "FTP-Patator": 20, "SSH-Patator": 20, "DoS Hulk": 30,
    "DDoS": 20, "Web Attack \u2013 XSS": 10, "Heartbleed": 3, "Infiltration": 5, "Bot": 40}.items()}


def unsw(rng):
    rows = []
    for cat, n in UNSW_COUNTS.items():
        for _ in range(n):
            spk, dpk = int(rng.integers(1, 400)), int(rng.integers(0, 300))
            dur = float(rng.exponential(2.0))
            rows.append({"id": len(rows) + 1, "dur": round(dur, 6),
                         "proto": rng.choice(["tcp", "udp"]),
                         "service": rng.choice(["-", "http", "ssh", "ftp", "dns", "smtp"]),
                         "state": rng.choice(["FIN", "INT", "CON", "REQ"]), "spkts": spk, "dpkts": dpk,
                         "sbytes": int(rng.integers(40, 2_000_000)), "dbytes": int(rng.integers(0, 500_000)),
                         "rate": round((spk + dpk) / max(dur, 1e-3), 3), "sttl": 31, "dttl": 29,
                         "attack_cat": cat, "label": 0 if cat == "Normal" else 1})
    df = pd.DataFrame(rows).sample(frac=1, random_state=1).reset_index(drop=True)
    df["id"] = range(1, len(df) + 1)
    return df


def cicids(rng, with_ips):
    rows = []
    for label, n in CIC_COUNTS.items():
        for _ in range(n):
            r = {" Destination Port": int(rng.choice([21, 22, 80, 443, 8080, 53, 445])),
                 " Flow Duration": int(rng.integers(100, 50_000_000)),
                 " Total Fwd Packets": int(rng.integers(1, 500)),
                 " Total Backward Packets": int(rng.integers(0, 400)),
                 "Total Length of Fwd Packets": int(rng.integers(0, 3_000_000)),
                 " Total Length of Bwd Packets": int(rng.integers(0, 900_000)),
                 " Flow Packets/s": round(float(rng.exponential(5000)), 3),
                 " Label": label}
            if with_ips:
                r = {" Source IP": f"192.168.10.{rng.integers(2, 60)}",
                     " Destination IP": f"172.16.0.{rng.integers(1, 30)}", " Protocol": 6, **r}
            rows.append(r)
    return pd.DataFrame(rows).sample(frac=1, random_state=2).reset_index(drop=True)


def beth(rng):
    rows = []
    for (sus, evil), n in {(0, 0): 600 * SCALE, (1, 0): 40 * SCALE, (1, 1): 40 * SCALE}.items():
        for _ in range(n):
            rows.append({"timestamp": round(float(rng.uniform(0, 5000)), 6),
                         "processId": int(rng.integers(100, 9000)), "threadId": int(rng.integers(100, 9000)),
                         "parentProcessId": int(rng.integers(1, 3000)), "userId": int(rng.choice([0, 100, 1000])),
                         "mountNamespace": 4026531840,
                         "processName": rng.choice(["sshd", "bash", "sh", "python3", "systemd", "cron"]),
                         "hostName": rng.choice(["ip-10-100-1-79", "ip-10-100-1-120", "ip-10-100-1-217"]),
                         "eventId": int(rng.integers(1, 1000)),
                         "eventName": rng.choice(["execve", "openat", "connect", "close", "security_file_open"]),
                         "stackAddresses": "[]", "argsNum": 2, "returnValue": 0,
                         "args": "[{'name': 'pathname', 'type': 'const char*', 'value': '/usr/bin/id'}]",
                         "sus": sus, "evil": evil})
    return pd.DataFrame(rows).sample(frac=1, random_state=3).reset_index(drop=True)


def main(out: Path):
    rng = np.random.default_rng(7)
    for sub in ("unsw_nb15", "cicids2017", "beth"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    unsw(rng).to_csv(out / "unsw_nb15" / "UNSW_NB15_fixture.csv", index=False)
    cicids(rng, with_ips=True).to_csv(out / "cicids2017" / "cic_fixture_with_ips.csv", index=False)
    cicids(rng, with_ips=False).to_csv(out / "cicids2017" / "cic_fixture_mlcve.csv", index=False)
    beth(rng).to_csv(out / "beth" / "beth_fixture.csv", index=False)
    (out / "FIXTURE_NOT_REAL_DATA").write_text("Made-up test rows. Not real dataset data.\n")
    print(f"fixture written to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/raw_fixture"))
