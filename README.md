# Lightweight Python-Based Intrusion Detection System (IDS)

A signature-based Intrusion Detection System built in Python to detect **port scans** and **high-volume connection activity** in real time, with a live Flask web dashboard for alert monitoring.

Originally developed as my Engineering Thesis at Vistula University (Computer Science — Cybersecurity & Computer Networks Engineering), supervised by Dr. Selcuk Cankurt.

---

## What it does

The IDS reads network traffic logs (captured via Wireshark/TShark) and analyzes them against two detection algorithms:

- **Port Scan Detection** — flags a source→destination IP pair once the number of distinct destination ports scanned exceeds a threshold (default: 5 ports)
- **High-Volume Connection Detection** — flags a source IP once its connection count within a 60-second interval exceeds a threshold (default: 100 connections)

Detected events are logged to `alerts.log` and displayed live in a Flask web dashboard.

## Why

Port scanning and high-connection-volume activity are common reconnaissance and attack signatures. This project set out to answer two research questions:

1. Can a lightweight, Python-based IDS reliably detect common port scans and high-volume traffic in a controlled network environment?
2. What are the CPU, memory, and latency costs of that detection approach under varying traffic load?

## How it works

```
Kali Linux VM (attacker, Nmap)
        │  generates traffic
        ▼
Ubuntu Linux VM ── TShark captures traffic → traffic log file
        │
        ▼
   ids.py (runs every 60s)
        │  reads only new log lines (tracks offset via state.json)
        │  parses timestamp / src_ip / dst_ip / dst_port
        │  runs both detection algorithms
        ▼
   alerts.log ──────────────► app.py (Flask) ──────────────► Web dashboard
```

**Key implementation details:**
- **Stateful, incremental log processing** — the IDS remembers the last file offset it read (`state.json`), so it never reprocesses old data and avoids duplicate alerts
- **Interval-based execution** — runs every 60 seconds, balancing detection responsiveness against resource usage
- **In-memory aggregation** — traffic is grouped per source/destination IP pair (port scan detection) and per source IP (volume detection), held only temporarily to avoid memory overhead

## Tech stack

| Component | Tool |
|---|---|
| Detection engine | Python 3 |
| Traffic capture | Wireshark / TShark |
| Web dashboard | Flask |
| Attacker simulation | Kali Linux + Nmap |
| IDS host | Ubuntu Linux |
| Virtualization | Oracle VirtualBox (NAT network) |
| Version control | Git / GitHub |

## Repository structure

```
├── ids.py              # Core detection engine (log parsing, detection algorithms, alerting)
├── app.py              # Flask web app — serves the live alerts dashboard
├── templates/           # HTML templates for the dashboard
├── data/                # Traffic logs and alerts.log
└── requirements.txt     # Python dependencies
```

## Testing & results

The IDS was tested in a two-VM lab environment (Ubuntu as the IDS host, Kali as the attacker) using Oracle VirtualBox with NAT networking.

**Baseline scenario (normal traffic):** No alerts generated — confirms the system does not produce false positives under normal conditions.

**Attack scenario (Nmap scan from Kali → Ubuntu):** The IDS correctly detected both port-scanning activity and high-volume connections, generating accurate alerts in both `alerts.log` and the live web dashboard, including the full list of scanned ports per source/destination pair.

Resource usage was evaluated qualitatively rather than via formal benchmarking: the interval-based, in-memory design kept CPU and memory usage low throughout testing, with the main trade-off being detection latency (up to 60 seconds) in exchange for efficiency.

## Limitations & future work

- Tested in a controlled virtual lab, not a production network — results may not fully generalize
- Uses static, fixed thresholds — legitimate high-volume traffic could trigger false positives
- Interval-based rather than real-time detection
- Currently host-based (HIDS) only; could be extended to network-based (NIDS) monitoring
- Only two detection algorithms implemented; more signatures/anomaly-based detection could be added

## Running it locally

```bash
pip install -r requirements.txt
python ids.py       # start the detection engine
python app.py        # start the web dashboard (separate terminal)
```

Traffic logs are expected in `data/` in the format: `timestamp,src_ip,dst_ip,dst_port`.

## Author

**Levent Karaagac**
BEng Computer Science — Cybersecurity & Computer Networks Engineering, Vistula University
[LinkedIn](https://pl.linkedin.com/in/levent-karaagac) · [GitHub](https://github.com/LeventKaraagac) · [Medium](https://medium.com/@LeventKaraagac)
