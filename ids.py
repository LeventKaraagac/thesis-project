import argparse
import time
from datetime import datetime

# General variables used.
state_path = "data/state.json"
alert_path = "data/alerts.log"

port_count_dict = {}
src_volume_dict = {}

port_scan_threshold = 5
volume_threshold = 100

# Reading last offset, seeking, reading new lines, and basic parsing into events
def analyze_file(path):
    global port_count_dict, src_volume_dict
    port_count_dict = {}
    src_volume_dict = {}

    # Read last position (Defaults to 0 if the file is empty/missing)
    with open(state_path, "r") as f:
        line = f.readline().strip()
        previous_position = int(line) if line else 0

    # Opens file, checks if it's updated and parses data logs
    with open(path, "r") as file:
        file.seek(previous_position) # Start from saved offset

        # Parses log file into a dictionary
        for line in file:
            split_line = line.rstrip("\n").split(",")
            # skip empty / bad lines
            if len(split_line) != 4:
                continue

            timestamp = split_line[0]
            src_ip = split_line[1]
            dst_ip = split_line[2]
            dst_port = split_line[3]

            # For port_count_dict dictionary
            if not dst_port:
                continue
            try:
                dst_port_int = int(dst_port)
            except ValueError:
                continue

            if (src_ip, dst_ip) not in port_count_dict:
                port_count_dict[src_ip, dst_ip] = {dst_port_int}
            else:
                port_count_dict[src_ip, dst_ip].add(dst_port_int)

            # For src_volume_dict dictionary
            if src_ip not in src_volume_dict:
                src_volume_dict[src_ip] = 1
            else:
                src_volume_dict[src_ip] += 1

        offset = file.tell()

    # Write the last position to state.json
    with open(state_path, "w") as f:
        f.write(str(offset))

# Function for counting unique port scans and alerting
def analyze_port_count():
    # Analyzes and creates alerts
    for (src_ip, dst_ip), dst_port_int in port_count_dict.items():
        # Counts the amount of ports a pair of src_ip and dst_ip and creates an alert.
        if len(dst_port_int) > port_scan_threshold:
            details = f"distinct ports={sorted(dst_port_int)}"
            log_alert("PORT_SCAN", src_ip, dst_ip, details)
        else:
            print(f"INFO: {src_ip} to {dst_ip} used {dst_port_int} distinct ports")

# Function for analyzing connection count per source ip
def analyze_connection_count():
    for src_ip, volume in src_volume_dict.items():
        # Checks if the volume is above the threshold, and creates an alert.
        if volume > volume_threshold:
            details = f"connections={volume} in interval"
            log_alert("HIGH_VOLUME", src_ip, None, details)
        else:
            print(f"INFO: {src_ip} tried to connect {volume} times")

# for running the IDS in an interval
def analyze_periodically(path: str, interval_time: int = 60):
    while True:
        print("\n--- Running IDS ---")
        analyze_file(path)
        analyze_port_count()
        analyze_connection_count()
        print("Waiting for next time interval...\n")
        time.sleep(interval_time)

def log_alert(rule: str, src_ip: str, dst_ip: str | None, details: str) -> None:
    ts = datetime.now().isoformat(timespec="seconds")
    line = f"{ts} | {rule} | {src_ip} | {dst_ip or '-'} | {details}"
    print(line)
    with open(alert_path, "a") as file:
        file.write(line + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_path", type=str, help="Path to input log file")
    args = parser.parse_args()

    analyze_periodically(args.input_path, interval_time=60)
