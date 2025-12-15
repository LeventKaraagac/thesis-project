"""
MAIN THESIS PROJECT FILE

1. Implementing minimal parsing of data DONE
    - Read log file and print each event in a clear format.
    - For example: opens folder, loops over each time, splits the line by , into timestamp, src_ip, dst_ip, dst_port
    - Prints  something like: SRC 10.0.0.5 -> DST 10.0.0.10:22 at 2025-12-14T13:40:00

2. Add counting for distinct ports DONE
    - Goal is to detect the scan IP in this dev file
    - Create a dictionary keyed by (src_ip, dst_ip) that stores a set of destination ports.
    - For each parsed line, add dst_port to the set for that pair.
    - After reading the whole file, print for each (src_ip, dst_ip) pair how many distinct ports were contacted.
    - You should see that 10.0.0.5 -> 10.0.0.t10 has many ports, while others have fewer.

3. Turn counts into a simple alert rule
    - Goal: first detection behavior.
    - For each (src_ip, dst_ip) pair, if the count exceeds the threshold, print an alert like:
        ALERT: possible port scan from 10.0.0.5 to 10.0.0.10 (7 ports)
    - That gives you a minimal IDS prototype on synthetic logs.

Step 1: Open Log file, read and assign the relevant information to variables
# # Open Log file, read and assign the relevant information to variables
# with open("data/traffic_dev.log", "r") as file:
#     for line in file:
#         splitLine = line.rstrip("\n").split(",")
#         timestamp = splitLine[0]
#         src_ip = splitLine[1]
#         dst_ip = splitLine[2]
#         dst_port = splitLine[3]
#         print(f"SRC {src_ip} -> DST {dst_ip}:{dst_port} at {timestamp}")
Step 2: Counting for distinct ports
Step 3: Create an alert rule
"""
import argparse

def analyze_file(path: str, port_scan_threshold: int = 5):
    """Step 2: Counting for distinct ports"""
    port_count_dict = {}

    with open(path, "r") as file:
        for line in file:
            split_line = line.rstrip("\n").split(",")
            timestamp = split_line[0]
            src_ip = split_line[1]
            dst_ip = split_line[2]
            dst_port = split_line[3]
            if (src_ip, dst_ip) not in port_count_dict:
                port_count_dict[src_ip, dst_ip] = {int(dst_port)}
            else:
                port_count_dict[src_ip, dst_ip].add(int(dst_port))

    """Step 3: Create an alert rule"""
    for (src_ip, dst_ip), dst_port in port_count_dict.items():
        if len(dst_port) > port_scan_threshold:
            print(f"ALERT: possible port scan from {src_ip} to {dst_ip}: {dst_port}")
            with open("alerts.log", "a") as file:
                file.write(f"ALERT: possible port scan from {src_ip} to {dst_ip}: {dst_port}\n")
        else:
            print(f"INFO: {src_ip} to {dst_ip} used {dst_port} distinct ports")

parser = argparse.ArgumentParser()
parser.add_argument("input_path", type=str, help="Path to input log file")
args = parser.parse_args()

if __name__ == "__main__":
    analyze_file(args.input_path)