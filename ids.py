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

3. Turn counts into a simple alert rule DONE
    - Goal: first detection behavior.
    - For each (src_ip, dst_ip) pair, if the count exceeds the threshold, print an alert like:
        ALERT: possible port scan from 10.0.0.5 to 10.0.0.10 (7 ports)
    - That gives you a minimal IDS prototype on synthetic logs.

COUNTING DISTINCT PORTS - done
Step 1: Open Log file, check if the file is updated, and read and assign the relevant information to variables
Step 2: Counting for distinct ports
Step 3: Create an alert rule

REMEMBERING FILE POSITION TO NOT HAVE DUPLICATE ALERTS - done
Step 1: tell() method is used to figure out the position in the file, and it is saved to state.json at the end of every search.
step 2: seek() method is used to start reading the log file from the last location beginning of the search.
- This way, we don't get duplicate alerts and the IDS doesn't re-read the same lines it already did.

RUNS IN INTERVALS FUNCTIONALITY - done

COUNTING TOTAL CONNECTIONS PER src_ip
"""
import argparse
import time

def analyze_file(path: str, port_scan_threshold: int = 5, state_path: str = "data/state.json"):

    # Read last position
    with open(state_path, "r") as f: # Read last position
        line = f.readline().strip()
        previous_position = int(line) if line else 0

    # Opens file, checks if it's updated and parses data logs
    port_count_dict = {}
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
            if (src_ip, dst_ip) not in port_count_dict:
                port_count_dict[src_ip, dst_ip] = {int(dst_port)}
            else:
                port_count_dict[src_ip, dst_ip].add(int(dst_port))

        # Variable for last position read in the log file
        offset = file.tell()

    # Write the last position to state.json
    with open("data/state.json", "w") as f:
        f.write(str(offset))

    # Analyzes and creates alerts
    for (src_ip, dst_ip), dst_port in port_count_dict.items():
        if len(dst_port) > port_scan_threshold:
            print(f"ALERT: possible port scan from {src_ip} to {dst_ip}: {dst_port}")
            with open("alerts.log", "a") as file:
                file.write(f"ALERT: possible port scan from {src_ip} to {dst_ip}: {dst_port}\n")
        else:
            print(f"INFO: {src_ip} to {dst_ip} used {dst_port} distinct ports")

def analyze_periodically(path: str, interval_time: int = 60):
    while True:
        print("\n--- Running IDS ---")
        analyze_file(path)
        print("Waiting for next time interval...\n")
        time.sleep(interval_time)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_path", type=str, help="Path to input log file")
    args = parser.parse_args()

    analyze_periodically(args.input_path, interval_time=60)