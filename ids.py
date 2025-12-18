"""
MAIN THESIS PROJECT FILE
"""

"MINIMAL PARSING OF DATA - done"
"""
1. Implementing minimal parsing of data DONE
    - Read log file and print each event in a clear format.
    - For example: opens folder, loops over each time, splits the line by , into timestamp, src_ip, dst_ip, dst_port
    - Prints  something like: SRC 10.0.0.5 -> DST 10.0.0.10:22 at 2025-12-14T13:40:00
"""

"REMEMBERING FILE POSITION TO NOT HAVE DUPLICATE ALERTS - done"
"""
Step 1: tell() method is used to figure out the position in the file, and it is saved to state.json at the end of every search.
step 2: seek() method is used to start reading the log file from the last location beginning of the search.
- This way, we don't get duplicate alerts and the IDS doesn't re-read the same lines it already did.
"""

"RUNS IN INTERVALS FUNCTIONALITY - done"
"""
For this functionality, import time is used. def analyze_periodically is used.

Full code: 
def analyze_periodically(path: str, interval_time: int = 60):
    while True:
        print("\n--- Running IDS ---")
        analyze_file(path)
        analyze_port_count()
        print("Waiting for next time interval...\n")
        time.sleep(interval_time)
"""

"COUNTING DISTINCT PORTS FEATURE - done"
"""
Step 1: Open Log file, check if the file is updated, and read and assign the relevant information to variables
Step 2: Counting for distinct ports
Step 3: Create an alert rule

    1. Add counting for distinct ports DONE
        - Goal is to detect the scan IP in this dev file
        - Create a dictionary keyed by (src_ip, dst_ip) that stores a set of destination ports.
        - For each parsed line, add dst_port to the set for that pair.
        - After reading the whole file, print for each (src_ip, dst_ip) pair how many distinct ports were contacted.
        - You should see that 10.0.0.5 -> 10.0.0.t10 has many ports, while others have fewer.

    2. Turn counts into a simple alert rule DONE
        - Goal: first detection behavior.
        - For each (src_ip, dst_ip) pair, if the count exceeds the threshold, print an alert like:
            ALERT: possible port scan from 10.0.0.5 to 10.0.0.10 (7 ports)
        - That gives you a minimal IDS prototype on synthetic logs.
"""

"COUNTING TOTAL CONNECTIONS PER SRC_IP FEATURE - done"
"""
For this feature, we want to look at the same parsed data, but answer a different question
- Which source IPs are talking a lot overall in this interval?

Conceptually:
- It takes all events from the current run
- For each event, increments a counter for that src_ip
- At the end of the interval, it has a simple map: src_ip -> total number of connections in this run.

Using that it applies a threshold:
- If a src_ip has more than volume_threshold connections in this interval, create a "high volume" alert.
- Otherwise, optionally log an INFO line with its count.

Architecture considerations:
    - The current function def analyze_file(path) currently records only unique port scans and 
    and not duplicate hits to the same port by the same pair of source and destination IPs. 
    - This is an issue for this functionality as we want to get the number of hits to the same port (volume).
    - Maybe we can implement a counter that will increase every time there is a duplicate, 
    which in return can help us implement this feature.
    
Flow Chart of the functionality:
    1. new line in traffic_dev.log file is read
    2. Take a note of the src_ip, dst_ip, dst_port, timestamp
    3. Take a note of the src_ip into src_volume dictionary and increment by 1
    4. Every time the same src_ip shows up, increment the "value" of the src_ip volume key:value value by 1
    5. If the src_ip doesn't already exist in the src_volume dict, create a new key:value pair in the dictionary and increment by 1
    6. Keey going throuhg the log file until everything is read. Move onto the actual function def analyze_connection_count
    7. If the value for src_ip:volume pair in the src_volume dictionary passes 5, create an alert for that run.
"""

"WIRESHARK LOG FILE IMPLEMENTATION - done"
"""
1. Download Wireshark on laptop - done
2. Create some logs with it - traffic_wireshark_test.csv downloaded
3. Make sure the def analyze_file is configured properly for Wireshark implementation 
4. Figure out how to get the log files from Wireshark
5. Figure out the structure Wireshark uses for its log files
6. Adjust the code to be able to read and analyze Wireshark logs.

Using tshark to get specific logs with the following command that: 
tshark.exe -i 4 -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -E header=n -E separator=, -E quote=n
-E occurrence=f >> 'C:\ Users\leven\PycharmProjects\PythonProject\data\traffic_dev_TEST.log'
"""

"WEB INTERFACE IMPLEMENTATION"
"""
Simple Flask can be used for web interface representation.
1. import flask package
2. Create app.py and create a simple object with flask.
    Example:
    from flask import Flask, render_template, request
    app = Flask(__name__)  # Flask constructor
    @app.route('/')
    def index():
        return render_template("index.html")
3. Create a simple function in ids.py for sending the alerts to the flask app.
4. edit index.html for the connection in between the function and the table.
"""

"VM DEPLOYMENT AND INTEGRATION"

"TIMESTAMP FUNCTIONALITY ON THE ALERTS - done and added with Flask"

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