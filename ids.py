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
"""
from pprint import pprint

"""Step 1: Open Log file, read and assign the relevant information to variables"""
# # Open Log file, read and assign the relevant information to variables
# with open("data/traffic_dev.log", "r") as file:
#     for line in file:
#         splitLine = line.rstrip("\n").split(",")
#         timestamp = splitLine[0]
#         src_ip = splitLine[1]
#         dst_ip = splitLine[2]
#         dst_port = splitLine[3]
#         print(f"SRC {src_ip} -> DST {dst_ip}:{dst_port} at {timestamp}")

"""Step 2: Counting for distinct ports"""
# We basically want to know, for each pair src_ip, dst_ip, how many different ports were contacted.
# If the src_ip to dst_ip pair exists, add to the value.
# If the src_ip to dst_ip pair does not exist, create a new value.

PortCountDict = {}

with open("data/traffic_dev.log", "r") as file:
    for line in file:
        splitLine = line.rstrip("\n").split(",")
        timestamp = splitLine[0]
        src_ip = splitLine[1]
        dst_ip = splitLine[2]
        dst_port = splitLine[3]
        if (src_ip, dst_ip) not in PortCountDict:
            PortCountDict[src_ip, dst_ip] = {int(dst_port)}
        else:
            PortCountDict[src_ip, dst_ip].add(int(dst_port))

pprint(PortCountDict)
