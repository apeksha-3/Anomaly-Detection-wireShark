import asyncio
import pyshark
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import deque, Counter, defaultdict
from datetime import datetime

try:
    asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

print("Starting Real-Time Anomaly Detection with Visualization...")

INTERFACE = "Wi-Fi"
capture = pyshark.LiveCapture(interface=INTERFACE)

#                       tree banata hai    ho sakti hai    same tree bana chahiye kitne baar bi run kar le toh (seed) 
#                              |                  |                   |
model = IsolationForest(n_estimators=100, contamination=0.08, random_state=42) # Automatic model hai khud sse kar leta hai 
packet_features = deque(maxlen=300) # src ip , dest ip , ...
packet_lengths = deque(maxlen=300)  # size of packet
packet_indices = deque(maxlen=300)  # index of packet


plt.ion()  # interactive plot on -> packet len vs packet index
fig, ax = plt.subplots(figsize=(10, 6))
ax.set_title("Live Network Anomaly Detection")
ax.set_xlabel("Packet Index")
ax.set_ylabel("Packet Length (bytes)")
plt.tight_layout()


def extract_features(pkt):
    """Extract numeric features from each packet."""
    try:
        length = int(pkt.length)
        proto = hash(pkt.highest_layer) % 1000     # hash is used -> to find 
        src_ip = getattr(pkt.ip, 'src', '0.0.0.0') if hasattr(pkt, 'ip') else '0.0.0.0'
        dst_ip = getattr(pkt.ip, 'dst', '0.0.0.0') if hasattr(pkt, 'ip') else '0.0.0.0'
        src = hash(src_ip) % 10000
        dst = hash(dst_ip) % 10000
        port = int(getattr(pkt, 'udp', getattr(pkt, 'tcp', None)).srcport) if hasattr(pkt, 'udp') or hasattr(pkt, 'tcp') else 0
        return [length, proto, src, dst, port, src_ip, dst_ip]
    except Exception:
        return None

def classify_anomaly(feat, avg_len):
    """Categorize anomaly type based on simple rules."""
    length, proto, src, dst, port, _, _ = feat
    if length > 1500:
        return "Large Packet Flood"
    elif src == dst or src == 0 or dst == 0:
        return "Spoofed Address"
    elif port > 50000:
        return "Suspicious Port Activity"
    elif length > avg_len * 1.8:
        return "Traffic Spike"
    else:
        return "Unknown"

def update_plot():
    """Update live plot."""
    ax.clear()
    ax.set_title("Live Network Anomaly Detection")
    ax.set_xlabel("Packet Index")
    ax.set_ylabel("Packet Length (bytes)")

    ax.plot(packet_indices, packet_lengths, color="green", label="Normal Traffic")

    colors = {
        "Traffic Spike": ("red", "o"),
        "Large Packet Flood": ("orange", "x"),
        "Suspicious Port Activity": ("purple", "s"),
        "Spoofed Address": ("blue", "D"),
        "Unknown": ("black", "^")
    }

    for atype, (color, marker) in colors.items():
        indices = [i for i, f in zip(packet_indices, packet_features)
                   if "type" in f and f["type"] == atype]
        values = [f["length"] for f in packet_features if "type" in f and f["type"] == atype]
        ax.scatter(indices, values, color=color, s=35, marker=marker, label=atype)

    ax.legend(loc="upper right")
    plt.pause(0.05)


anomaly_log = []
anomaly_sources = defaultdict(int)
start_time = datetime.now()
total_packets = 0

print("Listening for packets... Press Ctrl+C to stop.\n")

try:
    for idx, pkt in enumerate(capture.sniff_continuously(packet_count=0)):  # isse aaye jare hai packet 
        feat = extract_features(pkt)
        if not feat:
            continue

        total_packets += 1
        packet_features.append({"length": feat[0], "feat": feat})
        packet_lengths.append(feat[0])
        packet_indices.append(idx)

        if len(packet_features) > 30:
            df = np.array([f["feat"][:5] for f in packet_features])  # use only numeric features
            preds = model.fit_predict(df)
            avg_len = np.mean([f["feat"][0] for f in packet_features])

            for i, p in enumerate(preds):
                if p == -1:
                    anomaly_type = classify_anomaly(packet_features[i]["feat"], avg_len)
                    packet_features[i]["type"] = anomaly_type
                    anomaly_log.append(anomaly_type)

                    
                    src_ip = packet_features[i]["feat"][5]
                    anomaly_sources[src_ip] += 1

                    print(f"Anomaly Detected -> {anomaly_type} | Src: {src_ip}")
                else:
                    packet_features[i]["type"] = "Normal"

        update_plot()

except KeyboardInterrupt:
    print("\nCapture stopped by user.")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Summary section
    print("\n========== FINAL ANOMALY SUMMARY ==========")
    print(f"Capture Duration: {duration:.2f} seconds")
    print(f"Total Packets Captured: {total_packets}")
    if anomaly_log:
        counts = Counter(anomaly_log)
        total_anomalies = sum(counts.values())
        anomaly_percent = (total_anomalies / total_packets * 100) if total_packets else 0
        print(f"Total Anomalies Detected: {total_anomalies} ({anomaly_percent:.2f}%)\n")
        print("Breakdown by Type:")
        for k, v in counts.items():
            print(f"   . {k:30s}: {v}")
    else:
        print("No anomalies detected.")

    print("----------------------------------------------")
    print(f"Average Packet Length: {np.mean(packet_lengths):.2f} bytes")
    print(f"Maximum Packet Length: {np.max(packet_lengths):.2f} bytes")

  
    if anomaly_sources:
        print("\nSources Involved in Anomalies:")
        print(f"{'Source IP':<20} {'# of Anomalies':<15}")
        print("-" * 35)
        for src, count in sorted(anomaly_sources.items(), key=lambda x: x[1], reverse=True):
            print(f"{src:<20} {count:<15}")
    else:
        print("\nNo specific source anomalies detected.")

    print("----------------------------------------------")
    print(f"Session Ended At: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("==============================================\n")

    
    with open("anomaly_report.txt", "w") as f:
        f.write("==== Anomaly Detection Report ====\n")
        f.write(f"Start Time : {start_time}\nEnd Time   : {end_time}\nDuration   : {duration:.2f}s\n\n")
        f.write(f"Total Packets : {total_packets}\n")
        if anomaly_log:
            for k, v in counts.items():
                f.write(f"{k}: {v}\n")
            f.write(f"Total Anomalies : {total_anomalies}\n\n")
            f.write("Source IPs Involved in Anomalies:\n")
            for src, count in anomaly_sources.items():
                f.write(f"{src} : {count}\n")
        else:
            f.write("No anomalies detected.\n")
        f.write(f"\nAverage Length: {np.mean(packet_lengths):.2f}\n")
        f.write(f"Max Length: {np.max(packet_lengths):.2f}\n")
    print("Summary saved to 'anomaly_report.txt'")

finally:
    capture.close()
    plt.ioff()
    plt.show()
    print("Capture closed successfully.")