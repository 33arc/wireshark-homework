from collections import Counter

def summarize_packets(packets):
    total = len(packets)

    protocols = Counter()
    for pkt in packets:
        if pkt.haslayer("TCP"):
            protocols["TCP"]+=1
        elif pkt.haslayer("UDP"):
            protocols["UDP"]+=1
        elif pkt.haslayer("ICMP"):
            protocols["ICMP"]+=1
    return {
        "total_packets": total,
        "protocol_counts":dict(protocols),
    }
