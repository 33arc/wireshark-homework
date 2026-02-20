from scapy.all import rdpcap

def load_pcap(path: str):
    return rdpcap(path)
