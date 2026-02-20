import sys
from .reader import load_pcap
from .summary import summarize_packets

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m homework.main <file.pcapng>")
        sys.exit(1)

    path = sys.argv[1]
    packets = load_pcap(path)

    # 1. DNS analysis
    # 2. TCP analysis
    # 3. HTTP/HTTPS analysis
    result = summarize_packets(packets)

    print("Total packets:", result["total_packets"])
    print("Protocol breakdown")
    for proto,count in result["protocol_counts"].items():
        print(f" {proto}: {count}")

if __name__ == "__main__":
    main()
