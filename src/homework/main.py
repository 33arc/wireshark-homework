import sys
from .reader import load_pcap
from .summary import summarize_packets,dns_analysis,tcp_analysis,http_https_analysis

def display_dns_report(report):
    print("\n===================DNS REPORT===================")
    print(f"\nDuring capture, {report['total_queries']} DNS query packets were observed")
    print(f"{len(report["unique_domains"])} unique domains were queried.")
    for domain,ips in report["resolutions"].items():
        if ips:
            print(f"The domain {domain} was resolved to:")
            for ip in sorted(ips):
                print(f"    -   {ip}")
            print()
    if report["protocols"]:
        print("DNS operates over UDP port 53.")

def display_tcp_report(report):
    print("\n===================TCP REPORT===================")
    if report["completed_handshakes"]:
        for i in report['completed_handshakes']:
            client_ip = i[0]
            server_ip = i[1]
            print(f"A TCP three-way handshake was observed between client "
                  f"({client_ip}) and server ({server_ip}).")
    else:
        print("No complete TCP three-way handshake was observed.")
    print(f"\nTotal TCP connections observed: {report['total_connections']}")

def display_web_report(web_report):
    print("\n===================HTTP/HTTPS REPORT===================")
    # http
    if web_report['http_requests']:
        print("HTTP traffic was observed.\n")
        for req in web_report['http_requests']:
            print(f'GET request detected for host: {req['host']}')
        for res in web_report['http_responses']:
            print(f'Response Code: {res['status']}')
            print(f'Content-Type: {res['content_type']}')
    else:
        print("No HTTP traffic detected.")
    # https
    if web_report['tls_info']:
        print('HTTPS (TLS) traffic was observed.\n')
        for entry in web_report['tls_info']:
            if entry['type']=='Client Hello':
                print('TLS Client Hello detected.')
                print(f'TLS Version: {entry['version']}')
            elif entry['type']=='Server Hello':
                print('TLS Server Hello detected.')
                print(f'TLS Version: {entry['version']}')
                print(f'Cipher Suite: {entry['cipher']}')
        print('\nImportant Point:')
        print('HTTPS is encrypted. Page content cannot be viewed only handshake details.')
    else:
        print("No HTTPS traffic detected.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m homework.main <file.pcapng>")
        sys.exit(1)

    path = sys.argv[1]
    packets = load_pcap(path)

    # 1. DNS analysis
    dns_report = dns_analysis(packets)
    display_dns_report(dns_report)
    # 2. TCP analysis
    tcp_report = tcp_analysis(packets)
    display_tcp_report(tcp_report)
    # 3. HTTP/HTTPS analysis
    web_report = http_https_analysis(packets)
    display_web_report(web_report)
    # 4. final
    result = summarize_packets(packets)

    print("Total packets:", result["total_packets"])
    print("Protocol breakdown")
    for proto,count in result["protocol_counts"].items():
        print(f" {proto}: {count}")

if __name__ == "__main__":
    main()
