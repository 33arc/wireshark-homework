from collections import Counter,defaultdict
from scapy.all import DNS,DNSQR,DNSRR,IP,UDP,TCP
from scapy.layers.http import HTTPRequest,HTTPResponse
from scapy.layers.tls.all import TLSClientHello, TLSServerHello

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

def dns_analysis(packets):
    dns_queries=0
    domains=set()
    resolutions=defaultdict(set)
    protocols=set()
    ports=set()

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            dns=pkt[DNS]
            # count queries
            if dns.qr == 0 and dns.qd:
                dns_queries+=1
                domain=dns.qd.qname.decode(errors="ignore").rstrip(".")
                domains.add(domain)
            # extract responses (A records only)
            if dns.qr == 1 and dns.an:
                for i in range(dns.ancount):
                    ans=dns.an[i]
                    if isinstance(ans,DNSRR) and ans.type==1: # A record
                        domain=ans.rrname.decode(errors="ignore").rstrip(".")
                        resolutions[domain].add(ans.rdata)
            # transport info
            if pkt.haslayer(UDP):
                protocols.add("UDP")
                ports.add(pkt[UDP].dport)

    return {
        "total_queries":dns_queries,
        "unique_domains":domains,
        "resolutions":resolutions,
        "protocols":protocols,
        "ports":ports
    }

def tcp_analysis(packets):
    connections = defaultdict(dict)
    completed_handshakes=[]

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip=pkt[IP]
            tcp=pkt[TCP]

            src=ip.src
            dst=ip.dst
            sport=tcp.sport
            dport=tcp.dport

            connection_key=(src,dst,sport,dport)

            if tcp.flags=="S": # SYN
                connections[connection_key]["SYN"]=True
            elif tcp.flags=="SA": # SYN-ACK
                reverse_key=(dst,src,dport,sport)
                connections[reverse_key]["SYN-ACK"]=True
            elif tcp.flags=="A": # ACK
                if "SYN" in connections[connection_key] and \
                        "SYN-ACK" in connections[connection_key]:
                            connections[connection_key]["ACK"]=True
                            # Handshake completed
                            completed_handshakes.append(connection_key)
    total_connections = len(connections)
    return {
        "total_connections":total_connections,
        "completed_handshakes":completed_handshakes
    }

def http_https_analysis(packets):
    http_requests=[]
    http_responses=[]
    tls_info=[]

    for pkt in packets:
        # for http
        if pkt.haslayer(HTTPRequest):
            http=pkt[HTTPRequest]
            host=http.Host.decode() if http.Host else "Unknown"
            method = http.Method.decode()
            http_requests.append({
                "method":method,
                "host":host
            })
        if pkt.haslayer(HTTPResponse):
            response=pkt[HTTPResponse]
            code=response.Status_Code.decode()
            content_type=response.Content_Type.decode() if response.Content_Type else "Unknown"
            http_responses.append({
                "status":code,
                "content_type":content_type
            })
        # TLS/HTTP
        if pkt.haslayer(TLSClientHello):
            ch=pkt[TLSClientHello]
            tls_info.append({
                "type":"Client Hello",
                "version":ch.version
            })
        if pkt.haslayer(TLSServerHello):
            sh=pkt[TLSServerHello]
            tls_info.append({
                "type":"Server Hello",
                "version":sh.version,
                "cipher":sh.cipher
            })

    return {
        "http_requests":http_requests,
        "http_responses":http_responses,
        "tls_info":tls_info
    }

