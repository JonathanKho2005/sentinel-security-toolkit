from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr

def syn_scan(host, ports):
    # Send Syn packets
    answered, unanswered = sr(IP(dst = host)/TCP(dport = ports, flags = "S"), timeout = 2, verbose = False)

    # Create results list to store status of each Syn packets
    results = []

    # Process answered packets
    for (sent,received) in answered:
        d_port = sent[TCP].dport

        if sent[TCP].dport == received[TCP].sport:
            if received[TCP].flags == "SA":
                results.append({"port" : d_port, "protocol" : "TCP", "scan" : "SYN", "status" : "open"})
            elif received[TCP].flags == "RA":
                results.append({"port" : d_port, "protocol" : "TCP", "scan" : "SYN",  "status": "closed"})

    # Process unanswered packets
    for sent in unanswered:
        d_port = sent[TCP].dport
        results.append({"port" : d_port, "protocol" : "TCP", "scan" : "SYN",  "status" : "filtered"})

    return results