from scapy.layers.inet import IP, TCP, ICMP
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

def xmas_scan(host, ports):
    # Send xmas packets
    answered, unanswered = sr(IP(dst = host)/TCP(dport = ports, flags = "FPU"), timeout = 2, verbose = False)

    # Create results list to store status of each xmas packets
    results = []

    # Process answered packets
    for (sent,received) in answered:
        d_port = sent[TCP].dport    # Check if a TCP packet is received
        if received.haslayer(TCP):
            flags = received.getlayer(TCP).flags
            if flags == "R" or flags == "RA":
                results.append({"port" : d_port, "protocol" : "TCP", "scan" : "XMAS", "status" : "closed"})

        if received.haslayer(ICMP):
            type = int(received.getlayer(ICMP).type)
            code = int(received.getlayer(ICMP).code)
            if type == 3 and code in [1,2,3,9,10,13]:
                results.append({"port": d_port, "protocol" : "ICMP", "scan" : "XMAS", "status" : "filtered"})

    # Process unanswered packets
    for sent in unanswered:
        d_port = sent[TCP].dport
        results.append({"port" : d_port, "protocol" : "TCP", "scan" : "XMAS", "status" : "open/filtered"})

    return results

