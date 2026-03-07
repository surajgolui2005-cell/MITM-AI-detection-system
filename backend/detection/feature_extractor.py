from scapy.all import IP, TCP, UDP, ARP


def extract_features(pkt):
    """
    Extract relevant network features from a packet
    to be used for ML prediction or dataset creation.
    """

    features = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": 0,
        "dst_port": 0,
        "protocol": 0,
        "length": len(pkt)
    }

    # ARP packets (common in MITM attacks)
    if ARP in pkt:
        features["protocol"] = 1
        features["src_ip"] = pkt[ARP].psrc
        features["dst_ip"] = pkt[ARP].pdst

    # IP packets
    elif IP in pkt:
        features["src_ip"] = pkt[IP].src
        features["dst_ip"] = pkt[IP].dst

        # TCP packets
        if TCP in pkt:
            features["protocol"] = 6
            features["src_port"] = pkt[TCP].sport
            features["dst_port"] = pkt[TCP].dport

        # UDP packets
        elif UDP in pkt:
            features["protocol"] = 17
            features["src_port"] = pkt[UDP].sport
            features["dst_port"] = pkt[UDP].dport

        # Other IP protocols
        else:
            features["protocol"] = pkt[IP].proto

    return features