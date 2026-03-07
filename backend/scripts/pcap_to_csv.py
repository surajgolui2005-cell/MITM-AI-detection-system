from scapy.all import rdpcap, IP, ARP, TCP, UDP, DNS, DNSQR, Raw
import os
import pandas as pd

# Paths relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

NORMAL_DIR = os.path.join(BASE_DIR, "../data/normal")
ATTACK_DIR = os.path.join(BASE_DIR, "../data/attack")
OUT_DIR = os.path.join(BASE_DIR, "../data/combined")

os.makedirs(OUT_DIR, exist_ok=True)


def extract_packet_info(pkt):

    info = {
        "timestamp": getattr(pkt, "time", None),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "length": len(pkt),
        "tcp_flags": None,
        "dns_qname": None,
        "http_method": None,
        "http_host": None,
        "tls_handshake": False
    }

    # ARP packets
    if ARP in pkt:
        info["protocol"] = "ARP"
        info["src_ip"] = pkt[ARP].psrc
        info["dst_ip"] = pkt[ARP].pdst
        return info

    # IP packets
    if IP in pkt:
        ip = pkt[IP]
        info["src_ip"] = ip.src
        info["dst_ip"] = ip.dst

        # TCP
        if TCP in pkt:
            t = pkt[TCP]
            info["protocol"] = "TCP"
            info["src_port"] = t.sport
            info["dst_port"] = t.dport
            info["tcp_flags"] = str(t.flags)

            if Raw in pkt:
                payload = bytes(pkt[Raw]).decode(errors="ignore")

                # HTTP detection
                for m in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "):
                    if payload.startswith(m):
                        info["http_method"] = m.strip()

                        for line in payload.split("\r\n"):
                            if line.lower().startswith("host:"):
                                info["http_host"] = line.split(":",1)[1].strip()
                                break
                        break

            # TLS detection
            if info["dst_port"] in (443, 8443) or info["src_port"] in (443, 8443):
                info["tls_handshake"] = True
            else:
                if Raw in pkt:
                    raw = bytes(pkt[Raw])
                    if len(raw) > 2 and raw[0] == 0x16 and raw[1] == 0x03:
                        info["tls_handshake"] = True

        # UDP
        elif UDP in pkt:
            u = pkt[UDP]
            info["protocol"] = "UDP"
            info["src_port"] = u.sport
            info["dst_port"] = u.dport

            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                info["protocol"] = "DNS"

                try:
                    if dns.qd and isinstance(dns.qd, DNSQR):
                        info["dns_qname"] = dns.qd.qname.decode().rstrip(".")
                except:
                    pass

        else:
            info["protocol"] = str(ip.proto)

        return info

    info["protocol"] = "OTHER"
    return info


def pcap_files_from_dir(directory):

    files = []

    if not os.path.isdir(directory):
        return files

    for f in os.listdir(directory):

        if f.lower().endswith((".pcap", ".pcapng")):
            files.append(os.path.join(directory, f))

    return sorted(files)


def parse_and_save(pcap_list, label, out_csv_path):

    rows = []

    for pcap in pcap_list:

        print("Reading", pcap)

        try:
            pkts = rdpcap(pcap)
        except Exception as e:
            print("Failed to read", pcap, ":", e)
            continue

        for pkt in pkts:

            try:
                info = extract_packet_info(pkt)
                info["label"] = label
                rows.append(info)
            except:
                continue

    if rows:

        df = pd.DataFrame(rows)

        cols = [
            "timestamp","src_ip","dst_ip","src_port","dst_port",
            "protocol","length","tcp_flags","dns_qname",
            "http_method","http_host","tls_handshake","label"
        ]

        df = df.reindex(columns=cols)

        df.to_csv(out_csv_path, index=False)

        print("Saved", len(df), "rows to", out_csv_path)

    else:
        print("No rows extracted")


def main():

    normal_pcaps = pcap_files_from_dir(NORMAL_DIR)
    attack_pcaps = pcap_files_from_dir(ATTACK_DIR)

    normal_csv = os.path.join(OUT_DIR, "normal_traffic.csv")
    attack_csv = os.path.join(OUT_DIR, "attack_traffic.csv")
    combined_csv = os.path.join(OUT_DIR, "combined_dataset.csv")

    parse_and_save(normal_pcaps, 0, normal_csv)
    parse_and_save(attack_pcaps, 1, attack_csv)

    dfs = []

    if os.path.exists(normal_csv):
        dfs.append(pd.read_csv(normal_csv))

    if os.path.exists(attack_csv):
        dfs.append(pd.read_csv(attack_csv))

    if dfs:

        combined = pd.concat(dfs, ignore_index=True)

        combined["tls_handshake"] = combined["tls_handshake"].fillna(False)

        combined.to_csv(combined_csv, index=False)

        print("Combined dataset saved to", combined_csv)

    else:

        print("No CSV files to combine")


if __name__ == "__main__":
    main()