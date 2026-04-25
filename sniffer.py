"""
Co-Pilot Sniffing Project
Author: Jeffery L Parker
Course: CTEC450 
Instructor: Professor Carter
Assignment: Co-Pilot Sniffing Project Using

====================================================
README / HOW TO RUN
====================================================

Purpose:
This project demonstrates the use of AI-assisted development tools such as GitHub Copilot 
to build a network packet sniffer in an ethical and controlled manner. AI was used to 
generate code suggestions, assist with debugging, and improve development efficiency. 
However, all code was reviewed, tested, and modified to ensure accuracy, security, and 
compliance with ethical guidelines.

The project highlights how AI can support developers while still requiring human 
oversight, especially in security-related applications. Special care was taken to 
implement safeguards such as data redaction, IP masking, and restricted traffic capture 
to prevent misuse.

Ethical Use:
This tool is intended strictly for educational purposes and should only be used on 
authorized networks or local lab environments. Unauthorized packet sniffing is illegal 
and unethical.

Requirements:
- Python 3.10 or higher
- scapy (for packet capture and analysis)
- pytest (for unit testing)

Install dependencies using:
pip install -r requirements.txt

How it works:
The program uses the Scapy library to capture network packets in real time. It listens for 
specific types of traffic using a Berkeley Packet Filter (BPF), focusing on HTTP (port 80) 
and DNS (port 53) traffic.

When a packet is captured:
- The source and destination IP addresses are extracted and partially masked for privacy
- The protocol (TCP/UDP) and port information are displayed
- DNS queries are decoded and printed when present
- Any raw payload data is scanned and sensitive information such as emails, passwords, 
  tokens, or authorization headers is redacted

The program captures a limited number of packets (25) and then stops automatically.
====================================================
END OF README / REFLECTION
====================================================
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
import re


def mask_ip(ip_address):
    parts = ip_address.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return ip_address


def redact_sensitive_data(data):
    data = re.sub(r"[\w\.-]+@[\w\.-]+\.\w+", "[REDACTED_EMAIL]", data)
    data = re.sub(r"(?i)authorization:\s*\S+", "Authorization: [REDACTED]", data)
    data = re.sub(r"(?i)(password|token|session)=\S+", r"\1=[REDACTED]", data)
    return data


def process_packet(packet):
    print("\n--- Packet Captured ---")

    if IP in packet:
        print(f"Source IP: {mask_ip(packet[IP].src)}")
        print(f"Destination IP: {mask_ip(packet[IP].dst)}")
        print(f"Protocol: {packet[IP].proto}")

    if TCP in packet:
        print(f"TCP Source Port: {packet[TCP].sport}")
        print(f"TCP Destination Port: {packet[TCP].dport}")

    if UDP in packet:
        print(f"UDP Source Port: {packet[UDP].sport}")
        print(f"UDP Destination Port: {packet[UDP].dport}")

    if DNS in packet and packet.haslayer(DNSQR):
        print(f"DNS Query: {packet[DNSQR].qname.decode(errors='ignore')}")

    if Raw in packet:
        payload = packet[Raw].load.decode(errors="ignore")
        clean_payload = redact_sensitive_data(payload)
        print(f"Payload: {clean_payload}")


def main():
    print("Starting ethical packet sniffer...")
    print("Capturing only authorized lab traffic.")
    print("Press Ctrl+C to stop.\n")

    sniff(
        iface=None,
        count=25,
        filter="tcp port 80 or udp port 53",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()