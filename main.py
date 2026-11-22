import argparse
import time
from scapy.all import IP, TCP, sr1, send, UDP, ICMP
from concurrent.futures import ThreadPoolExecutor

parser = argparse.ArgumentParser()

parser.add_argument("--timeout", type=float, default=2)
parser.add_argument("ip_address")
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("-j", "--num-threads", type=int, default=10)
parser.add_argument("protocols", nargs="+")

args = parser.parse_args()

def tcp_scan(ip,port,timeout,is_time):
    packet = IP(dst=ip) / TCP(dport=port,flags="S")

    start = time.perf_counter()
    response = sr1(packet,timeout=timeout,verbose=0)
    elapsed = (time.perf_counter() - start) * 1000

    if response is None or not response.haslayer(TCP):
        return

    flags = int(response[TCP].flags)

    if flags & 0x12 == 0x12:
        packet = IP(dst=ip) / TCP(sport=packet[TCP].sport,dport=port,flags="R",seq=response[TCP].ack)

        send(packet, verbose=0)

        if is_time:
            print(f"TCP {port} {elapsed:.2f}")
        else:
            print(f"TCP {port}")


def udp_scan(ip, port, timeout):
    packet = IP(dst=ip) / UDP(dport=port)

    response = sr1(packet, timeout=timeout, verbose=0)

    if response is None:
        return

    if response.haslayer(ICMP):
        if response[ICMP].type == 3 and response[ICMP].code == 3:
            return

    if response.haslayer(UDP):
        print(f"UDP {port}")



for protocol in args.protocols:
    parts = protocol.split("/")

    protocol_name = parts[0]

    if len(parts) == 1:
        ports = range(1, 65536)
    else:
        ports = set()

        for port in parts[1].split(","):
            if "-" in port:
                start, end = map(int, port.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(port))

    with ThreadPoolExecutor(max_workers=args.num_threads) as executor:
        for port in ports:
            if protocol_name == "tcp":
                executor.submit(tcp_scan, args.ip_address, port, args.timeout, args.verbose)

            elif protocol_name == "udp":
                executor.submit(udp_scan, args.ip_address, port, args.timeout)