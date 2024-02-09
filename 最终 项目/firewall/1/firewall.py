import os
import sys
import netfilterqueue
from scapy.all import IP, TCP, UDP

# 定义包处理函数
def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(TCP) or scapy_packet.haslayer(UDP):
        if scapy_packet[TCP].dport == target_port or scapy_packet[TCP].sport == source_port:
            print("Blocking packet that matched the filter")
            packet.drop()
        else:
            packet.accept()
    else:
        packet.accept()

# 设置命令行参数
if len(sys.argv) != 6:
    print("Usage: python firewall.py <TCP/UDP> <source_ip> <dest_ip> <source_port> <dest_port>")
    sys.exit(1)

protocol = sys.argv[1]
source_ip = sys.argv[2]
dest_ip = sys.argv[3]
source_port = int(sys.argv[4])
dest_port = int(sys.argv[5])

# 设置Netfilter队列
os.system(f"iptables -I INPUT -p {protocol} --source {source_ip} --destination {dest_ip} --sport {source_port} --dport {dest_port} -j NFQUEUE --queue-num 1")
nfqueue = netfilterqueue.NetfilterQueue()
nfqueue.bind(1, process_packet)

try:
    print("Starting firewall...")
    nfqueue.run()
except KeyboardInterrupt:
    pass
finally:
    nfqueue.unbind()
    os.system("iptables --flush")

