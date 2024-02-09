import os
import sys
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP

# 定义数据包处理功能
def process_packet(packet):

    scapy_packet = IP(packet.get_payload())
    # 判断是否符合过滤条件
    if scapy_packet.haslayer(TCP) or scapy_packet.haslayer(UDP):
        if (scapy_packet[IP].src == src_ip and
                scapy_packet[IP].dst == dst_ip and
                scapy_packet[TCP].sport == src_port and
                scapy_packet[TCP].dport == dst_port):
            print('Dropping packet::{} ->:{} {}'.format(scapy_packet[IP].src,
                                                               scapy_packet[TCP].sport,
                                                               scapy_packet[IP].dst,
                                                               scapy_packet[TCP].dport,
                                                               scapy_packet[IP].proto))
            packet.drop()
            return

    packet.accept()

# 设置命令行参数
if len(sys.argv) != 6:
    print("Usage: python fw.py <TCP/UDP> <src_ip> <dst_ip> <src_port> <dst_port>")
    sys.exit(1)

_, protocol, src_ip, dst_ip, src_port, dst_port = sys.argv
src_port = int(src_port)
dst_port = int(dst_port)

# 设置iptables规则进行包的DNAT到nfqueue
os.system(f"iptables -I INPUT -p {protocol.lower()} --source {src_ip} --destination {dst_ip} --sport {src_port} --dport {dst_port} -j NFQUEUE --queue-num 1")
os.system(f"iptables -I OUTPUT -p {protocol.lower()} --source {src_ip} --destination {dst_ip} --sport {src_port} --dport {dst_port} -j NFQUEUE --queue-num 1")

# 创建netfilter队列实例并配置处理函数
nfqueue = NetfilterQueue()
nfqueue.bind(1, process_packet)

try:
    print("Starting firewall...")
    nfqueue.run()
except KeyboardInterrupt:
    pass
finally:
    # 在退出程序时移除iptables规则
    os.system(f"iptables -D INPUT -p {protocol.lower()} --source {src_ip} --destination {dst_ip} --sport {src_port} --dport {dst_port} -j NFQUEUE --queue-num 1")
    os.system(f"iptables -D OUTPUT -p {protocol.lower()} --source {src_ip} --destination {dst_ip} --sport {src_port} --dport {dst_port} -j NFQUEUE --queue-num 1")
    nfqueue.unbind()
    print("Firewall stopped.")


