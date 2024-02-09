#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>

// 定义模块参数
static char *protocol = "tcp"; // 默认协议为TCP
static char *src_ip = "0.0.0.0"; // 默认源IP
static char *dest_ip = "0.0.0.0"; // 默认目的IP
static int src_port = 0; // 默认源端口，0表示所有端口
static int dest_port = 0; // 默认目的端口，0表示所有端口
static char *action = "drop"; // 默认行为是drop，可以是 "accept" 或 "drop"

// 注册模块参数
module_param(protocol, charp, 0000);
MODULE_PARM_DESC(protocol, "Protocol to filter (tcp/udp)");
module_param(src_ip, charp, 0000);
MODULE_PARM_DESC(src_ip, "Source IP address to filter");
module_param(dest_ip, charp, 0000);
MODULE_PARM_DESC(dest_ip, "Destination IP address to filter");
module_param(src_port, int, 0000);
MODULE_PARM_DESC(src_port, "Source port number to filter");
module_param(dest_port, int, 0000);
MODULE_PARM_DESC(dest_port, "Destination port number to filter");
module_param(action, charp, 0000);
MODULE_PARM_DESC(action, "Action on packets (accept/drop)");

static struct nf_hook_ops netfilter_ops;

unsigned int main_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    u32 src_ip_addr, dest_ip_addr;
    u16 source, dest;
    
    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    // 将字符串IP地址转换为网络字节序的整数
    in4_pton(src_ip, -1, (u8 *)&src_ip_addr, -1, NULL);
    in4_pton(dest_ip, -1, (u8 *)&dest_ip_addr, -1, NULL);

    // 对于TCP协议
    if (ip_header->protocol == IPPROTO_TCP && strcmp(protocol, "tcp") == 0) {
        tcp_header = tcp_hdr(skb);
        source = ntohs(tcp_header->source);
        dest = ntohs(tcp_header->dest);

        if ((src_ip_addr == ip_header->saddr || src_ip_addr == 0) &&
            (dest_ip_addr == ip_header->daddr || dest_ip_addr == 0) &&
            (src_port == source || src_port == 0) &&
            (dest_port == dest || dest_port == 0)) {
            if (strcmp(action, "drop") == 0) {
                printk(KERN_INFO "Dropping TCP packet from %pI4:%d to %pI4:%d\n",
                    &ip_header->saddr, source, &ip_header->daddr, dest);
                return NF_DROP;
            } else {
                printk(KERN_INFO "Accepting TCP packet from %pI4:%d to %pI4:%d\n",
                    &ip_header->saddr, source, &ip_header->daddr, dest);
                return NF_ACCEPT;
            }
        }
    }

    // 对于UDP协议
    if (ip_header->protocol == IPPROTO_UDP && strcmp(protocol, "udp") == 0) {
        udp_header = udp_hdr(skb);
        source = ntohs(udp_header->source);
        dest = ntohs(udp_header->dest);

        if ((src_ip_addr == ip_header->saddr || src_ip_addr == 0) &&
            (dest_ip_addr == ip_header->daddr || dest_ip_addr == 0) &&
            (src_port == source || src_port == 0) &&
            (dest_port == dest || dest_port == 0)) {
            if (strcmp(action, "drop") == 0) {
                printk(KERN_INFO "Dropping UDP packet from %pI4:%d to %pI4:%d\n",
                    &ip_header->saddr, source, &ip_header->daddr, dest);
                return NF_DROP;
            } else {
                printk(KERN_INFO "Accepting UDP packet from %pI4:%d to %pI4:%d\n",
                    &ip_header->saddr, source, &ip_header->daddr, dest);
                return NF_ACCEPT;
            }
        }
    }

    // 如果不匹配，根据action参数接受或丢弃这个包
    if (strcmp(action, "drop") == 0) {
        return NF_DROP;
    } else {
        return NF_ACCEPT;
    }
}

int setup_filter(void) {
    printk(KERN_INFO "Registering filter.\n");
    netfilter_ops.hook = main_hook;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops);
    return 0;
}

void remove_filter(void) {
    printk(KERN_INFO "Filter is being removed.\n");
    nf_unregister_net_hook(&init_net, &netfilter_ops);
}

module_init(setup_filter);
module_exit(remove_filter);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Karui2awa");
MODULE_DESCRIPTION("A network filter module");

