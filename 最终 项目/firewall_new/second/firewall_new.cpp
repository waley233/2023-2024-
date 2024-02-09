#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <getopt.h>
#include <chrono>
#include <iomanip>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <csignal>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct Params {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;
    bool drop = false;
};

Params params;

static int onPacketReceived(nfq_q_handle *queueHandle, struct nfgenmsg *nfmsg, nfq_data *nfa, void *data) {
    Params *params = reinterpret_cast<Params*>(data);

    uint32_t id = 0;
    nfqnl_msg_packet_hdr *header;

    header = nfq_get_msg_packet_hdr(nfa);
    if (header) {
        id = ntohl(header->packet_id);
    }

    int verdict = NF_ACCEPT;
    unsigned char *pktData;
    struct iphdr *ipHeader;
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;

    int len = nfq_get_payload(nfa, &pktData);
    if (len >= 0) {
        ipHeader = reinterpret_cast<struct iphdr*>(pktData);
        if (ipHeader->protocol == IPPROTO_TCP && params->protocol == "tcp") {
            tcpHeader = reinterpret_cast<struct tcphdr*>(pktData + (ipHeader->ihl * 4));
            if ((params->src_port == 0 || ntohs(tcpHeader->source) == params->src_port) &&
                (params->dst_port == 0 || ntohs(tcpHeader->dest) == params->dst_port)) {
                verdict = params->drop ? NF_DROP : NF_ACCEPT;
            }
        } else if (ipHeader->protocol == IPPROTO_UDP && params->protocol == "udp") {
            udpHeader = reinterpret_cast<struct udphdr*>(pktData + (ipHeader->ihl * 4));
            if ((params->src_port == 0 || ntohs(udpHeader->source) == params->src_port) &&
                (params->dst_port == 0 || ntohs(udpHeader->dest) == params->dst_port)) {
                verdict = params->drop ? NF_DROP : NF_ACCEPT;
            }
        }
    }

    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);

    if (len > 0) {
        std::cout << "Payload:" << std::endl;
        for (int i = 0; i < len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)pktData[i];
            if ((i + 1) % 16 == 0) std::cout << std::endl;
            else if ((i + 1) % 8 == 0) std::cout << "  ";
            else std::cout << " ";
        }
        std::cout << std::dec << std::endl;
    }

    std::cout << "[" << std::put_time(std::localtime(&now_c), "%F %T") << "] ";
    std::cout << (verdict == NF_DROP ? "Dropping" : "Accepting") << " packet." << std::endl;

    return nfq_set_verdict(queueHandle, id, verdict, 0, nullptr);
}

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " [OPTIONS]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --src-ip IP          Source IP address to filter" << std::endl;
    std::cout << "  --src-port PORT      Source port number to filter" << std::endl;
    std::cout << "  --dst-ip IP          Destination IP address to filter" << std::endl;
    std::cout << "  --dst-port PORT      Destination port number to filter" << std::endl;
    std::cout << "  --protocol PROTOCOL  Protocol to filter (tcp or udp)" << std::endl;
    std::cout << "  --drop               Drop packets instead of accepting" << std::endl;
}

bool parseCommandLine(int argc, char** argv) {
    const char* const short_opts = "s:S:d:D:p:hx";
    const option long_opts[] = {
        {"src-ip", required_argument, nullptr, 's'},
        {"src-port", required_argument, nullptr, 'S'},  // Change here
        {"dst-ip", required_argument, nullptr, 'd'},
        {"dst-port", required_argument, nullptr, 'D'},  // And here
        {"protocol", required_argument, nullptr, 'p'},
        {"drop", no_argument, nullptr, 'x'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, no_argument, nullptr, 0}
};


    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 's':
                params.src_ip = optarg;
                break;
            case 'S':
    params.src_port = static_cast<uint16_t>(std::stoi(optarg));
    break;
            case 'd':
                params.dst_ip = optarg;
                break;
            case 'D':
    params.dst_port = static_cast<uint16_t>(std::stoi(optarg));
    break;
            case 'p':
                params.protocol = optarg;
                break;
            case 'x':
                params.drop = true;
                break;
            case 'h': // -h or --help
            case '?': // Unrecognized option
            default:
                printUsage(argv[0]);
                return false;
        }
    }
	if (params.src_port == 0) {
        	std::cout << "No source port specified, defaults to all ports." << std::endl;
    	}
    	if (params.dst_port == 0) {
    	    std::cout << "No destination port specified, defaults to all ports." << std::endl;
    	}
    return true;
}

void cleanup() {
    system("sudo iptables -F");
}

void signalHandler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    cleanup();
    exit(signum);
}

int main(int argc, char** argv) {
    atexit(cleanup);
    signal(SIGINT, signalHandler);
    system("sudo iptables -I INPUT -j NFQUEUE --queue-num 0");
    if (!parseCommandLine(argc, argv)) {
        return EXIT_FAILURE;
    }

    struct nfq_handle *nfqHandle;
    struct nfq_q_handle *queueHandle;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    nfqHandle = nfq_open();
    if (!nfqHandle) {
        std::cerr << "Error: nfq_open() failed." << std::endl;
        return EXIT_FAILURE;
    }

    if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
        std::cerr << "Error: nfq_unbind_pf() failed." << std::endl;
        return EXIT_FAILURE;
    }

    if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
        std::cerr << "Error: nfq_bind_pf() failed." << std::endl;
        return EXIT_FAILURE;
    }

    queueHandle = nfq_create_queue(nfqHandle, 0, &onPacketReceived, &params);

    if (!queueHandle) {
        std::cerr << "Error: nfq_create_queue() failed." << std::endl;
        return EXIT_FAILURE;
    }

    if (nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Error: can't set packet_copy mode." << std::endl;
        return EXIT_FAILURE;
    }

    fd = nfq_fd(nfqHandle);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(nfqHandle, buf, rv);
    }

    nfq_destroy_queue(queueHandle);
    nfq_close(nfqHandle);
    return EXIT_SUCCESS;
}


