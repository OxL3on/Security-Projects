#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>


#define TAB_1      "\t "
#define TAB_2      "\t\t "
#define TAB_3      "\t\t\t "
#define TAB_4      "\t\t\t\t "
#define DATA_TAB_3 "\t\t\t "


void get_mac_addr(const uint8_t *bytes, char *out)
{
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
}

void format_multi_line(const char *prefix, const uint8_t *data, int len, int width) 
{
    int prefix_len = (int)strlen(prefix);
    int usable = width - prefix_len;
    if (usable % 2 != 0) usable--;
    if (usable <= 0) usable = 4;

    int bytes_per_line = usable / 4;
    if (bytes_per_line < 1) bytes_per_line = 1;

    for (int i = 0; i < len; i++) {
        if (i % bytes_per_line == 0) {
            if (i != 0) printf("\n");
            printf("%s", prefix);
        }
        printf("\\x%02x", data[i]);
    }
    if (len > 0) printf("\n");
}

typedef struct {
    char     dest_mac[18];
    char     src_mac[18];
    uint16_t eth_proto;
    const uint8_t *payload;
    int      payload_len;
} EthernetFrame;

int parse_ethernet(const uint8_t *data, int data_len, EthernetFrame *frame)
{
    if (data_len < 14) return 0;
    
    get_mac_addr(data, frame->dest_mac);
    get_mac_addr(data + 6,  frame->src_mac);

    uint16_t proto_raw;
    memcpy(&proto_raw, data + 12, 2);
    frame->eth_proto = ntohs(proto_raw);

    frame->payload = data + 14;
    frame->payload_len = data_len - 14;

    return 1;
}

typedef struct  {
    int version;
    int header_length;
    int ttl;
    int proto;
    char src_ip[16];
    char dest_ip[16];
    const uint8_t *payload;
    int payload_len;
} IPv4Packet;


int parse_ipv4(const uint8_t *data, int data_len, IPv4Packet *pkt)
{
    if (data_len < 20) return 0;

    uint8_t version_ihl = data[0];

    pkt->version = version_ihl >> 4;

    pkt->header_length = (version_ihl & 0x0F) * 4;

    pkt->ttl = data[8];
    pkt->proto = data[9];

    struct in_addr src_addr, dest_addr;
    memcpy(&src_addr, data + 12, 4);
    memcpy(&dest_addr, data + 16, 4);
    strncpy(pkt->src_ip, inet_ntoa(src_addr), sizeof(pkt->src_ip) - 1);
    strncpy(pkt->dest_ip, inet_ntoa(dest_addr), sizeof(pkt->dest_ip) - 1);

    pkt->payload = data + pkt->header_length;
    pkt->payload_len = data_len - pkt->header_length;
    if (pkt->payload_len < 0) pkt->payload_len = 0;

    return 1;
}

typedef struct {
    int icmp_type;
    int code;
    uint16_t checksum;
    const uint8_t *payload;
    int payload_len;
} IcmpPacket;

int parse_icmp(const uint8_t *data, int data_len, IcmpPacket *pkt)
{
    if (data_len < 4) return 0;

    pkt->icmp_type = data[0];
    pkt->code = data[1];

    uint16_t chk_raw;
    memcpy(&chk_raw, data + 2, 2);
    pkt->checksum = ntohs(chk_raw);

    pkt->payload = data + 4;
    pkt->payload_len = data_len -4;
    return 1;
}

typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence;
    uint32_t acknowledgement;
    int offset;
    int flag_urg, flag_ack, flag_psh;
    int flag_rst, flag_syn, flag_fin;
    const uint8_t *payload;
    int payload_len;
} TcpSegment;



int parse_tcp(const uint8_t *data, int data_len, TcpSegment *seg)
{
    if (data_len < 20) return 0;

    uint16_t sp, dp;
    uint32_t seq, ack;
    memcpy(&sp,  data,      2);  seg->src_port        = ntohs(sp);
    memcpy(&dp,  data + 2,  2);  seg->dest_port       = ntohs(dp);
    memcpy(&seq, data + 4,  4);  seg->sequence        = ntohl(seq);
    memcpy(&ack, data + 8,  4);  seg->acknowledgement = ntohl(ack);

    uint16_t offset_reserved_flag;
    memcpy(&offset_reserved_flag, data + 12, 2);
    offset_reserved_flag = ntohs(offset_reserved_flag);

    seg->offset = (offset_reserved_flag >> 12) * 4;

    seg->flag_urg = (offset_reserved_flag & 32) >> 5;
    seg->flag_ack = (offset_reserved_flag & 16) >> 4;
    seg->flag_psh = (offset_reserved_flag &  8) >> 3;
    seg->flag_rst = (offset_reserved_flag &  4) >> 2;
    seg->flag_syn = (offset_reserved_flag &  2) >> 1;
    seg->flag_fin = (offset_reserved_flag &  1);

    int off = seg->offset;
    if (off > data_len) off = data_len;
    seg->payload     = data + off;
    seg->payload_len = data_len - off;
    return 1;
}

typedef struct {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t size;
    const uint8_t *payload;
    int      payload_len;
} UdpSegment;

int parse_udp(const uint8_t *data, int data_len, UdpSegment *seg)
{
    if (data_len < 8) return 0;

    uint16_t sp, dp, sz;
    memcpy(&sp, data,     2);  seg->src_port  = ntohs(sp);
    memcpy(&dp, data + 2, 2);  seg->dest_port = ntohs(dp);
    memcpy(&sz, data + 4, 2);  seg->size      = ntohs(sz);

    seg->payload     = data + 8;
    seg->payload_len = data_len - 8;
    return 1;
}

int main(void)
{
    int conn = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (conn < 0) {
        perror("socket() failed — did you run with sudo?");
        return 1;
    }

    printf("Listening for packets... Press Ctrl+C to stop.\n\n");

    uint8_t raw_data[65536];

    while (1) {

        int raw_len = (int)recvfrom(conn, raw_data, sizeof(raw_data), 0, NULL, NULL);
        if (raw_len <= 0) break;

        EthernetFrame eth;
        if (!parse_ethernet(raw_data, raw_len, &eth)) continue;

        printf("\nEthernet Frame:\n");
        printf("Destination: %s, Source: %s, Protocol: %u\n",
               eth.dest_mac, eth.src_mac, eth.eth_proto);

        if (eth.eth_proto == 0x0800) {

            IPv4Packet ip;
            if (!parse_ipv4(eth.payload, eth.payload_len, &ip)) continue;

            printf(TAB_1 "IPv4 Packet:\n");
            printf(TAB_2 "Version: %d, Header Length: %d, TTL: %d\n",
                   ip.version, ip.header_length, ip.ttl);
            printf(TAB_2 "Protocol: %d, Source: %s, Target: %s\n",
                   ip.proto, ip.src_ip, ip.dest_ip);

            if (ip.proto == 1) {
                IcmpPacket icmp;
                if (!parse_icmp(ip.payload, ip.payload_len, &icmp)) continue;

                printf(TAB_2 "ICMP Packet:\n");
                printf(TAB_3 "Type: %d, Code: %d, Checksum: %u\n",
                       icmp.icmp_type, icmp.code, icmp.checksum);
                printf(TAB_3 "Data:\n");
                format_multi_line(DATA_TAB_3, icmp.payload, icmp.payload_len, 80);
            }

            else if (ip.proto == 6) {
                TcpSegment tcp;
                if (!parse_tcp(ip.payload, ip.payload_len, &tcp)) continue;

                printf(TAB_2 "TCP Segment:\n");
                printf(TAB_3 "Source Port: %u, Destination Port: %u\n",
                       tcp.src_port, tcp.dest_port);
                printf(TAB_3 "Sequence: %u, Acknowledgement: %u\n",
                       tcp.sequence, tcp.acknowledgement);
                printf(TAB_3 "Flags:\n");
                printf(TAB_4 "URG: %d, ACK: %d, PSH: %d\n",
                       tcp.flag_urg, tcp.flag_ack, tcp.flag_psh);
                printf(TAB_4 "RST: %d, SYN: %d, FIN: %d\n",
                       tcp.flag_rst, tcp.flag_syn, tcp.flag_fin);
                printf(TAB_3 "Data:\n");
                format_multi_line(DATA_TAB_3, tcp.payload, tcp.payload_len, 80);
            }

            else if (ip.proto == 17) {
                UdpSegment udp;
                if (!parse_udp(ip.payload, ip.payload_len, &udp)) continue;

                printf(TAB_2 "UDP Segment:\n");
                printf(TAB_3 "Source Port: %u, Destination Port: %u, Length: %u\n",
                       udp.src_port, udp.dest_port, udp.size);
                printf(TAB_3 "Data:\n");
                format_multi_line(DATA_TAB_3, udp.payload, udp.payload_len, 80);
            }

            else {
                printf(TAB_2 "Other IPv4 Data:\n");
                format_multi_line(DATA_TAB_3, ip.payload, ip.payload_len, 80);
            }
        }
    }

    close(conn);
    return 0;
}
