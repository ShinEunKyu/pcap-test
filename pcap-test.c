#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

struct Eth_header{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct Ip_header{
    uint8_t head_len;
    uint8_t field;
    uint16_t Total_len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct Tcp_header{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t pointer;
};

void print_eth(struct Eth_header *Eth)
{
    printf("**Ethernet Header**\n");
    printf("Source MAC: ");
    for(int i = 0; i < 6; i++)
    {
        if(i < 5) printf("%02x : ", Eth->src_mac[i]);
        else printf("%02x\n", Eth->src_mac[i]);
    }
    printf("Destination MAC: ");
    for(int i = 0; i < 6; i++)
    {
        if(i < 5) printf("%02x : ", Eth->dst_mac[i]);
        else printf("%02x\n\n", Eth->dst_mac[i]);
    }
}

void print_iph(struct Ip_header *Iph)
{
    printf("**IP Header**\n");
    printf("Source IP: ");
    for(int i = 0; i<4; i++)
    {
        if(i < 3) printf("%d.",Iph->src_ip[i]);
        else printf("%d\n",Iph->src_ip[i]);
    }
    printf("Destination IP: ");
    for(int i = 0; i<4; i++)
    {
        if(i < 3) printf("%d.",Iph->dst_ip[i]);
        else printf("%d\n\n", Iph->dst_ip[i]);
    }
}

void print_tcp(struct Tcp_header *Tcph, const u_char * data, int datalen)
{
    printf("**TCP Header**\n");
    printf("Source Port: %d\n", ntohs(Tcph->src_port));
    printf("Destination Port : %d\n\n", ntohs(Tcph->dst_port));

    printf("**data**\n");
    if(datalen != 0)
    {
        uint8_t *temp = (uint8_t *)malloc(datalen + 1);
        memcpy(temp, data, datalen);

        if (temp[0] != 0x00)
        {
            for(int i = 0; i < 8; i++)
            {
                printf("%02x", temp[i]);
                if(i+1 == datalen) break;
            }
            printf("\n");
        }
        else printf("no data\n");
    }
    else printf("no data\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        int datalen = 0;
        struct Eth_header *eth;
        eth = (struct Eth_header *)(packet);
        datalen += sizeof(*eth);

        if (ntohs(eth->type) == 0x0800)
        {
            struct Ip_header *iph;
            iph = (struct Ip_header *)(datalen + packet);
            datalen += sizeof(*iph);

            if (iph->protocol == 0x06)
            {
                struct Tcp_header *tcph;
                tcph = (struct Tcp_header *)(datalen + packet);
                datalen += ((int)((ntohs(tcph->flags) & 0xF000) >> 12)) * 4;
                int payload_len = header->caplen - datalen;

                print_eth(eth);
                print_iph(iph);
                print_tcp(tcph, datalen + packet, payload_len);
                printf("\n\n\n\n");
            }
        }
    }
    pcap_close(pcap);
}
