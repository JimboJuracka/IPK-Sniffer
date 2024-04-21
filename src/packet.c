#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
//#include <netinet/ether.h>
//#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <time.h>

#include "ipk-sniffer.h"
#include "packet.h"


int get_devs(pcap_if_t** devsk){
    char errstring[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(devsk, errstring) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_findalldevs(): %s\n", errstring);
        return 1;
    }
    if(*devsk == NULL){
        fprintf(stdout, "No device was found\n");
        return 1;
    }
    return 0;
}

void print_interfaces(pcap_if_t *interfaces){
    pcap_if_t *temp = interfaces;
    while(temp != NULL){
        fprintf(stdout, "%s\n", temp->name);
        temp = temp->next;
    }
}

int check_interface(char* inface, pcap_if_t *interfaces){
    pcap_if_t *temp = interfaces;
    while(temp != NULL){
        if(strcmp(inface, temp->name) == 0){
            return 0;
        }
        temp = temp->next;
    }
    return 1;
}

pcap_t* get_handle(char* dev){
    char errstring[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 ip;
    pcap_t* handle;
    struct bpf_program filter;
    char filter_string[200];
    memset(filter_string, 0, 200);

    if(pcap_lookupnet(dev, &ip, &mask, errstring) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_lookupnet(): %s\n", errstring);
        return NULL;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errstring);
    if(handle == NULL){
        fprintf(stderr, "ERROR: pcap_open_live(): %s\n", errstring);
        return NULL;
    }

    if(DEF_FILTERS){
        if(DEF_TCP || DEF_UDP){
            sprintf(filter_string, "(");
            if(DEF_ANY_PORT >= 0){
                sprintf(&(filter_string[1]), "port %d && ", DEF_ANY_PORT);
            }
            if(DEF_DST_PORT >= 0){
                if(DEF_SRC_PORT >= 0){
                    sprintf(&(filter_string[1]), "(dst port %d or src port %d) && ", DEF_DST_PORT, DEF_SRC_PORT);
                }else{
                    sprintf(&(filter_string[1]), "dst port %d && ", DEF_DST_PORT);
                }

            }else if(DEF_SRC_PORT >= 0){
                sprintf(&(filter_string[1]), "src port %d && ", DEF_SRC_PORT);
            }

            if(DEF_TCP){
                if(DEF_UDP){
                    sprintf(&(filter_string[strlen(filter_string)]), "(tcp or udp)");
                }else{
                    sprintf(&(filter_string[strlen(filter_string)]), "tcp");
                }
            }else if(DEF_UDP){
                sprintf(&(filter_string[strlen(filter_string)]), "udp");
            }
            sprintf(&(filter_string[strlen(filter_string)]), ")");
        }
        if(DEF_ICPM4){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "icmp");
        }
        if(DEF_ICPM6){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "icmp6");
        }
        if(DEF_ARP){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "arp");
        }
        if(DEF_NDP){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "(icmp6 && (ip6[40] == 133 || ip6[40] == 134 || ip6[40] == 135 || ip6[40] == 136 || ip6[40] == 137))");
        }
        if(DEF_IGMP){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "igmp");
        }
        if(DEF_MLD){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string,  "(icmp6 && ip6[40] == 131 || icmp6 && ip6[40] == 132 || icmp6 && ip6[40] == 143)");
        }
    }

    #ifdef DEBUG
    printf("INFO: filter_string: %s\n", filter_string);
    #endif
    if(pcap_compile(handle, &filter, filter_string, 0, mask) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }
    if(pcap_setfilter(handle, &filter) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }
    return handle;
}

void print_data(const unsigned char* data_ptr, int byte_offset, int size){
    unsigned char c;
    int pn = size / byte_offset;
    int tn = byte_offset;
    if(size > 0){
        if(size % byte_offset > 0)
            pn++;
        
        for(int i = 0; i < pn; i++){
            if((i+1)*byte_offset > size){
                tn = size - i*byte_offset;
            }
            fprintf(stdout, "0x%04x: ", i*byte_offset);
            for(int j = 0; j < tn; j++){
                fprintf(stdout, "%02x ", (unsigned char)data_ptr[i*byte_offset+j]);
                if(j == byte_offset/2 - 1){
                    fprintf(stdout, " ");
                }
            }
            if(tn != byte_offset){
                for(int g = 0; g < byte_offset - tn; g++){
                    fprintf(stdout, "   ");
                }
                if(tn < byte_offset/2){
                    fprintf(stdout, " ");
                }
            }
            fprintf(stdout, " ");
            for(int k = 0; k < tn; k++){
                c = data_ptr[i*byte_offset + k];
                if(c < 32 || c > 127){c = '.';}
                fprintf(stdout, "%c", c);
                if(k == byte_offset/2 - 1){
                    fprintf(stdout, " ");
                }
            }
            fprintf(stdout, "\n");
        }
    }
}

void handle_packet(unsigned char* user, const struct pcap_pkthdr* packet_head, const unsigned char* ptr){
    user++;
    const unsigned char* packet_ptr = ptr;
    struct tm* ts = localtime(&packet_head->ts.tv_sec);
    char timestamp[256];
    int frame_length = packet_head->len;
    //link layer
    int linktype;
    uint16_t eth_type;
    // internet layer
    struct iphdr* ip_hdr;
    struct ip6_hdr* ip6_hdr;
    struct arphdr* arp_hdr;
    char dstip[256];
    char srcip[256];
    uint8_t proto_type;
    //transport layer
    struct igmp* igmp_hdr;
    struct icmphdr* icmp_hdr;
    struct tcphdr* tcp_hdr;
    struct udphdr* udp_hdr;

    //reading time hurts
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", ts);
    sprintf(timestamp+strlen(timestamp), ".%06d", (int)packet_head->ts.tv_usec);
    strftime(timestamp+strlen(timestamp), sizeof(timestamp), "%z", ts);
    fprintf(stdout, "timestamp: %s\n", timestamp);

    //link layer
    if((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
    switch (linktype){
        case DLT_LINUX_SLL:
            packet_ptr += 16;
            fprintf(stdout, "Linux cooked:\n");
            fprintf(stdout, "src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11]);
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            memcpy(&eth_type, &(ptr[14]), 2);
            eth_type = ntohs(eth_type);
            break;

        case DLT_EN10MB:
            packet_ptr += 14;
            fprintf(stdout, "Ethernet:\n");
            fprintf(stdout, "src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11]);
            fprintf(stdout, "dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            memcpy(&eth_type, &(ptr[12]), 2);
            eth_type = ntohs(eth_type);
            break;
    
        default:
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            printf("Unsupported link layer protocol\n");
            goto print_the_packet;
    }


    //internet layer
    switch(eth_type){
        case 0x0800:    //IPv4
            ip_hdr = (struct iphdr*)packet_ptr;
            packet_ptr += (uint16_t)(ip_hdr->ihl * 4);
            proto_type = ip_hdr->protocol;
            fprintf(stdout, "IPv4:\n");
            strcpy(srcip, inet_ntoa(*(struct in_addr *)&(ip_hdr->saddr)));
            strcpy(dstip, inet_ntoa(*(struct in_addr *)&(ip_hdr->daddr)));
            fprintf(stdout, "src IP: %s\n", srcip);
            fprintf(stdout, "dst IP: %s\n", dstip);
            break;

        case 0x86DD:    //IPv6
            ip6_hdr = (struct ip6_hdr*)packet_ptr;
            packet_ptr += 40;
            proto_type = ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            fprintf(stdout, "IPv6:\n");
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), srcip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dstip, INET6_ADDRSTRLEN);
            fprintf(stdout, "src IP: %s\n", srcip);
            fprintf(stdout, "dst IP: %s\n", dstip);
            break;

        case 0x0806:    //ARP
            fprintf(stdout, "ARP:\n");
            arp_hdr = (struct arphdr*)packet_ptr;
            strcpy(srcip, inet_ntoa(*(struct in_addr *)&(packet_ptr[14])));
            strcpy(dstip, inet_ntoa(*(struct in_addr *)&(packet_ptr[24])));
            fprintf(stdout, "Hardware Type: %d\n", ntohs(arp_hdr->ar_hrd));
            fprintf(stdout, "Protocol Type: %02x\n", (uint16_t)ntohs(arp_hdr->ar_pro));
            fprintf(stdout, "ARP opcode (command): %d\n", ntohs(arp_hdr->ar_op));
            fprintf(stdout, "sender MAC %02x:%02x:%02x:%02x:%02x:%02x\n", packet_ptr[8], packet_ptr[9], packet_ptr[10], packet_ptr[11], packet_ptr[12], packet_ptr[13]);
            fprintf(stdout, "sender IP: %s\n", srcip);
            fprintf(stdout, "target MAC %02x:%02x:%02x:%02x:%02x:%02x\n", packet_ptr[18], packet_ptr[19], packet_ptr[20], packet_ptr[21], packet_ptr[22], packet_ptr[23]);
            fprintf(stdout, "target IP: %s\n", dstip);
            goto print_the_packet;
            break;
        
        default:
            fprintf(stdout, "Unsuported internet protocol\n");
    }

    //transport layer
    switch(proto_type){
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr*)packet_ptr;
            fprintf(stdout, "TCP:\n");
            fprintf(stdout, "src port %d\n",  ntohs(tcp_hdr->th_sport));
            fprintf(stdout, "dst port: %d\n", ntohs(tcp_hdr->th_dport));
            break;

        case IPPROTO_UDP:
            fprintf(stdout, "UDP:\n");
            udp_hdr = (struct udphdr*)packet_ptr;
            fprintf(stdout, "src port %d\n", ntohs(udp_hdr->uh_sport));
            fprintf(stdout, "dst port: %d\n", ntohs(udp_hdr->uh_dport));
            break;

        case IPPROTO_ICMP:
            fprintf(stdout, "ICMP:\n");
            icmp_hdr = (struct icmphdr*)(packet_ptr);
            fprintf(stdout, "Type: %d\n", (uint8_t)icmp_hdr->type);
            fprintf(stdout, "Code: %d\n", (uint8_t)icmp_hdr->code);
            break;

        case IPPROTO_ICMPV6:
            fprintf(stdout, "ICMPv6:\n");
            icmp_hdr = (struct icmphdr*)(packet_ptr);
            fprintf(stdout, "Type: %d\n", (uint8_t)icmp_hdr->type);
            fprintf(stdout, "Code: %d\n", (uint8_t)icmp_hdr->code);
            break;

        case IPPROTO_IGMP:
            fprintf(stdout, "IGMP:\n");
            igmp_hdr = (struct igmp*)packet_ptr;
            fprintf(stdout, "Type: %d\n", igmp_hdr->igmp_type);
            fprintf(stdout, "Code: %d\n", igmp_hdr->igmp_code);
            fprintf(stdout, "Group address: %s\n", inet_ntoa(igmp_hdr->igmp_group));
            break;

        default:
            fprintf(stdout, "Unsuported transport layer protocol\n");
    }

    print_the_packet:
    fprintf(stdout, "\n");
    print_data(ptr, 16, packet_head->caplen);
    //dont_print_packet:
    fprintf(stdout, "\n");
}
