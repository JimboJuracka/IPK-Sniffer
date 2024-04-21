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
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <time.h>

#include "ipk-sniffer.h"
#include "packet.h"

/* Function to print avilable interfaces */
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

/* Function to print avilable interfaces */
void print_interfaces(pcap_if_t *interfaces){
    pcap_if_t *temp = interfaces;
    while(temp != NULL){
        fprintf(stdout, "%s\n", temp->name);
        temp = temp->next;
    }
}

/* Function to check if the user given interface can be used */
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

/**/
pcap_t* get_handle(char* dev){
    char errstring[PCAP_ERRBUF_SIZE];   // string for error messages
    bpf_u_int32 mask;             
    bpf_u_int32 ip;
    pcap_t* handle;
    struct bpf_program filter;          // filter structure
    char filter_string[200];            // buffer to store filter string
    memset(filter_string, 0, 200);

    /* Gets network address and network mask for a capture device */
    if(pcap_lookupnet(dev, &ip, &mask, errstring) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_lookupnet(): %s\n", errstring);
        return NULL;
    }

    /* Initialization of the handle for a live capture*/
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errstring);
    if(handle == NULL){
        fprintf(stderr, "ERROR: pcap_open_live(): %s\n", errstring);
        return NULL;
    }

    /* Construction of filter string */
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

    /* Compilation of the bpf structure with the filter string */
    if(pcap_compile(handle, &filter, filter_string, 0, mask) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    /* Set the filter for handle */
    if(pcap_setfilter(handle, &filter) == PCAP_ERROR) {
        pcap_freecode(&filter);
        fprintf(stderr, "ERROR: pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    /* Free the bpf structure */
    pcap_freecode(&filter);
    return handle;
}

/* Function to print packet frames in hexadecimal fomat*/
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
            // byte_offset (0x0000:)
            fprintf(stdout, "0x%04x: ", i*byte_offset);

            // byte_offset_hexa (i.e. 05 a0 52 5b 40 00 36 06 5b db d9 43 16 8c 93 e5)
            for(int j = 0; j < tn; j++){
                fprintf(stdout, "%02x ", (unsigned char)data_ptr[i*byte_offset+j]);
                if(j == byte_offset/2 - 1){
                    fprintf(stdout, " ");
                }
            }
            // padding (if necesarry)
            if(tn != byte_offset){
                for(int g = 0; g < byte_offset - tn; g++){
                    fprintf(stdout, "   ");
                }
                if(tn < byte_offset/2){
                    fprintf(stdout, " ");
                }
            }
            fprintf(stdout, " ");

            // byte_offset_ASCII (i.e. ........ ..4 ..)
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

/* Function to handle the printing of packet information */
void handle_packet(unsigned char* user, const struct pcap_pkthdr* packet_head, const unsigned char* ptr){
    user++;
    const unsigned char* packet_ptr = ptr;  // pointer to the start of each header, adjusted with each layer
    struct tm* ts;                          // time structure
    char timestamp[256];                    // timestamp string
    int frame_length = packet_head->len;    // length of frame

    //link layer
    int linktype;               // type of link layer
    uint16_t eth_type;          // type of internet layer

    // internet layer
    struct iphdr* ip_hdr;       // IPv4 header
    struct ip6_hdr* ip6_hdr;    // IPv6 header
    struct arphdr* arp_hdr;     // ARP header
    char dstip[256];            // Destination address string
    char srcip[256];            // Source address string
    uint8_t proto_type;         // type of transport layer

    //transport layer
    struct igmp* igmp_hdr;      // IGMP header
    struct icmphdr* icmp_hdr;   // ICMP header
    struct tcphdr* tcp_hdr;     // TCP header
    struct udphdr* udp_hdr;     // UDP header

    /*
    Timestamp is obtained from pcap_pkthdr structure in second, then converted into string.
    The number of microseconds and timezone is appended.
    */
    ts = localtime(&packet_head->ts.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", ts);
    sprintf(timestamp+strlen(timestamp), ".%06d", (int)packet_head->ts.tv_usec);
    strftime(timestamp+strlen(timestamp), sizeof(timestamp), "%z", ts);
    fprintf(stdout, "timestamp: %s\n", timestamp);


    /*              DATA LINK LAYER             */

    // Obtaining the type of data link layer
    if((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
    switch (linktype){
        case DLT_LINUX_SLL:     // Linux cooked
            packet_ptr += 16;
            #ifdef DEBUG
            fprintf(stdout, "Linux cooked:\n");
            #endif
            fprintf(stdout, "src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11]);
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            memcpy(&eth_type, &(ptr[14]), 2);
            eth_type = ntohs(eth_type);
            break;

        case DLT_EN10MB:        // Ethernet
            packet_ptr += 14;
            #ifdef DEBUG
            fprintf(stdout, "Ethernet:\n");
            #endif
            fprintf(stdout, "src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11]);
            fprintf(stdout, "dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            memcpy(&eth_type, &(ptr[12]), 2);
            eth_type = ntohs(eth_type);
            break;
    
        default:
            fprintf(stdout, "Unsupported link layer protocol\n");
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            goto print_the_packet;
    }


    /*          INTERNET LAYER          */
    
    switch(eth_type){
        case 0x0800:    //IPv4
            ip_hdr = (struct iphdr*)packet_ptr;
            packet_ptr += (uint16_t)(ip_hdr->ihl * 4);
            proto_type = ip_hdr->protocol;
            #ifdef DEBUG
            fprintf(stdout, "IPv4:\n");
            #endif
            strcpy(srcip, inet_ntoa(*(struct in_addr *)&(ip_hdr->saddr)));
            strcpy(dstip, inet_ntoa(*(struct in_addr *)&(ip_hdr->daddr)));
            fprintf(stdout, "src IP: %s\n", srcip);
            fprintf(stdout, "dst IP: %s\n", dstip);
            break;

        case 0x86DD:    //IPv6
            ip6_hdr = (struct ip6_hdr*)packet_ptr;
            packet_ptr += 40;
            proto_type = ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            #ifdef DEBUG
            fprintf(stdout, "IPv6:\n");
            #endif
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), srcip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dstip, INET6_ADDRSTRLEN);
            fprintf(stdout, "src IP: %s\n", srcip);
            fprintf(stdout, "dst IP: %s\n", dstip);
            break;

        case 0x0806:    //ARP
            arp_hdr = (struct arphdr*)packet_ptr;
            strcpy(srcip, inet_ntoa(*(struct in_addr *)&(packet_ptr[14])));
            strcpy(dstip, inet_ntoa(*(struct in_addr *)&(packet_ptr[24])));
            #ifdef DEBUG
            fprintf(stdout, "ARP:\n");
            #endif
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


    /*          TRANSPORT LAYER         */
    
    switch(proto_type){
        case IPPROTO_TCP:       // TCP
            tcp_hdr = (struct tcphdr*)packet_ptr;
            #ifdef DEBUG
            fprintf(stdout, "TCP:\n");
            #endif
            fprintf(stdout, "src port %d\n",  ntohs(tcp_hdr->th_sport));
            fprintf(stdout, "dst port: %d\n", ntohs(tcp_hdr->th_dport));
            break;

        case IPPROTO_UDP:       // UDP
            udp_hdr = (struct udphdr*)packet_ptr;
            #ifdef DEBUG
            fprintf(stdout, "UDP:\n");
            #endif
            fprintf(stdout, "src port %d\n", ntohs(udp_hdr->uh_sport));
            fprintf(stdout, "dst port: %d\n", ntohs(udp_hdr->uh_dport));
            break;

        case IPPROTO_ICMP:      // ICMPv4
            icmp_hdr = (struct icmphdr*)(packet_ptr);
            #ifdef DEBUG
            fprintf(stdout, "ICMPv4:\n");
            #endif
            fprintf(stdout, "Type: %d\n", (uint8_t)icmp_hdr->type);
            fprintf(stdout, "Code: %d\n", (uint8_t)icmp_hdr->code);
            break;

        case IPPROTO_ICMPV6:    // ICMPv6
            icmp_hdr = (struct icmphdr*)(packet_ptr);
            #ifdef DEBUG
            fprintf(stdout, "ICMPv6:\n");
            #endif
            fprintf(stdout, "Type: %d\n", (uint8_t)icmp_hdr->type);
            fprintf(stdout, "Code: %d\n", (uint8_t)icmp_hdr->code);
            break;

        case IPPROTO_IGMP:      // IGMP
            igmp_hdr = (struct igmp*)packet_ptr;
            #ifdef DEBUG
            fprintf(stdout, "IGMP:\n");
            #endif
            fprintf(stdout, "Type: %d\n", igmp_hdr->igmp_type);
            fprintf(stdout, "Code: %d\n", igmp_hdr->igmp_code);
            fprintf(stdout, "Group address: %s\n", inet_ntoa(igmp_hdr->igmp_group));
            break;

        default:
            fprintf(stdout, "Unsuported transport layer protocol\n");
    }

    // Printing of the frame in format:  byte_offset: byte_offset_hexa byte_offset_ASCII
    print_the_packet:
    fprintf(stdout, "\n");
    print_data(ptr, 16, packet_head->caplen);
    fprintf(stdout, "\n");
}

/*Function to handle SIGINT signal*/
void stop_capture(){
    pcap_close(handle);
    exit(EXIT_SUCCESS);
}
